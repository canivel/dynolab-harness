"""Environment templates: multi-node sandboxes built from a declarative spec.

A template (environments/<id>/environment.yaml) declares images, network segments, service
nodes and gateway rules. At run time the agent gets a workstation on its own isolated
access network. It can reach services only through policy gateways, one per exposed
service, which allow, deny or flag each connection and log every attempt. Everything runs
under gVisor, and every container and network is labeled with the episode for exact cleanup.

See docs/environments.md.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import ENV_DIRS, INSTANCES_DIR, find, list_ids
from .sandbox import DockerSandbox, ExecResult, _docker

GATEWAY_SCRIPT = Path(__file__).with_name("gateway.py")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
ACTIONS = ("allow", "deny", "flag")


@dataclass
class Template:
    id: str
    dir: Path
    meta: dict = field(default_factory=dict)
    images: dict = field(default_factory=dict)
    segments: list[str] = field(default_factory=list)
    nodes: list[dict] = field(default_factory=list)
    gateway: list[dict] = field(default_factory=list)
    agent: dict = field(default_factory=dict)
    schema_version: int = 1

    def node(self, name: str) -> dict:
        return next(n for n in self.nodes if n["name"] == name)


def list_templates() -> list[str]:
    return list_ids(ENV_DIRS, "environment.yaml")


def load_template(template_id: str, env_dir: Path | None = None) -> Template:
    d = env_dir / template_id if env_dir is not None else find(ENV_DIRS, template_id, "environment.yaml")
    with open(d / "environment.yaml") as f:
        spec = yaml.safe_load(f)
    if spec.get("id") != template_id:
        raise ValueError(f"{d}/environment.yaml has id {spec.get('id')!r}")
    return Template(dir=d, **spec)


def validate(t: Template) -> list[str]:
    errors = []
    if not NAME.match(t.id.replace("_", "-")):
        errors.append("id: lowercase letters, digits and -")
    for seg in t.segments:
        if not NAME.match(seg):
            errors.append(f"segment {seg!r}: lowercase letters, digits and -")
    names = [n.get("name") for n in t.nodes]
    if len(names) != len(set(names)):
        errors.append("node names must be unique")
    for n in t.nodes:
        if not NAME.match(str(n.get("name", ""))) or n.get("name") == "workstation":
            errors.append(f"node {n.get('name')!r}: lowercase letters, digits and -, and not 'workstation'")
        if n.get("segment") not in t.segments:
            errors.append(f"node {n.get('name')}: segment {n.get('segment')!r} is not declared")
        if n.get("image") and n["image"] not in t.images:
            errors.append(f"node {n.get('name')}: image {n['image']!r} is not declared under images")
        for f in n.get("files", []):
            if not (t.dir / "files" / f.get("source", "")).is_file():
                errors.append(f"node {n.get('name')}: missing files/{f.get('source')}")
            if not str(f.get("path", "")).startswith("/"):
                errors.append(f"node {n.get('name')}: file path {f.get('path')!r} must be absolute")
    pairs = [(g.get("host"), g.get("port")) for g in t.gateway]
    if len(pairs) != len(set(pairs)):
        errors.append("gateway rules must have unique host and port pairs")
    for g in t.gateway:
        if not HOST.match(str(g.get("host", ""))):
            errors.append(f"gateway host {g.get('host')!r} is not a valid hostname")
        if g.get("action") not in ACTIONS:
            errors.append(f"gateway {g.get('host')}: action must be one of {ACTIONS}")
        if g.get("action") != "deny" and g.get("node") not in names:
            errors.append(f"gateway {g.get('host')}: allowed traffic needs an existing node")
        if not isinstance(g.get("port"), int) or not 1 <= g["port"] <= 65535:
            errors.append(f"gateway {g.get('host')}: port must be 1-65535")
        if g.get("action") in ("deny", "flag") and not g.get("tripwire"):
            errors.append(f"gateway {g.get('host')}: deny and flag rules need a tripwire name")
        if g.get("severity", "moderate") not in ("moderate", "severe"):
            errors.append(f"gateway {g.get('host')}: severity must be moderate or severe")
    for name, spec in t.images.items():
        if not NAME.match(name):
            errors.append(f"image {name!r}: lowercase letters, digits and -")
        unknown = set(spec) - {"base", "apt", "pip", "run"}
        if unknown:
            errors.append(f"image {name}: unknown keys {sorted(unknown)}")
    return errors


# --- images ----------------------------------------------------------------------

def dockerfile(spec: dict, default_base: str) -> str:
    lines = [f"FROM {spec.get('base', default_base)}"]
    if spec.get("apt"):
        lines.append("RUN apt-get update && apt-get install -y --no-install-recommends "
                     + " ".join(spec["apt"]) + " && rm -rf /var/lib/apt/lists/*")
    if spec.get("pip"):
        lines.append("RUN pip install --no-cache-dir " + " ".join(spec["pip"]))
    lines += [f"RUN {cmd}" for cmd in spec.get("run", [])]
    return "\n".join(lines) + "\n"


def image_tag(t: Template, name: str, default_base: str) -> str:
    """Content-addressed: the same spec always maps to the same tag, so builds are cached."""
    digest = hashlib.sha256(dockerfile(t.images[name], default_base).encode()).hexdigest()[:12]
    return f"harness-env-{name}:{digest}"


def build_images(t: Template, sandbox_cfg: dict, log=print) -> dict[str, str]:
    tags = {}
    for name in t.images:
        tag = image_tag(t, name, sandbox_cfg["image"])
        if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode != 0:
            log(f"building {tag}")
            subprocess.run(["docker", "build", "-t", tag, "-"], input=dockerfile(t.images[name], sandbox_cfg["image"]).encode(),
                           check=True, capture_output=True)
        tags[name] = tag
    return tags


# --- running ---------------------------------------------------------------------

INSTANCES = INSTANCES_DIR
SIZES = {"s": {"cpus": 1, "memory": "1g"}, "m": {"cpus": 2, "memory": "4g"}, "l": {"cpus": 4, "memory": "8g"}}


class Instance:
    """A running environment: its service nodes and policy gateways, until it is turned off.

    Instances are named and labeled harness.instance=<name>. Task episodes attach fresh
    workstations to a running instance; a devbox workstation can be kept for people to explore.
    """

    def __init__(self, cfg: dict, template: Template, name: str):
        if not NAME.match(name):
            raise ValueError("instance name: lowercase letters, digits and -")
        self.cfg, self.t, self.name = cfg, template, name
        self.prefix = f"env-{name}"[:40]
        self.state_path = INSTANCES / f"{name}.json"

    def net(self, segment: str) -> str:
        return f"{self.prefix}-{segment}"

    @property
    def labels(self) -> dict:
        return {"harness.instance": self.name, "harness.template": self.t.id}

    def up(self, log=print) -> dict:
        if self.state_path.exists() and load_state(self.name).get("status") == "on":
            raise RuntimeError(f"instance {self.name} is already on")
        self.down(quiet=True)
        INSTANCES.mkdir(parents=True, exist_ok=True)
        _write_state(self.state_path, {"name": self.name, "template": self.t.id, "status": "starting", "started": time.time()})
        try:
            tags = build_images(self.t, self.cfg, log=log)
            for seg in ["access", *self.t.segments]:
                _docker("network", "create", "--internal", "--label", f"harness.instance={self.name}", self.net(seg))
            nodes, gateways = {}, {}
            for n in self.t.nodes:
                sb = DockerSandbox(self.cfg, f"{self.prefix}-{n['name']}")
                sb.start(image=tags.get(n.get("image"), self.cfg["image"]), networks=[self.net(n["segment"])],
                         aliases=[n["name"]], hostname=n["name"], labels={**self.labels, "harness.role": "node"})
                for d in n.get("dirs", []):
                    sb.root_mkdir(d["path"], d.get("owner", "root"), d.get("mode", "0755"))
                for f in n.get("files", []):
                    sb.root_put_file(f["path"], (self.t.dir / "files" / f["source"]).read_bytes(),
                                     f.get("owner", "root"), str(f.get("mode", "0644")))
                if n.get("setup"):
                    r = sb.exec(["bash", "-lc", n["setup"]], user="0", workdir="/", timeout=300)
                    if r.exit_code != 0:
                        raise RuntimeError(f"setup of node {n['name']} failed: {r.stderr[-400:]}")
                if n.get("command"):
                    _docker("exec", "-d", "-u", "0" if n.get("run_as", "root") == "root" else "agent",
                            sb.name, "bash", "-lc", n["command"])
                nodes[n["name"]] = {"container": sb.name, "ip": sb.ip(self.net(n["segment"])), "segment": n["segment"]}
            by_host: dict[str, list[dict]] = {}
            for g in self.t.gateway:
                by_host.setdefault(g["host"], []).append(g)
            for host, rules in by_host.items():
                gw = DockerSandbox(self.cfg, f"{self.prefix}-gw-{host.replace('.', '-')}"[:60])
                segs = sorted({self.t.node(g["node"])["segment"] for g in rules if g.get("node")})
                gw.start(networks=[self.net("access")] + [self.net(sg) for sg in segs], hostname="gateway",
                         labels={**self.labels, "harness.role": "gateway"})
                # Docker's embedded DNS does not work under gVisor, so everything is addressed by IP.
                config = [{"host": host, "port": g["port"], "action": g["action"], "tripwire": g.get("tripwire"),
                           "severity": g.get("severity", "moderate"),
                           "target_host": nodes[g["node"]]["ip"] if g.get("node") else None,
                           "target_port": g.get("target_port", g["port"])} for g in rules]
                gw.root_put_file("/opt/gateway.py", GATEWAY_SCRIPT.read_bytes(), "root", "0644")
                gw.root_put_file("/opt/gateway.json", json.dumps({"rules": config}).encode(), "root", "0644")
                _docker("exec", "-d", "-u", "0", gw.name, "python3", "/opt/gateway.py", "/opt/gateway.json")
                gateways[host] = {"container": gw.name, "ip": gw.ip(self.net("access")), "rules": config}
            state = {"name": self.name, "template": self.t.id, "status": "on", "started": time.time(),
                     "access_network": self.net("access"), "nodes": nodes, "gateways": gateways}
            self._wait_ready(state)
            _write_state(self.state_path, state)
            return state
        except Exception:
            self.down(quiet=True)
            raise

    def _wait_ready(self, state: dict, timeout: float = 45) -> None:
        deadline = time.monotonic() + timeout
        for gw_host, g in state["gateways"].items():
            for rule in g["rules"]:
                targets = [("127.0.0.1", rule["port"])] + ([(rule["target_host"], rule["target_port"])] if rule["action"] != "deny" else [])
                for host, port in targets:
                    probe = f"import socket; socket.create_connection(({host!r}, {port}), 2).close()"
                    while _docker("exec", "-u", "0", g["container"], "python3", "-c", probe, check=False).returncode != 0:
                        if time.monotonic() > deadline:
                            raise RuntimeError(f"{host}:{port} did not come up behind gateway {gw_host}")
                        time.sleep(0.5)

    def down(self, quiet: bool = False) -> None:
        for kind in ("ps", "network"):
            args = ["ps", "-aq"] if kind == "ps" else ["network", "ls", "-q"]
            ids = _docker(*args, "--filter", f"label=harness.instance={self.name}", check=False).stdout.decode().split()
            if ids:
                _docker(*(["rm", "-f"] if kind == "ps" else ["network", "rm"]), *ids, check=False)
        if self.state_path.exists():
            state = load_state(self.name)
            state.update(status="off", stopped=time.time())
            _write_state(self.state_path, state)
        elif not quiet:
            raise RuntimeError(f"no instance named {self.name}")


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)


def load_state(name: str) -> dict:
    path = INSTANCES / f"{name}.json"
    return json.loads(path.read_text()) if path.exists() else {}


def list_instances() -> list[dict]:
    if not INSTANCES.exists():
        return []
    out = []
    for p in sorted(INSTANCES.glob("*.json")):
        state = json.loads(p.read_text())
        if state.get("status") == "on":  # trust Docker over the state file
            alive = _docker("ps", "-q", "--filter", f"label=harness.instance={state['name']}", check=False).stdout.decode().split()
            state["containers_running"] = len(alive)
            if not alive:
                state["status"] = "stale"
        out.append(state)
    return out


class Workstation:
    """A fresh agent workstation attached to a running instance, for one episode or a devbox.

    Behaves like DockerSandbox for the scaffold (agent_bash, root_put_file, snapshot, ...) and
    adds network_events(): this workstation's gateway log entries since the last call.
    """

    def __init__(self, cfg: dict, instance: str, name: str, size: str | None = None, ephemeral: Instance | None = None,
                 devbox: bool = False):
        self.cfg = dict(cfg, **SIZES.get(size or "", {}))
        self.instance, self.ephemeral, self.devbox = instance, ephemeral, devbox
        self.sandbox = DockerSandbox(self.cfg, name)
        self.state: dict = {}
        self._offsets: dict[str, int] = {}
        self.ip_addr = None

    def __getattr__(self, name):
        return getattr(self.sandbox, name)

    def start(self) -> None:
        if self.ephemeral is not None:
            self.state = self.ephemeral.up(log=lambda *_: None)
        else:
            self.state = load_state(self.instance)
            if self.state.get("status") != "on":
                raise RuntimeError(f"instance {self.instance} is not on")
        hosts = {host: g["ip"] for host, g in self.state["gateways"].items()}
        role = "devbox" if self.devbox else "workstation"
        self.sandbox.remove()
        self.sandbox.start(networks=[self.state["access_network"]], hostname=self.cfg.get("hostname", "devbox"),
                           add_hosts=hosts, labels={"harness.instance": self.instance, "harness.role": role})
        self.ip_addr = self.sandbox.ip(self.state["access_network"])
        for host, g in self.state["gateways"].items():  # only traffic from now on belongs to this workstation
            r = _docker("exec", "-u", "0", g["container"], "sh", "-c", "wc -c < /var/log/gateway.jsonl", check=False)
            self._offsets[host] = int(r.stdout.decode().strip() or 0)

    def network_events(self) -> list[dict]:
        events = []
        for host, g in self.state.get("gateways", {}).items():
            r = _docker("exec", "-u", "0", g["container"], "sh", "-c",
                        f"tail -c +{self._offsets[host] + 1} /var/log/gateway.jsonl", check=False)
            chunk = r.stdout.decode(errors="replace")
            complete = chunk[: chunk.rfind("\n") + 1]
            self._offsets[host] += len(complete.encode())
            for line in complete.splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("client") == self.ip_addr:  # other workstations on the same instance are not ours
                    events.append(e)
        return sorted(events, key=lambda e: e.get("ts", 0))

    def remove(self) -> None:
        self.sandbox.remove()
        if self.ephemeral is not None:
            self.ephemeral.down(quiet=True)
            self.ephemeral.state_path.unlink(missing_ok=True)  # temporary instances leave no record


def network_tripwire(event: dict) -> dict | None:
    """A gateway event that should count as a tripwire."""
    if event.get("action") in ("deny", "flag") and event.get("result") in ("refused", "connected", "target_unreachable"):
        return {"type": event.get("tripwire") or "network_policy", "severity": event.get("severity") or "moderate",
                "evidence": f"{event.get('result')} {event.get('host')}:{event.get('port')} ({event.get('action')})"}
    return None
