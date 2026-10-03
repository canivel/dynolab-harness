"""One fresh gVisor container per episode, driven through `docker exec`.

The container starts as root only so setup can place root-owned files and hash
protected paths. Every agent command runs as the unprivileged `agent` user.

Deviation from the guide: the guide drops all capabilities. With no
capabilities at all, root inside the container cannot chown files to `agent` or
hash files it does not own, so we add back CHOWN, DAC_OVERRIDE and FOWNER. These
only ever apply to root. `agent` is non-root and runs under no-new-privileges, so
it can't gain them.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

# Runs as root inside the container. Prints {path: entry} for every file under
# the given paths, so changes to content, mode, owner or existence all show up.
_SNAPSHOT_SCRIPT = r"""
import hashlib, json, os, sys
out = {}
def entry(p):
    st = os.lstat(p)
    e = {"mode": oct(st.st_mode & 0o7777), "uid": st.st_uid}
    if os.path.islink(p):
        e["link"] = os.readlink(p)
    elif os.path.isfile(p):
        try:
            with open(p, "rb") as f:
                e["sha256"] = hashlib.sha256(f.read()).hexdigest()
        except OSError as err:
            e["error"] = err.strerror
    return e
for root in sys.argv[1:]:
    if not os.path.lexists(root):
        out[root] = "MISSING"
        continue
    if os.path.isdir(root) and not os.path.islink(root):
        out[root + "/"] = entry(root)
        for d, dirs, files in os.walk(root):
            dirs[:] = sorted(x for x in dirs if x != "__pycache__")
            for name in sorted(files):
                out[os.path.join(d, name)] = entry(os.path.join(d, name))
    else:
        out[root] = entry(root)
print(json.dumps(out, sort_keys=True))
"""


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float


def _docker(*args: str, input: bytes | None = None, timeout: float | None = None,
            check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], input=input, capture_output=True,
                          timeout=timeout, check=check)


class DockerSandbox:
    def __init__(self, cfg: dict, name: str):
        self.cfg = cfg
        self.name = name

    def start(self, *, image: str | None = None, networks: list[str] | None = None,
              aliases: list[str] | None = None, hostname: str | None = None,
              add_hosts: dict[str, str] | None = None, labels: dict[str, str] | None = None) -> None:
        """Start the container. With no arguments: the single-box sandbox from harness.yaml."""
        c = self.cfg
        nets = networks or [c["network"]]
        args = ["run", "-d", "--name", self.name,
                # A neutral hostname: the agent's machine shouldn't announce that it is a test.
                "--hostname", hostname or c.get("hostname", "devbox"),
                "--runtime", c["runtime"],
                "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE",
                "--cap-add=FOWNER", "--security-opt", "no-new-privileges",
                "--cpus", str(c["cpus"]), "--memory", c["memory"],
                "--pids-limit", str(c["pids_limit"]), "--label", "harness=1"]
        # gVisor can't attach networks to a running container, so every network is given
        # at creation (Docker 25+ accepts several --network flags).
        for net in nets:
            args += ["--network", ",".join([f"name={net}", *[f"alias={a}" for a in aliases or []]])
                     if len(nets) > 1 or aliases else net]
        for host, ip in (add_hosts or {}).items():
            args += ["--add-host", f"{host}:{ip}"]
        for key, value in (labels or {}).items():
            args += ["--label", f"{key}={value}"]
        _docker(*args, image or c["image"])

    def ip(self, network: str) -> str:
        p = _docker("inspect", "--format",
                    "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % network, self.name)
        return p.stdout.decode().strip()

    def remove(self) -> None:
        _docker("rm", "-f", self.name, check=False)

    def exec(self, argv: list[str], user: str = "agent", workdir: str = "/workspace",
             stdin: bytes | None = None, timeout: float | None = None) -> ExecResult:
        flags = ["-i"] if stdin is not None else []
        t0 = time.monotonic()
        try:
            p = _docker("exec", *flags, "-u", user, "-w", workdir, self.name, *argv,
                        input=stdin, timeout=timeout, check=False)
            out, err, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as e:
            out, err, code = e.stdout or b"", (e.stderr or b"") + b"\n[host timeout]", 124
        return ExecResult(out.decode(errors="replace"), err.decode(errors="replace"),
                          code, round(time.monotonic() - t0, 3))

    # --- agent-facing operations (all as `agent`, so file permissions apply) ---

    def agent_bash(self, command: str) -> ExecResult:
        t = self.cfg["command_timeout_s"]
        return self.exec(["timeout", str(t), "bash", "-lc", command], timeout=t + 30)

    def agent_read(self, path: str) -> ExecResult:
        return self.exec(["cat", "--", path], timeout=30)

    def agent_write(self, path: str, content: str) -> ExecResult:
        return self.exec(["sh", "-c", 'cat > "$1"', "sh", path],
                         stdin=content.encode(), timeout=30)

    # --- setup and forensics (as root) ---

    def root_mkdir(self, path: str, owner: str, mode: str) -> None:
        self._root_ok(["sh", "-c", 'mkdir -p "$1" && chown "$2" "$1" && chmod "$3" "$1"',
                       "sh", path, owner, mode])

    def root_put_file(self, path: str, content: bytes, owner: str, mode: str) -> None:
        self._root_ok(["sh", "-c", 'mkdir -p "$(dirname "$1")" && cat > "$1"', "sh", path],
                      stdin=content)
        self._root_ok(["sh", "-c", 'chown "$2" "$1" && chmod "$3" "$1"',
                       "sh", path, owner, mode])

    def snapshot(self, paths: list[str]) -> dict:
        r = self.exec(["python3", "-c", _SNAPSHOT_SCRIPT, *paths], user="0", timeout=120)
        if r.exit_code != 0:
            raise RuntimeError(f"snapshot failed: {r.stderr}")
        return json.loads(r.stdout)

    def runtime(self) -> str:
        p = _docker("inspect", "--format", "{{.HostConfig.Runtime}}", self.name)
        return p.stdout.decode().strip()

    def _root_ok(self, argv: list[str], stdin: bytes | None = None) -> None:
        r = self.exec(argv, user="0", workdir="/", stdin=stdin, timeout=60)
        if r.exit_code != 0:
            raise RuntimeError(f"root exec failed ({argv[:3]}...): {r.stderr}")


def image_digest(image: str) -> str:
    p = _docker("image", "inspect", "--format", "{{.Id}}", image, check=False)
    return p.stdout.decode().strip() or "unknown"
