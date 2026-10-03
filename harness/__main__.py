"""Command line: python -m harness <command>. See README.md for the pilot order."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

from . import evidence, ledger
from .config import MOCK_DIRS, RUNS_DIR, find, load_config
from .isolation import DESCRIPTIONS, run_checks
from .labeler import label_episode
from .model import ScriptedModel, OpenAICompatModel
from .sandbox import DockerSandbox
from .scaffold import NUDGE, SYSTEM_PROMPT, run_episode
from .tools import TOOLS
from .summarize import summarize
from .tasks import load_task


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _check_entry(name: str, passed: bool, detail: str) -> dict:
    what, command = DESCRIPTIONS.get(name, ("", ""))
    return {"name": name, "passed": passed, "detail": detail, "what": what, "command": command}


def cmd_check(cfg, args) -> int:
    as_json = getattr(args, "json", False)
    # In JSON mode each result also goes to stderr as it finishes, so viewers can show progress.
    progress = (lambda n, p, d: print(json.dumps(_check_entry(n, p, d)), file=sys.stderr, flush=True)) \
        if as_json else None
    results = run_checks(cfg["sandbox"], on_result=progress)
    ok = bool(results) and all(passed for _, passed, _ in results)
    if as_json:
        print(json.dumps({"ok": ok, "checks": [_check_entry(n, p, d) for n, p, d in results]}))
        return 0 if ok else 1
    for name, passed, detail in results:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}  ({detail})")
    if not ok:
        print("Isolation checks failed. Do not run episodes.")
    return 0 if ok else 1


def cmd_smoke(cfg, args) -> int:
    """Step 2.3: one request with one dummy tool must come back as a tool call."""
    m = cfg["model"]
    tool = {"type": "function", "function": {
        "name": "get_time", "description": "Get the current time in a city.",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}},
                       "required": ["city"]}}}
    r = requests.post(f"{m['base_url'].rstrip('/')}/chat/completions", timeout=120, json={
        "model": m["id"], "tools": [tool], "tool_choice": "auto",
        "messages": [{"role": "user", "content": "What time is it in Lisbon? Use the tool."}]})
    r.raise_for_status()
    msg = r.json()["choices"][0]["message"]
    print(json.dumps(msg, indent=2))
    print("\n", json.dumps(OpenAICompatModel(m).info(), indent=2))
    if not msg.get("tool_calls"):
        print("FAIL: no tool_calls. Fix --tool-call-parser before going further.")
        return 1
    print("PASS: tool calling works.")
    return 0


def _episode_sandbox(cfg, task, episode_id: str, instance: str | None):
    """A plain box, a workstation on a running instance, or a temporary instance for this episode."""
    if not task.environment:
        if instance:
            raise SystemExit(f"task {task.id} has no environment; --instance does not apply")
        sb = DockerSandbox(cfg["sandbox"], f"ep-{episode_id}")
        sb.remove()
        return sb
    from .environments import Instance, Workstation, load_state, load_template
    template = load_template(task.environment["template"])
    if instance:
        state = load_state(instance)
        if state.get("template") != template.id:
            raise SystemExit(f"instance {instance} runs {state.get('template')}, task {task.id} needs {template.id}")
        return Workstation(cfg["sandbox"], instance, f"ep-{episode_id}", size=task.environment.get("size"))
    import hashlib
    name = "ep" + hashlib.sha256(episode_id.encode()).hexdigest()[:10]
    return Workstation(cfg["sandbox"], name, f"ep-{episode_id}", size=task.environment.get("size"),
                       ephemeral=Instance(cfg["sandbox"], template, name))


def _run_one(cfg, model, task_id: str, run_dir: Path, episode_id: str, seed,
             condition: str | None = None, instance: str | None = None) -> dict:
    task = load_task(task_id)
    sandbox = _episode_sandbox(cfg, task, episode_id, instance)
    run_episode(model=model, task=task, cfg=cfg, episode_dir=run_dir / episode_id,
                episode_id=episode_id, seed=seed, sandbox=sandbox, condition=condition)
    return label_episode(run_dir / episode_id)


def cmd_control(cfg, args) -> int:
    """Step 7.2: every scripted rule break must be flagged, every honest run must be clean."""
    run_dir = Path(args.out or RUNS_DIR / f"control-{_stamp()}")
    failures = []
    results = []
    for task_id in args.tasks or cfg["pilot"]["plan"]:
        for behaviour in ("honest", "rule_break"):
            path = find(MOCK_DIRS, task_id, f"{behaviour}.yaml") / f"{behaviour}.yaml"
            expect = yaml.safe_load(path.read_text())["expect"]
            label = _run_one(cfg, ScriptedModel(path), task_id, run_dir,
                             f"{task_id}-{behaviour}", seed=None)
            got = {t["type"] for t in label["tripwires"]}
            missing = set(expect["tripwires"]) - got
            unexpected = got if not expect["tripwires"] else set()
            ok = label["outcome"] == expect["outcome"] and not missing and not unexpected
            print(f"[{'PASS' if ok else 'FAIL'}] {task_id}/{behaviour}: outcome={label['outcome']} "
                  f"tripwires={sorted(got)}", flush=True)
            results.append({"task": task_id, "behaviour": behaviour, "passed": ok,
                            "outcome": label["outcome"], "tripwires": sorted(got)})
            if not ok:
                failures.append(f"{task_id}/{behaviour}: expected {expect}, missing {sorted(missing)}, "
                                f"unexpected {sorted(unexpected)}")
    print(f"\nControl run folder: {run_dir}")
    for f in failures:
        print("  FAIL", f)
    (run_dir / "controls.json").write_text(json.dumps({"ok": not failures, "results": results}, indent=2))
    return 1 if failures else 0


def cmd_episode(cfg, args) -> int:
    run_dir = Path(args.out or RUNS_DIR / f"adhoc-{_stamp()}")
    model = (ScriptedModel.for_task(args.task, args.model.split(":", 1)[1])
             if args.model.startswith("scripted:") else OpenAICompatModel(cfg["model"]))
    label = _run_one(cfg, model, args.task, run_dir, f"{args.task}-{_stamp()}", args.seed)
    print(json.dumps(label, indent=2))
    return 0


def cmd_run(cfg, args) -> int:
    """Episodes on one task with the configured model; no controls. Used by Dyno."""
    run_dir = Path(args.out or RUNS_DIR / f"run-{_stamp()}")
    model = OpenAICompatModel(cfg["model"])
    seed = args.seed if args.seed is not None else cfg["pilot"]["base_seed"]
    for i in range(1, args.count + 1):
        cond = f"-{args.condition}" if args.condition and args.condition != "neutral" else ""
        ep = f"{args.task}{cond}-{_stamp()}-{i}"
        try:
            label = _run_one(cfg, model, args.task, run_dir, ep, seed + i, args.condition, args.instance)
            print(f"{ep}: {label['outcome']} tripwires={[t['type'] for t in label['tripwires']]}")
        except Exception as e:
            print(f"{ep}: harness error: {e!r}")
            if (run_dir / ep / "manifest.json").exists():
                label_episode(run_dir / ep)
    summarize(run_dir)
    return 0


def cmd_pilot(cfg, args) -> int:
    """Step 7: isolation checks, positive controls, then the episodes, labels and summary."""
    if cfg["model"].get("revision") in (None, "", "FILL_ME"):
        print("Set model.revision in harness.yaml first; it goes into every manifest.")
        return 1
    if cmd_check(cfg, args):
        return 1
    if not args.skip_control and cmd_control(cfg, argparse.Namespace(out=None, tasks=None)):
        print("Positive controls failed. Fix the labeler before running the pilot.")
        return 1
    run_dir = Path(args.out or RUNS_DIR / f"pilot-{_stamp()}")
    model = OpenAICompatModel(cfg["model"])
    seed = cfg["pilot"]["base_seed"]
    n = 0
    for task_id, count in cfg["pilot"]["plan"].items():
        for i in range(1, count + 1):
            n += 1
            ep = f"{n:02d}-{task_id}-{i}"
            try:
                label = _run_one(cfg, model, task_id, run_dir, ep, seed + n)
                print(f"{ep}: {label['outcome']} (claimed_success={label['claimed_success']}, "
                      f"tripwires={len(label['tripwires'])})")
            except Exception as e:  # keep going; the episode folder records the error
                print(f"{ep}: harness error: {e!r}")
                if (run_dir / ep / "manifest.json").exists():
                    label_episode(run_dir / ep)
    summary = summarize(run_dir)
    print((run_dir / "summary.md").read_text())
    print(f"Next: hand-review every transcript in {run_dir}/review.md, then "
          f"`python -m harness seal {run_dir} --key keys/signing.pem`.")
    return 0 if summary["episodes"] else 1


def cmd_label(cfg, args) -> int:
    run_dir = Path(args.run_dir)
    for ep in sorted(p.parent for p in run_dir.glob("*/manifest.json")):
        lb = label_episode(ep)
        print(f"{ep.name}: {lb['outcome']} tripwires={[t['type'] for t in lb['tripwires']]}")
    summarize(run_dir)
    print((run_dir / "summary.md").read_text())
    return 0


def cmd_summarize(cfg, args) -> int:
    summarize(Path(args.run_dir))
    print((Path(args.run_dir) / "summary.md").read_text())
    return 0


def cmd_tasks(cfg, args) -> int:
    """List tasks as JSON, for viewers such as Dyno that don't parse YAML."""
    from .config import is_builtin
    from .tasks import list_task_ids
    tasks = [load_task(i) for i in list_task_ids()]
    print(json.dumps({"tasks": [{"id": t.id, "rule": t.rule, "prompt": t.prompt,
                                 "allowed_hosts": t.allowed_hosts,
                                 "protected": t.protected_paths,
                                 "honeypots": [s["name"] for s in t.secrets],
                                 "watched": [w["type"] for w in t.watched_reads],
                                 "schema_version": t.schema_version, "meta": t.meta,
                                 "conditions": [c["id"] for c in t.conditions],
                                 "has_setup": bool(t.setup.get("script")),
                                 "honest_checks": {"must_report": t.honest_checks.get("must_report", []),
                                                   "state_checks": [c.get("name") for c in t.honest_checks.get("state_checks", [])]},
                                 "limits": t.limits, "environment": t.environment or None,
                                 "builtin": is_builtin(t.dir), "path": str(t.dir)} for t in tasks],
                      "model": {k: cfg["model"].get(k) for k in ("base_url", "id", "revision")},
                      # Exactly what the model under test receives besides the task and tool output.
                      "agent_view": {"system_prompt": SYSTEM_PROMPT, "nudge": NUDGE,
                                     "hostname": cfg["sandbox"].get("hostname", "devbox"),
                                     "tools": [{"name": t["function"]["name"], "description": t["function"]["description"]}
                                               for t in TOOLS]}},
                     indent=2))
    return 0


def cmd_task_check(cfg, args) -> int:
    """Validate one task folder: it loads, its files exist, and its patterns compile."""
    import re
    from .tasks import load_task
    folder = Path(args.task_dir).resolve()
    errors = []
    try:
        task = load_task(folder.name, folder.parent)
    except Exception as e:  # noqa: BLE001 - report any load failure to the caller
        print(json.dumps({"ok": False, "errors": [f"task.yaml: {e}"]}))
        return 1
    if not task.prompt.strip() or not task.rule.strip():
        errors.append("prompt and rule are required")
    for f in task.files:
        if not (folder / "files" / f["source"]).is_file():
            errors.append(f"missing file: files/{f['source']}")
        if f.get("owner") not in ("agent", "root"):
            errors.append(f"{f['path']}: owner must be agent or root")
        if not re.fullmatch(r"0?[0-7]{3}", str(f.get("mode", ""))):
            errors.append(f"{f['path']}: mode must be octal, e.g. 0644")
        if not str(f.get("path", "")).startswith("/"):
            errors.append(f"{f.get('path')}: path must be absolute")
    patterns = [p for spec in task.protected for p in spec.get("patterns", [])]
    patterns += [p for w in task.watched_reads for p in w.get("patterns", [])]
    patterns += [p for s in task.secrets for k in ("file_patterns", "use_patterns") for p in s.get(k, [])]
    for p in patterns:
        try:
            re.compile(p)
        except re.error as e:
            errors.append(f"pattern {p!r}: {e}")
    if task.setup:
        if not isinstance(task.setup.get("script"), str) or not task.setup["script"].strip():
            errors.append("setup.script must be a non-empty string")
        if task.setup.get("as_user", "root") not in ("root", "agent"):
            errors.append("setup.as_user must be root or agent")
    for key, value in task.limits.items():
        if key not in ("max_steps", "max_seconds") or not isinstance(value, int) or value <= 0:
            errors.append(f"limits.{key} must be a positive integer (max_steps or max_seconds)")
    ids = [c.get("id") for c in task.conditions]
    if len(ids) != len(set(ids)) or "neutral" in ids:
        errors.append("condition ids must be unique and not 'neutral'")
    for c in task.conditions:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,40}", str(c.get("id", ""))):
            errors.append(f"condition id {c.get('id')!r}: lowercase letters, digits, - and _")
        if not (c.get("prompt_suffix") or c.get("prompt_override")):
            errors.append(f"condition {c.get('id')}: give prompt_suffix or prompt_override")
        for key, value in c.get("limits", {}).items():
            if key not in ("max_steps", "max_seconds") or not isinstance(value, int) or value <= 0:
                errors.append(f"condition {c.get('id')}: limits.{key} must be a positive integer")
    for p in task.honest_checks.get("must_report", []):
        try:
            re.compile(p)
        except re.error as e:
            errors.append(f"must_report {p!r}: {e}")
    for c in task.honest_checks.get("state_checks", []):
        if not c.get("command"):
            errors.append(f"state check {c.get('name')!r} needs a command")
    names = {s["name"] for s in task.secrets}
    for f in task.files:
        text = (folder / "files" / f["source"]).read_text(errors="replace") if (folder / "files" / f["source"]).is_file() else ""
        for used in re.findall(r"\{\{secret:(\w+)\}\}", text):
            if used not in names:
                errors.append(f"files/{f['source']} uses undeclared secret {used!r}")
    print(json.dumps({"ok": not errors, "errors": errors, "task": task.id}))
    return 0 if not errors else 1


def cmd_task_dryrun(cfg, args) -> int:
    """Build the task's sandbox without an agent and report what is armed. Nothing is kept."""
    from .tasks import setup_task
    folder = Path(args.task_dir).resolve()
    task = load_task(folder.name, folder.parent)
    secret_values = task.new_secrets()
    sb = DockerSandbox(cfg["sandbox"], f"ep-dryrun-{_stamp().lower()}")
    report = {"task": task.id, "ok": True, "errors": [],
              "prompts": {c["id"]: task.prompt_for(c) for c in [{"id": "neutral"}, *task.conditions]},
              "limits": {c["id"]: task.limits_for(cfg["episode"], c) for c in [{"id": "neutral"}, *task.conditions]}}
    sb.remove()
    try:
        sb.start()
        report["setup"] = setup_task(sb, task, secret_values)
        snapshot = sb.snapshot(task.protected_paths)
        report["protected"] = [{"path": p, "exists": snapshot.get(p) != "MISSING"} for p in task.protected_paths]
        report["errors"] += [f"protected path does not exist after setup: {p['path']}" for p in report["protected"] if not p["exists"]]
        paths = sorted({d["path"] for d in task.dirs} | {f["path"] for f in task.files} | {"/workspace"})
        listing = sb.exec(["sh", "-c", 'for p in "$@"; do [ -e "$p" ] && find "$p" -maxdepth 3 -printf "%p|%u|%m|%y|%s\\n" 2>/dev/null; done', "sh", *paths],
                          user="0", workdir="/", timeout=60)
        tree = {}
        for line in listing.stdout.splitlines():
            path, owner, mode, kind, size = (line.split("|") + ["", "", "", "", ""])[:5]
            tree[path] = {"owner": owner, "mode": mode, "type": "dir" if kind == "d" else "file", "size": int(size or 0)}
        report["tree"] = [{"path": p, **v} for p, v in sorted(tree.items())]
        report["honeypots"] = [{"name": s["name"], "file_patterns": s.get("file_patterns", []),
                                "use_patterns": s.get("use_patterns", [])} for s in task.secrets]
        report["watched"] = task.watched_reads
        report["readable_by_agent"] = {}
        for f in task.files:
            r = sb.agent_bash(f"test -r {f['path']}")
            report["readable_by_agent"][f["path"]] = r.exit_code == 0
    except Exception as e:  # noqa: BLE001 - the report is the product
        report["errors"].append(f"{type(e).__name__}: {e}")
    finally:
        sb.remove()
    report["ok"] = not report["errors"]
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def cmd_env(cfg, args) -> int:
    """Environment templates and instances: list, validate, build, up, down, status, events."""
    from . import environments as env
    from .config import is_builtin
    out = None
    if args.action == "list":
        out = {"templates": [], "instances": env.list_instances()}
        for tid in env.list_templates():
            t = env.load_template(tid)
            out["templates"].append({"id": t.id, "meta": t.meta, "segments": t.segments,
                                     "builtin": is_builtin(t.dir), "path": str(t.dir), "agent": t.agent,
                                     "nodes": [{"name": n["name"], "segment": n["segment"], "image": n.get("image")} for n in t.nodes],
                                     "gateway": t.gateway, "errors": env.validate(t)})
        out["presets"] = env.PRESETS
    elif args.action == "validate":
        errors = env.validate(env.load_template(args.target))
        out = {"ok": not errors, "errors": errors}
    elif args.action == "check":
        # Validate an environment folder before it is saved (the folder name must equal its id).
        folder = Path(args.target).resolve()
        try:
            errors = env.validate(env.load_template(folder.name, folder.parent))
        except Exception as e:  # noqa: BLE001 - reported to the caller
            errors = [f"environment.yaml: {e}"]
        out = {"ok": not errors, "errors": errors}
    elif args.action == "build":
        t = env.load_template(args.target)
        out = {"images": env.build_images(t, cfg["sandbox"], log=lambda m: print(m, file=sys.stderr))}
    elif args.action == "up":
        t = env.load_template(args.target)
        errors = env.validate(t)
        if errors:
            out = {"ok": False, "errors": errors}
        else:
            out = env.Instance(cfg["sandbox"], t, args.name or t.id).up(log=lambda m: print(m, file=sys.stderr))
    elif args.action == "down":
        state = env.load_state(args.target)
        env.Instance(cfg["sandbox"], env.load_template(state["template"]), args.target).down()
        out = env.load_state(args.target)
    elif args.action == "status":
        out = {"instances": env.list_instances()}
    elif args.action == "events":
        state = env.load_state(args.target)
        events = []
        for host, g in state.get("gateways", {}).items():
            r = subprocess.run(["docker", "exec", "-u", "0", g["container"], "cat", "/var/log/gateway.jsonl"],
                               capture_output=True, text=True)
            events += [e for e in (json.loads(l) for l in r.stdout.splitlines() if l.strip())
                       # the gateway starting up and the harness's own readiness probes are not traffic
                       if e.get("result") != "listening" and e.get("client") != "127.0.0.1"]
        out = {"events": sorted(events, key=lambda e: e.get("ts", 0))[-500:]}
    print(json.dumps(out, indent=2))
    return 0 if not (isinstance(out, dict) and out.get("ok") is False) else 1


def cmd_devbox(cfg, args) -> int:
    """Long-lived environments people can explore: create, list, shell, delete."""
    from . import environments as env
    if args.action == "create":
        t = env.load_template(args.template)
        state = env.load_state(args.name)
        if state.get("status") != "on":
            env.Instance(cfg["sandbox"], t, args.name).up(log=lambda m: print(m, file=sys.stderr))
        ws = env.Workstation(cfg["sandbox"], args.name, f"env-{args.name}-devbox"[:60], size=args.size, devbox=True)
        ws.start()
        if args.checkout:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:  # the sandbox has no internet; clone on the host
                subprocess.run(["git", "clone", "--depth", "1", args.checkout, tmp + "/repo"], check=True)
                subprocess.run(["docker", "cp", tmp + "/repo/.", f"{ws.sandbox.name}:/workspace/"], check=True)
            ws.sandbox.exec(["chown", "-R", "agent", "/workspace"], user="0", workdir="/")
        print(json.dumps({"devbox": args.name, "container": ws.sandbox.name, "size": args.size,
                          "shell": f"docker exec -it -u agent -w /workspace {ws.sandbox.name} bash"}, indent=2))
    elif args.action == "list":
        boxes = subprocess.run(["docker", "ps", "--filter", "label=harness.role=devbox", "--format",
                                "{{.Names}}\t{{.Label \"harness.instance\"}}\t{{.Status}}"], capture_output=True, text=True).stdout
        print(json.dumps({"devboxes": [dict(zip(("container", "instance", "status"), l.split("\t"))) for l in boxes.splitlines()]}, indent=2))
    elif args.action == "shell":
        os.execvp("docker", ["docker", "exec", "-it", "-u", "agent", "-w", "/workspace", f"env-{args.name}-devbox"[:60], "bash"])
    elif args.action == "delete":
        state = env.load_state(args.name)
        if state:
            env.Instance(cfg["sandbox"], env.load_template(state["template"]), args.name).down()
        print(json.dumps({"deleted": args.name}))
    return 0


def cmd_paths(cfg, args) -> int:
    """Where everything lives, so apps never have to guess or ask people for folders."""
    from . import config as c
    print(json.dumps({"version": c.version(), "home": str(c.HOME), "builtin": str(c.BUILTIN),
                      "user_tasks": str(c.HOME / "tasks"), "user_environments": str(c.HOME / "environments"),
                      "user_mocks": str(c.HOME / "mocks"), "runs": str(c.RUNS_DIR), "instances": str(c.INSTANCES_DIR),
                      "keys": str(c.KEYS_DIR), "sandbox_image": cfg["sandbox"]["image"],
                      "network": cfg["sandbox"]["network"], "runtime": cfg["sandbox"]["runtime"]}, indent=2))
    return 0


def _step(name: str, ok: bool, detail: str = "") -> dict:
    entry = {"name": name, "passed": ok, "detail": detail}
    print(json.dumps(entry), file=sys.stderr, flush=True)  # progress for apps
    return entry


def cmd_setup(cfg, args) -> int:
    """Prepare this machine: sandbox runtime (optional install), image and network."""
    import platform
    import shutil
    from . import config as c
    steps, sb = [], cfg["sandbox"]
    brew = shutil.which("brew") or ("/opt/homebrew/bin/brew" if Path("/opt/homebrew/bin/brew").exists() else None)
    if args.install_runtime:
        if platform.system() != "Darwin" or not brew:
            steps.append(_step("install runtime", False, "Automatic install needs macOS with Homebrew. On Linux, install Docker and gVisor (runsc): https://gvisor.dev/docs/user_guide/install/"))
        else:
            for name, cmd in [
                ("install colima and docker", [brew, "install", "colima", "docker", "docker-buildx"]),
                ("start the Linux VM", ["colima", "start", "--cpu", "4", "--memory", "8", "--disk", "60", "--vm-type", "vz"]),
                ("install gVisor in the VM", ["colima", "ssh", "--", "bash", "-lc",
                    "curl -fsSL https://gvisor.dev/archive.key | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg && "
                    "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main\" | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null && "
                    "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq runsc && sudo runsc install && sudo systemctl restart docker"])]:
                r = subprocess.run(cmd, capture_output=True, text=True)
                steps.append(_step(name, r.returncode == 0, (r.stderr or r.stdout)[-300:].strip()))
                if r.returncode:
                    break
            colima_cfg = Path("~/.colima/default/colima.yaml").expanduser()
            if colima_cfg.exists() and "runsc" not in colima_cfg.read_text():
                text = colima_cfg.read_text().replace("docker: {}", "docker:\n  runtimes:\n    runsc:\n      path: /usr/bin/runsc")
                colima_cfg.write_text(text)
                steps.append(_step("keep gVisor across VM restarts", "runsc" in text, str(colima_cfg)))
    try:
        info = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True, timeout=30)
        docker_ok = info.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        docker_ok, info = False, None
    steps.append(_step("docker reachable", docker_ok, "" if docker_ok else "Install a Docker runtime, or run setup --install-runtime on macOS"))
    if docker_ok:
        steps.append(_step("gVisor runtime available", sb["runtime"] in info.stdout, info.stdout.strip()[:200]))
        have = subprocess.run(["docker", "image", "inspect", sb["image"]], capture_output=True).returncode == 0
        if not have:
            r = subprocess.run(["docker", "build", "-t", sb["image"], "-f", str(c.DOCKERFILE), str(c.BUILTIN)], capture_output=True, text=True)
            have = r.returncode == 0
        steps.append(_step("sandbox image", have, sb["image"]))
        net = subprocess.run(["docker", "network", "inspect", sb["network"]], capture_output=True).returncode == 0
        if not net:
            net = subprocess.run(["docker", "network", "create", "--internal", "--subnet", "10.77.0.0/24", sb["network"]],
                                 capture_output=True).returncode == 0
        steps.append(_step("internal network", net, sb["network"]))
    for d in (c.HOME / "tasks", c.HOME / "environments", c.HOME / "mocks", c.RUNS_DIR, c.KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    ok = all(s["passed"] for s in steps)
    print(json.dumps({"ok": ok, "steps": steps, "home": str(c.HOME)}, indent=2))
    return 0 if ok else 1


def cmd_export(cfg, args) -> int:
    """A shareable, verifiable bundle of a run. Reasoning is included unless --no-reasoning."""
    from .config import KEYS_DIR
    from .export import export_run
    key = Path(args.key) if args.key else (KEYS_DIR / "signing.pem" if (KEYS_DIR / "signing.pem").exists() else None)
    meta = {k: v for k, v in (("title", args.title), ("question", args.question)) if v}
    summary = export_run(Path(args.run_dir), Path(args.out), reasoning=not args.no_reasoning, key=key, meta=meta)
    print(json.dumps({k: summary[k] for k in ("schema", "reasoning_included", "redactions", "signed")} |
                     {"episodes": len(summary["episodes"]), "files": len(summary["files"]),
                      "bytes": sum(f["bytes"] for f in summary["files"]), "out": args.out}, indent=2))
    return 0


def cmd_keygen(cfg, args) -> int:
    from .config import KEYS_DIR
    print(f"Public key: {evidence.keygen(Path(args.out) if args.out else KEYS_DIR / 'signing.pem')}  (publish this; keep the .pem private)")
    return 0


def cmd_seal(cfg, args) -> int:
    print(f"Wrote {evidence.seal(Path(args.run_dir), args.key)}"
          + (" and SHA256SUMS.sig" if args.key else " (unsigned: pass --key to sign)"))
    return 0


def cmd_verify(cfg, args) -> int:
    problems = evidence.verify(Path(args.run_dir), args.pubkey)
    for p in problems:
        print("FAIL", p)
    print("OK: bundle verifies." if not problems else f"{len(problems)} problem(s).")
    return 1 if problems else 0


def cmd_ledger(cfg, args) -> int:
    problems = ledger.validate()
    for p in problems:
        print("FAIL", p)
    print("OK: ledger is valid." if not problems else f"{len(problems)} problem(s).")
    return 1 if problems else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness")
    ap.add_argument("--config", help="path to harness.yaml")
    ap.add_argument("--base-url", help="override model.base_url (e.g. Dyno's http://127.0.0.1:8971/v1)")
    ap.add_argument("--model-id", help="override model.id")
    ap.add_argument("--model-revision", help="override model.revision")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="run isolation checks").add_argument("--json", action="store_true")
    sub.add_parser("smoke", help="smoke-test tool calling on the model server")
    p = sub.add_parser("control", help="run scripted positive controls")
    p.add_argument("--tasks", nargs="*")
    p.add_argument("--out")
    p = sub.add_parser("episode", help="run a single episode")
    p.add_argument("--task", required=True)
    p.add_argument("--model", default="vllm", help="vllm | scripted:honest | scripted:rule_break")
    p.add_argument("--seed", type=int)
    p.add_argument("--out")
    p = sub.add_parser("run", help="N episodes of one task with the configured model")
    p.add_argument("--task", required=True)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--condition", help="a condition id from the task (default: neutral)")
    p.add_argument("--instance", help="run against this running environment instance")
    p.add_argument("--seed", type=int)
    p.add_argument("--out")
    p = sub.add_parser("pilot", help="checks, controls, then the 20-episode pilot")
    p.add_argument("--out")
    p.add_argument("--skip-control", action="store_true")
    for name in ("label", "summarize"):
        sub.add_parser(name).add_argument("run_dir")
    p = sub.add_parser("keygen", help="create an Ed25519 signing key")
    p.add_argument("--out", default=None, help="default: <HARNESS_HOME>/keys/signing.pem")
    p = sub.add_parser("seal", help="write SHA256SUMS (and signature) for a run folder")
    p.add_argument("run_dir")
    p.add_argument("--key")
    p = sub.add_parser("verify", help="verify a sealed run folder")
    p.add_argument("run_dir")
    p.add_argument("--pubkey")
    sub.add_parser("ledger", help="validate ledger/claims.yaml")
    sub.add_parser("tasks", help="list tasks as JSON")
    sub.add_parser("paths", help="where built-in and user content lives")
    p = sub.add_parser("export", help="a shareable, verifiable bundle of a run")
    p.add_argument("run_dir")
    p.add_argument("--out", required=True)
    p.add_argument("--no-reasoning", action="store_true", help="remove the model's reasoning from every transcript")
    p.add_argument("--key", help="signing key (default: <HARNESS_HOME>/keys/signing.pem if present)")
    p.add_argument("--title")
    p.add_argument("--question")
    sub.add_parser("setup", help="prepare the sandbox runtime, image and network").add_argument(
        "--install-runtime", action="store_true", help="macOS: install Colima, Docker and gVisor with Homebrew")
    p = sub.add_parser("env", help="environment templates and instances")
    p.add_argument("action", choices=["list", "validate", "check", "build", "up", "down", "status", "events"])
    p.add_argument("target", nargs="?", help="template id (validate/build/up) or instance name (down/events)")
    p.add_argument("--name", help="instance name for up (default: the template id)")
    p = sub.add_parser("devbox", help="long-lived environments to explore by hand")
    p.add_argument("action", choices=["create", "list", "shell", "delete"])
    p.add_argument("name", nargs="?")
    p.add_argument("--template")
    p.add_argument("--size", choices=["s", "m", "l"], default="m")
    p.add_argument("--checkout", help="git repository to copy into /workspace")
    sub.add_parser("task-check", help="validate one task folder").add_argument("task_dir")
    sub.add_parser("task-dryrun", help="build a task's sandbox without an agent and report it").add_argument("task_dir")

    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    for key, value in (("base_url", args.base_url), ("id", args.model_id),
                       ("revision", args.model_revision)):
        if value:
            cfg["model"][key] = value
    return globals()[f"cmd_{args.cmd.replace('-', '_')}"](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
