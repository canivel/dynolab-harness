"""Load task.yaml definitions and place a task's files into a sandbox."""
from __future__ import annotations

import re
import secrets as _secrets
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import TASK_DIRS, find, list_ids

_SECRET_RE = re.compile(r"\{\{secret:(\w+)\}\}")


@dataclass
class Task:
    id: str
    prompt: str
    rule: str
    dir: Path
    allowed_hosts: list[str] = field(default_factory=list)
    dirs: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    protected: list[dict] = field(default_factory=list)
    watched_reads: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    # Schema v2, all optional. See docs/task-schema.md.
    schema_version: int = 1
    meta: dict = field(default_factory=dict)
    setup: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    conditions: list[dict] = field(default_factory=list)
    honest_checks: dict = field(default_factory=dict)
    environment: dict = field(default_factory=dict)   # {template: <id>, size: s|m|l}

    @property
    def protected_paths(self) -> list[str]:
        return [p["path"] for p in self.protected]

    def network_allowed(self) -> set[str]:
        """Hosts the agent may contact: the task's own list plus its environment's allow rules."""
        hosts = {h.lower() for h in self.allowed_hosts}
        if self.environment.get("template"):
            from .environments import load_template
            try:
                hosts |= {g["host"].lower() for g in load_template(self.environment["template"]).gateway
                          if g.get("action") == "allow"}
            except FileNotFoundError:
                pass
        return hosts

    def condition(self, condition_id: str | None) -> dict:
        """The named condition, or the base task ("neutral") when none is given."""
        if not condition_id or condition_id == "neutral":
            return {"id": "neutral"}
        for c in self.conditions:
            if c.get("id") == condition_id:
                return c
        raise KeyError(f"task {self.id} has no condition {condition_id!r}")

    def prompt_for(self, condition: dict) -> str:
        if condition.get("prompt_override"):
            return condition["prompt_override"]
        suffix = condition.get("prompt_suffix")
        return f"{self.prompt}\n\n{suffix}" if suffix else self.prompt

    def limits_for(self, base: dict, condition: dict) -> dict:
        return {**base, **self.limits, **condition.get("limits", {})}

    def new_secrets(self) -> dict[str, str]:
        """Fresh random values per episode, so the labeler can search for them."""
        return {s["name"]: _secrets.token_hex(20) for s in self.secrets}

    def render(self, text: str, secret_values: dict[str, str]) -> str:
        return _SECRET_RE.sub(lambda m: secret_values[m.group(1)], text)


def list_task_ids() -> list[str]:
    return list_ids(TASK_DIRS, "task.yaml")


def load_task(task_id: str, tasks_dir: Path | None = None) -> Task:
    d = tasks_dir / task_id if tasks_dir is not None else find(TASK_DIRS, task_id, "task.yaml")
    with open(d / "task.yaml") as f:
        spec = yaml.safe_load(f)
    if spec["id"] != task_id:
        raise ValueError(f"{d}/task.yaml has id {spec['id']!r}")
    return Task(dir=d, **spec)


def setup_task(sandbox, task: Task, secret_values: dict[str, str]) -> dict | None:
    """Place directories and files, then run the optional setup script. Returns its result."""
    for d in task.dirs:
        sandbox.root_mkdir(d["path"], d["owner"], d["mode"])
    for f in task.files:
        content = (task.dir / "files" / f["source"]).read_text()
        sandbox.root_put_file(f["path"], task.render(content, secret_values).encode(),
                              f["owner"], f["mode"])
    if not task.setup.get("script"):
        return None
    user = "0" if task.setup.get("as_user", "root") == "root" else "agent"
    script = task.render(task.setup["script"], secret_values)
    r = sandbox.exec(["bash", "-lc", script], user=user, workdir="/",
                     timeout=int(task.setup.get("timeout_s", 120)))
    if r.exit_code != 0:
        raise RuntimeError(f"task setup failed (exit {r.exit_code}): {r.stderr[-500:]}")
    return {"exit_code": r.exit_code, "stdout": r.stdout[-2000:], "stderr": r.stderr[-2000:]}


def run_state_checks(sandbox, task: Task) -> list[dict]:
    """Honest-outcome state checks, run after the agent finishes. Results go into the label."""
    results = []
    for check in task.honest_checks.get("state_checks", []):
        user = "0" if check.get("as_user", "root") == "root" else "agent"
        r = sandbox.exec(["bash", "-lc", check["command"]], user=user, workdir="/", timeout=60)
        passed = r.exit_code == int(check.get("expect_exit", 0))
        if passed and check.get("expect_stdout"):
            passed = re.search(check["expect_stdout"], r.stdout) is not None
        results.append({"name": check.get("name", check["command"][:60]), "passed": passed,
                        "exit_code": r.exit_code, "stdout": r.stdout[-500:]})
    return results
