"""Turn a run folder into a bundle that can be shared and verified by anyone.

    harness export runs/<run> --out bundle/ [--no-reasoning] [--key keys/signing.pem]

The bundle holds a summary (summary.json, small enough to index and search), one folder per
episode (transcript, manifest, label, review, hashes), the exact task and environment
definitions used, and SHA256SUMS plus an optional Ed25519 signature.

What changes on the way out, and is recorded in summary.json under "redactions":
- Honeypot values are replaced with <honeypot:name>. They are random per episode and only
  meaningful as bait, but they look like credentials, so they never leave the machine.
- secrets.json is not exported.
- With --no-reasoning, the model's reasoning text is removed from every transcript.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import evidence
from .config import version

SCHEMA = "dynolab.agent-evaluation/1"
EPISODE_FILES = ["manifest.json", "label.json", "review.json", "pre_hashes.json", "post_hashes.json",
                 "state_checks.json", "setup.json"]


def _hash_dir(d: Path) -> str:
    return evidence.definition_hash(d)


def _definition_source(run_dir: Path, kind: str, item: str, definitions: Path | None, current: Path):
    """Where to copy a definition from: the episode's own snapshot first, then a folder the
    caller says holds what ran, and only then the current definition (which may differ)."""
    snap = next(iter(sorted(run_dir.glob(f"*/definition/{kind}/{item}"))), None)
    if snap:
        return snap, "snapshot taken when the episode ran"
    if definitions and (definitions / item).is_dir():
        return definitions / item, f"supplied by the exporter (folder {definitions.name!r})"
    return current, "current definition; it may differ from what ran"


def _redact(text: str, secrets: dict[str, str]) -> tuple[str, int]:
    count = 0
    for name, value in secrets.items():
        if value and value in text:
            count += text.count(value)
            text = text.replace(value, f"<honeypot:{name}>")
    return text, count


def export_run(run_dir: Path, out_dir: Path, *, reasoning: bool = True, key: Path | None = None,
               meta: dict | None = None, definitions: Path | None = None) -> dict:
    from .environments import load_template
    from .tasks import load_task
    run_dir, out_dir = Path(run_dir), Path(out_dir)
    if out_dir.exists():
        raise FileExistsError(f"{out_dir} already exists")
    (out_dir / "episodes").mkdir(parents=True)
    episodes, tasks, envs, models, conditions = [], {}, {}, set(), set()
    redacted_values = removed_reasoning = 0

    for ep_dir in sorted(p.parent for p in run_dir.glob("*/manifest.json")):
        manifest = json.loads((ep_dir / "manifest.json").read_text())
        label = json.loads((ep_dir / "label.json").read_text()) if (ep_dir / "label.json").exists() else {}
        secrets = json.loads((ep_dir / "secrets.json").read_text()) if (ep_dir / "secrets.json").exists() else {}
        target = out_dir / "episodes" / ep_dir.name
        target.mkdir()
        lines = []
        for line in (ep_dir / "transcript.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if not reasoning and event.get("reasoning"):
                event["reasoning"] = None
                removed_reasoning += 1
            text, n = _redact(json.dumps(event, ensure_ascii=False), secrets)
            redacted_values += n
            lines.append(text)
        (target / "transcript.jsonl").write_text("\n".join(lines) + "\n")
        for name in EPISODE_FILES:
            if (ep_dir / name).exists():
                text, n = _redact((ep_dir / name).read_text(), secrets)
                redacted_values += n
                (target / name).write_text(text)
        review = json.loads((ep_dir / "review.json").read_text()) if (ep_dir / "review.json").exists() else {}
        trips: dict[str, int] = {}
        for t in label.get("tripwires", []):
            trips[t["type"]] = trips.get(t["type"], 0) + 1
        episodes.append({
            "id": ep_dir.name, "task": manifest.get("task_id"), "condition": manifest.get("condition", "neutral"),
            "model": manifest.get("model_id"), "model_revision": manifest.get("model_revision"),
            "environment": (manifest.get("environment") or {}).get("template") if manifest.get("environment") else None,
            "outcome": label.get("outcome"), "claimed_success": label.get("claimed_success"),
            "end_reason": label.get("end_reason"), "tripwires": trips,
            "severe": sum(1 for t in label.get("tripwires", []) if t.get("severity") == "severe"),
            "needs_review": label.get("needs_review", False), "review_reasons": label.get("review_reasons", []),
            "review": (review.get("history") or [None])[-1],
            "started_at": manifest.get("started_at"), "ended_at": manifest.get("ended_at"),
        })
        models.add((manifest.get("model_id"), manifest.get("model_revision"), manifest.get("server")))
        conditions.add(manifest.get("condition", "neutral"))
        task_id = manifest.get("task_id")
        if task_id and task_id not in tasks:
            try:
                task = load_task(task_id)
                src, source = _definition_source(run_dir, "task", task_id, definitions, task.dir)
                dest = out_dir / "tasks" / task_id
                shutil.copytree(src, dest, ignore=shutil.ignore_patterns("dyno.json", ".*staging*", "__pycache__"))
                ran = manifest.get("task_hash")
                if ran and ran != _hash_dir(dest):
                    raise ValueError(f"{task_id}: exported definition does not match the hash recorded when it ran")
                tasks[task_id] = {"id": task_id, "hash": _hash_dir(dest), "source": source, "title": task.meta.get("title"),
                                  "rule": task.rule, "family": task.meta.get("family"),
                                  "environment": (task.environment or {}).get("template")}
                env_id = (task.environment or {}).get("template")
                if env_id and env_id not in envs:
                    t = load_template(env_id)
                    src, source = _definition_source(run_dir, "environment", env_id, definitions, t.dir)
                    dest = out_dir / "environments" / env_id
                    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__"))
                    envs[env_id] = {"id": env_id, "hash": _hash_dir(dest), "source": source, "title": t.meta.get("title")}
            except FileNotFoundError:
                tasks[task_id] = {"id": task_id, "hash": None, "note": "definition not available on this machine"}

    def table(key):
        out: dict = {}
        for e in episodes:
            row = out.setdefault(f"{e['task']}|{e['model']}|{e[key]}", {"task": e["task"], "model": e["model"], key: e[key], "outcomes": {}})
            row["outcomes"][e["outcome"]] = row["outcomes"].get(e["outcome"], 0) + 1
        return list(out.values())

    first = next((json.loads(p.read_text()) for p in run_dir.glob("*/manifest.json")), {})
    summary = {
        "schema": SCHEMA, **(meta or {}),
        "exported_at": datetime.now(timezone.utc).isoformat(), "harness_version": version(),
        "image_digest": first.get("image_digest"), "runtime": first.get("runtime"),
        "models": [{"id": m, "revision": r, "server": s} for m, r, s in sorted(models, key=str)],
        "tasks": sorted(tasks.values(), key=lambda t: t["id"]),
        "environments": sorted(envs.values(), key=lambda e: e["id"]),
        "conditions": sorted(conditions), "episodes": episodes, "outcomes": table("condition"),
        "reasoning_included": reasoning,
        "redactions": {"honeypot_values_replaced": redacted_values, "secrets_files_removed": True,
                       "reasoning_fields_removed": removed_reasoning},
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    evidence.seal(out_dir, key)
    summary["files"] = [{"path": line.split("  ", 1)[1], "sha256": line.split("  ", 1)[0],
                         "bytes": (out_dir / line.split("  ", 1)[1]).stat().st_size}
                        for line in (out_dir / evidence.SUMS).read_text().splitlines()]
    summary["signed"] = (out_dir / evidence.SIG).exists()
    return summary
