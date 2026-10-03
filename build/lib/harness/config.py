"""Where the harness finds things: built-in content shipped with the package, and the user's own.

Built-in tasks, environment templates, scripted controls and the sandbox Dockerfile ship inside
the package and are read-only. Everything people create (tasks, environments, controls, runs,
signing keys, running instances) lives under HARNESS_HOME, default ~/.dynolab/harness.
The harness reads both; built-in ids cannot be overridden.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

PACKAGE = Path(__file__).resolve().parent
BUILTIN = PACKAGE / "builtin"
ROOT = PACKAGE.parent                      # the source checkout, when running from one
HOME = Path(os.environ.get("HARNESS_HOME") or "~/.dynolab/harness").expanduser()

TASK_DIRS = [BUILTIN / "tasks", HOME / "tasks"]
ENV_DIRS = [BUILTIN / "environments", HOME / "environments"]
MOCK_DIRS = [BUILTIN / "mocks", HOME / "mocks"]
RUNS_DIR = HOME / "runs"
INSTANCES_DIR = HOME / "instances"
KEYS_DIR = HOME / "keys"
LEDGER_DIR = ROOT / "ledger"
DOCKERFILE = BUILTIN / "sandbox.Dockerfile"

# Kept for code and tests that address the built-in set directly.
TASKS_DIR = BUILTIN / "tasks"
MOCKS_DIR = BUILTIN / "mocks"


def find(kind_dirs: list[Path], item: str, marker: str) -> Path:
    """The first directory that holds <item>/<marker>; built-in first so it can't be shadowed."""
    for d in kind_dirs:
        if (d / item / marker).exists():
            return d / item
    raise FileNotFoundError(f"{item} not found in {', '.join(str(d) for d in kind_dirs)}")


def list_ids(kind_dirs: list[Path], marker: str) -> list[str]:
    seen: dict[str, Path] = {}
    for d in kind_dirs:
        if d.exists():
            for item in sorted(d.iterdir()):
                if (item / marker).exists() and item.name not in seen:
                    seen[item.name] = item
    return sorted(seen)


def is_builtin(path: Path) -> bool:
    return BUILTIN in Path(path).resolve().parents


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path: str | Path | None = None) -> dict:
    """Built-in defaults, then HARNESS_HOME/harness.yaml, then ./harness.yaml, then an explicit file."""
    cfg = yaml.safe_load((BUILTIN / "harness.yaml").read_text())
    layers = [HOME / "harness.yaml", Path.cwd() / "harness.yaml"] + ([Path(path)] if path else [])
    for layer in layers:
        if layer.exists() and layer.resolve() != (BUILTIN / "harness.yaml").resolve():
            cfg = _merge(cfg, yaml.safe_load(layer.read_text()) or {})
    if cfg["sandbox"].get("image") in (None, "", "auto"):
        cfg["sandbox"]["image"] = sandbox_image_tag()
    return cfg


def sandbox_image_tag() -> str:
    """Named after the Dockerfile's content, so a changed image is rebuilt, never reused."""
    import hashlib
    return "dynolab-sandbox:" + hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest()[:12]


def version() -> str:
    try:
        from importlib.metadata import version as v
        return v("claims-harness")
    except Exception:  # noqa: BLE001 - running from a checkout without an install
        return "dev"
