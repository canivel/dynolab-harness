"""Model clients: vLLM's OpenAI-compatible server, and a scripted fake for controls."""
from __future__ import annotations

import json
from pathlib import Path

import requests
import yaml

from .config import MOCK_DIRS, find


class OpenAICompatModel:
    """Any OpenAI-compatible chat server: mlx_lm.server, Dyno, vLLM."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.base_url = cfg["base_url"].rstrip("/")

    def start_episode(self, ctx: dict) -> None:
        pass

    def complete(self, messages: list[dict], tools: list[dict], seed: int | None) -> dict:
        body = {"model": self.cfg["id"], "messages": messages, "tools": tools,
                "tool_choice": "auto", **self.cfg.get("sampling", {})}
        if seed is not None:
            body["seed"] = seed
        r = requests.post(f"{self.base_url}/chat/completions", json=body,
                          timeout=self.cfg.get("request_timeout_s", 300))
        r.raise_for_status()
        data = r.json()
        choice = data["choices"][0]
        # Kept beside the message so the scaffold can log them; never sent back.
        return {**choice["message"], "_finish_reason": choice.get("finish_reason"),
                "_usage": data.get("usage")}

    def info(self) -> dict:
        root = self.base_url.removesuffix("/v1")
        try:
            version = requests.get(f"{root}/version", timeout=10).json().get("version")
        except (requests.RequestException, ValueError):
            version = None
        return {"model_id": self.cfg["id"], "model_revision": self.cfg.get("revision"),
                "server": self.cfg.get("server"), "server_version": version,
                "base_url": self.base_url, "sampling": self.cfg.get("sampling", {})}


class ScriptedModel:
    """Replays pre-set tool calls. `{{secret:name}}` in arguments is filled per episode.

    Used for positive controls: a rule-breaking script that the labeler fails to
    flag means the labeler is wrong.
    """

    def __init__(self, script_path: Path):
        self.script_path = Path(script_path)
        with open(self.script_path) as f:
            self.steps = yaml.safe_load(f)["steps"]
        self._secrets: dict[str, str] = {}
        self._i = 0

    @classmethod
    def for_task(cls, task_id: str, behaviour: str) -> "ScriptedModel":
        return cls(find(MOCK_DIRS, task_id, f"{behaviour}.yaml") / f"{behaviour}.yaml")

    def start_episode(self, ctx: dict) -> None:
        self._secrets = ctx.get("secrets", {})
        self._i = 0

    def _fill(self, value: str) -> str:
        for k, v in self._secrets.items():
            value = value.replace("{{secret:%s}}" % k, v)
        return value

    def complete(self, messages: list[dict], tools: list[dict], seed: int | None) -> dict:
        if self._i >= len(self.steps):
            return {"role": "assistant", "content": "(script exhausted)"}
        step = self.steps[self._i]
        self._i += 1
        args = {k: self._fill(str(v)) for k, v in step["args"].items()}
        return {"role": "assistant", "content": step.get("text"),
                "reasoning_content": step.get("reasoning"),
                "tool_calls": [{"id": f"call_{self._i}", "type": "function",
                                "function": {"name": step["tool"],
                                             "arguments": json.dumps(args)}}]}

    def info(self) -> dict:
        return {"model_id": f"scripted:{self.script_path.parent.name}/{self.script_path.stem}",
                "model_revision": None, "server": "scripted", "server_version": None,
                "base_url": None, "sampling": {}}
