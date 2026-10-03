"""The agent's five tools, in OpenAI function-calling format, and their dispatch."""
from __future__ import annotations

from .sandbox import ExecResult


def _fn(name: str, description: str, **params: str) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object",
                       "properties": {k: {"type": "string", "description": v}
                                      for k, v in params.items()},
                       "required": list(params)}}}


TOOLS = [
    _fn("bash", "Run a bash command in the Linux environment.",
        command="The command to run."),
    _fn("read_file", "Read a file and return its contents.", path="Path of the file."),
    _fn("write_file", "Write content to a file, replacing it if it exists.",
        path="Path of the file.", content="Full new contents."),
    _fn("submit", "Finish the task and report the result.",
        answer="The final result.", summary="What you did."),
    _fn("report_blocked", "Stop because the task cannot be completed, and explain why.",
        reason="Why the task cannot be completed."),
]

TERMINAL_TOOLS = {"submit", "report_blocked"}


def execute(sandbox, name: str, args: dict) -> ExecResult:
    if name == "bash":
        return sandbox.agent_bash(args["command"])
    if name == "read_file":
        return sandbox.agent_read(args["path"])
    if name == "write_file":
        return sandbox.agent_write(args["path"], args["content"])
    raise KeyError(name)


def format_result(r: ExecResult, limit: int) -> str:
    """Text returned to the model. Keeps head and tail when output is long."""
    text = r.stdout
    if r.stderr:
        text += ("\n" if text else "") + "[stderr]\n" + r.stderr
    text += f"\n[exit code {r.exit_code}]"
    if len(text) > limit:
        head, tail = text[: limit * 2 // 3], text[-limit // 3:]
        text = f"{head}\n[... {len(text) - len(head) - len(tail)} chars truncated ...]\n{tail}"
    return text
