"""Pre-batch isolation checks (guide Step 3.7). A batch must not start if any fails."""
from __future__ import annotations

import subprocess
from typing import Callable

from .sandbox import DockerSandbox

PROBE = "/opt/isolation-probe"

# What each check proves, and the command behind it. Shown to people reviewing a run.
DESCRIPTIONS = {
    "docker reachable": ("Docker answers on this machine.", "docker info"),
    "sandbox image built": ("The sandbox image exists locally.", "docker image inspect <image>"),
    "network is --internal": ("The episode network has no route to the outside world.",
                              "docker network inspect --format {{.Internal}} <network>"),
    "runtime is runsc": ("A throwaway container really runs under gVisor, not the default runtime.",
                         "docker inspect --format {{.HostConfig.Runtime}} ep-isolation-check"),
    "no egress": ("The agent user cannot reach the internet from inside the container.",
                  "curl -sS -m 5 https://example.com  (as agent; must fail)"),
    "root files protected": ("The agent user cannot read a root-only file (mode 0600).",
                             f"cat {PROBE}  (as agent; must fail)"),
    "no sudo": ("The agent user cannot escalate with sudo.", "sudo -n true  (as agent; must fail)"),
}

Report = Callable[[str, bool, str], None]


def run_checks(sandbox_cfg: dict, on_result: Report | None = None) -> list[tuple[str, bool, str]]:
    """Returns (check name, passed, detail) for each check, reporting each as it finishes."""
    results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        results.append((name, passed, detail))
        if on_result:
            on_result(name, passed, detail)

    try:
        info = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"],
                              capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        record("docker reachable", False, f"docker unavailable: {e}")
        return results
    record("docker reachable", info.returncode == 0,
           "ok" if info.returncode == 0 else (info.stderr.strip()[:200] or "docker not found"))
    if info.returncode != 0:
        return results
    image = subprocess.run(["docker", "image", "inspect", sandbox_cfg["image"]],
                           capture_output=True, text=True)
    record("sandbox image built", image.returncode == 0,
           sandbox_cfg["image"] if image.returncode == 0 else "run `make image`")
    if image.returncode != 0:
        return results
    net = subprocess.run(["docker", "network", "inspect", "--format", "{{.Internal}}",
                          sandbox_cfg["network"]], capture_output=True, text=True)
    record("network is --internal", net.stdout.strip() == "true",
           net.stdout.strip() or net.stderr.strip())

    sb = DockerSandbox(sandbox_cfg, "ep-isolation-check")
    sb.remove()
    try:
        sb.start()
        rt = sb.runtime()
        record("runtime is runsc", rt == "runsc", rt)

        r = sb.agent_bash("curl -sS -m 5 https://example.com")
        record("no egress", r.exit_code != 0, f"curl exit {r.exit_code}: {r.stderr.strip()[:160]}")

        sb.root_put_file(PROBE, b"probe\n", "root", "0600")
        r = sb.agent_bash(f"cat {PROBE}")
        record("root files protected", r.exit_code != 0, f"cat exit {r.exit_code}: {r.stderr.strip()[:160]}")

        r = sb.agent_bash("sudo -n true")
        record("no sudo", r.exit_code != 0, f"sudo exit {r.exit_code}: {r.stderr.strip()[:160]}")
    finally:
        sb.remove()
    return results
