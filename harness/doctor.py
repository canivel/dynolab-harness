"""What this machine still needs before agents can run in the sandbox, and setting it up.

`diagnose` only looks: it lists each requirement, whether it's met, why it's needed and how setup would fix it,
so an app can ask the person before anything is installed. `setup` then fixes what's missing, in order, each step
with a time limit and the tool's own error when it fails.
"""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

BREW_INSTALL = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
GVISOR_IN_VM = (
    "curl -fsSL https://gvisor.dev/archive.key | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg && "
    "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] "
    "https://storage.googleapis.com/gvisor/releases release main\" | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null && "
    "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq runsc && sudo runsc install && "
    "sudo systemctl restart docker")
COLIMA_NEW = ["colima", "start", "--cpu", "4", "--memory", "8", "--disk", "60", "--vm-type", "vz"]
COLIMA_CONFIG = Path("~/.colima/default/colima.yaml").expanduser()

Step = Callable[[str, bool, str], None]


def run(cmd: list[str], timeout: float = 30, input: str | None = None) -> tuple[int, str, str]:
    """Never raises: a missing tool is 127 and a timeout is 124, like a shell."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]} did not finish within {int(timeout)} s"


def tail(text: str, n: int = 400) -> str:
    text = " ".join(text.strip().split())
    return text if len(text) <= n else "…" + text[-n:]


def brew() -> str | None:
    return shutil.which("brew") or next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if Path(p).exists()), None)


def runtimes() -> tuple[bool, list[str], str]:
    """(docker answers, runtime names, error)."""
    code, out, err = run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=30)
    if code != 0:
        return False, [], tail(err or out) or "docker did not answer"
    try:
        return True, sorted(json.loads(out or "{}")), ""
    except ValueError:
        return True, [], ""


def colima_state() -> str:
    """'missing', 'stopped' or 'running'."""
    if not shutil.which("colima"):
        return "missing"
    return "running" if run(["colima", "status"], timeout=30)[0] == 0 else "stopped"


def engine_name() -> str:
    code, out, _ = run(["docker", "context", "show"], timeout=10)
    return out.strip() if code == 0 else ""


def diagnose(sandbox_cfg: dict) -> dict:
    """Each requirement with ok, detail, why, and the fix setup would apply (or what the person must do)."""
    mac = platform.system() == "Darwin"
    has_brew = bool(brew())
    colima = colima_state()
    docker_ok, names, docker_err = runtimes()
    context = engine_name() if docker_ok else ""
    on_colima = docker_ok and context.startswith("colima")
    items = []

    def item(id, name, ok, detail, why, fix=None):
        # Without Docker the rest can't be looked at: ok is None and the fix is what setup does if it's missing.
        if not docker_ok and id != "docker":
            ok, detail = None, "Checked once Docker runs"
            fix = dict(fix, if_missing=True) if fix else None
        items.append(dict(id=id, name=name, ok=ok, detail=detail, why=why, fix=None if ok else fix))

    def install_fix(label, minutes):
        if not mac:
            return dict(auto=False, label="Install Docker and gVisor (runsc) yourself",
                        manual="https://gvisor.dev/docs/user_guide/install/")
        return dict(auto=True, label=label, minutes=minutes, needs=["internet", "homebrew"])

    if docker_ok:
        item("docker", "Docker", True, f"Running ({context or 'default context'})",
             "Every agent works inside a throwaway Docker container.")
    elif colima == "stopped":
        item("docker", "Docker", False, "Colima is installed but its Linux VM is stopped",
             "Every agent works inside a throwaway Docker container.",
             dict(auto=True, label="Start the Colima Linux VM", minutes=1, needs=[]))
    else:
        item("docker", "Docker", False, docker_err if shutil.which("docker") else "Not installed",
             "Every agent works inside a throwaway Docker container.",
             install_fix("Install Colima and Docker with Homebrew, then start the Colima Linux VM (4 CPUs, 8 GB memory)", 5))

    gvisor_ok = sandbox_cfg.get("runtime", "runsc") in names
    if gvisor_ok:
        why_detail = "Installed in Docker"
    elif not docker_ok:
        why_detail = "Needs Docker first"
    elif on_colima:
        why_detail = "Not installed in the Colima VM"
    else:
        why_detail = f"Not available in {context or 'this Docker'}"
    gvisor_fix = (dict(auto=True, label="Install gVisor in the Colima VM", minutes=2, needs=["internet"])
                  if on_colima or not docker_ok else
                  dict(auto=mac, label="Install Colima with Homebrew and use it for the sandbox, with gVisor "
                       f"(your docker command will then use Colima; `docker context use {context}` switches back)",
                       minutes=6, needs=["internet", "homebrew"],
                       **({} if mac else dict(manual="https://gvisor.dev/docs/user_guide/install/"))))
    item("gvisor", "gVisor sandbox runtime", gvisor_ok, why_detail,
         "gVisor puts its own kernel between the agent and your Mac, so a command can't escape the container.", gvisor_fix)

    image = sandbox_cfg["image"]
    image_ok = docker_ok and run(["docker", "image", "inspect", image], timeout=30)[0] == 0
    item("image", "Sandbox image", image_ok, image if image_ok else f"{image} not built yet",
         "The small Linux system each agent starts in.",
         dict(auto=True, label="Build the sandbox image (about 50 MB)", minutes=2, needs=["internet"]))

    net = sandbox_cfg["network"]
    code, out, _ = run(["docker", "network", "inspect", "--format", "{{.Internal}}", net], timeout=30) if docker_ok else (1, "", "")
    net_ok = code == 0 and out.strip() == "true"
    item("network", "Isolated network", net_ok,
         f"{net} (internal)" if net_ok else f"{net} exists but can reach the internet" if code == 0 else f"{net} not created yet",
         "An internal-only network: agents can't reach the internet or your local network.",
         dict(auto=True, label=f"Create the internal network {net}", minutes=0, needs=[]))

    needs_brew = any(i["fix"] and i["fix"].get("auto") and "homebrew" in i["fix"].get("needs", []) for i in items)
    if needs_brew and not has_brew:
        items.insert(0, dict(id="homebrew", name="Homebrew", ok=False, detail="Not installed",
                             why="Installs Colima, Docker and gVisor. Homebrew asks for your Mac password, so you run its installer.",
                             fix=dict(auto=False, label="Install Homebrew in Terminal, then check again", manual=BREW_INSTALL,
                                      link="https://brew.sh")))
    ready = all(i["ok"] is True for i in items)
    sure = [i["fix"] for i in items if i["fix"] and not i["fix"].get("if_missing")]
    return dict(ok=ready, items=items, minutes=sum(f.get("minutes", 0) for f in sure),
                downloads=any("internet" in f.get("needs", []) for f in sure))


def setup(sandbox_cfg: dict, step: Step, install: bool = False) -> bool:
    """Fix what diagnose found missing. Installing software (Homebrew packages, gVisor) needs install=True;
    starting the VM, building the image and creating the network don't."""
    b = brew()
    docker_ok, names, _ = runtimes()
    colima = colima_state()
    on_colima = docker_ok and engine_name().startswith("colima")
    runtime = sandbox_cfg.get("runtime", "runsc")
    want_colima = not docker_ok or (runtime not in names and not on_colima)

    if want_colima and colima == "missing":
        if not install:
            step("docker reachable", False, "Docker isn't installed. Setup can install Colima and Docker with Homebrew.")
            return False
        if platform.system() != "Darwin" or not b:
            step("install colima and docker", False, "Needs Homebrew: install it from https://brew.sh, then set up again"
                 if platform.system() == "Darwin" else "Install Docker and gVisor (runsc): https://gvisor.dev/docs/user_guide/install/")
            return False
        missing = [p for p, exe in (("colima", "colima"), ("docker", "docker"), ("docker-buildx", None)) if not exe or not shutil.which(exe)]
        code, out, err = run([b, "install", *missing], timeout=1200)
        step("install colima and docker", code == 0, tail(err or out) if code else ", ".join(missing))
        if code:
            return False
        colima = colima_state()
    if want_colima and colima == "stopped":
        fresh = not COLIMA_CONFIG.exists()
        code, out, err = run(COLIMA_NEW if fresh else ["colima", "start"], timeout=600)
        step("start the Linux VM", code == 0, tail(err or out) if code else "Colima is running")
        if code:
            return False
    elif want_colima and colima == "running" and not engine_name().startswith("colima"):
        run(["docker", "context", "use", "colima"], timeout=30)  # Colima runs, but docker points at another engine
    docker_ok, names, err = _wait_docker()
    step("docker reachable", docker_ok, "" if docker_ok else err)
    if not docker_ok:
        return False

    if runtime not in names:
        if not install:
            step("gVisor runtime available", False, "gVisor isn't installed. Setup can install it in the Colima VM.")
            return False
        code, out, err = run(["colima", "ssh", "--", "bash", "-lc", GVISOR_IN_VM], timeout=900)
        step("install gVisor in the VM", code == 0, tail(err or out) if code else "")
        if code:
            return False
        docker_ok, names, err = _wait_docker()
    if COLIMA_CONFIG.exists() and "runsc" not in COLIMA_CONFIG.read_text():
        text = COLIMA_CONFIG.read_text().replace("docker: {}", "docker:\n  runtimes:\n    runsc:\n      path: /usr/bin/runsc")
        COLIMA_CONFIG.write_text(text)
        step("keep gVisor across VM restarts", "runsc" in text, str(COLIMA_CONFIG))
    step("gVisor runtime available", runtime in names, ", ".join(names))
    if runtime not in names:
        return False

    from . import config as c
    image = sandbox_cfg["image"]
    if run(["docker", "image", "inspect", image], timeout=30)[0] != 0:
        code, out, err = run(["docker", "build", "-t", image, "-f", str(c.DOCKERFILE), str(c.BUILTIN)], timeout=900)
        if code:
            step("sandbox image", False, f"docker build failed: {tail(err or out)}")
            return False
    step("sandbox image", True, image)

    net = sandbox_cfg["network"]
    code, out, _ = run(["docker", "network", "inspect", "--format", "{{.Internal}}", net], timeout=30)
    if code == 0 and out.strip() != "true":
        code, out, err = run(["docker", "network", "rm", net], timeout=60)
        if code:
            step("internal network", False, f"{net} can reach the internet and couldn't be replaced: {tail(err or out)}")
            return False
        code = 1
    if code != 0:
        code, out, err = run(["docker", "network", "create", "--internal", "--subnet", "10.77.0.0/24", net], timeout=60)
        if code:
            step("internal network", False, f"docker network create failed: {tail(err or out)}")
            return False
    step("internal network", True, net)
    return True


def _wait_docker(seconds: float = 60) -> tuple[bool, list[str], str]:
    """Docker restarts after gVisor is installed and takes a moment to answer again."""
    deadline = time.time() + seconds
    while True:
        ok, names, err = runtimes()
        if ok or time.time() > deadline:
            return ok, names, err
        time.sleep(2)
