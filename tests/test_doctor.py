"""First-run setup without Docker: every tool is faked, so these run anywhere."""
import subprocess

import pytest

from harness import doctor, isolation

CFG = {"image": "dynolab-sandbox:abc", "network": "harness-net", "runtime": "runsc"}


class Machine:
    """A fake Mac: which tools exist, whether the VM runs, what Docker has."""

    def __init__(self, tools=("brew", "colima", "docker"), vm="running", runtimes=("runc", "runsc"),
                 image=True, network="true", context="colima", fail=()):
        self.tools, self.vm, self.rt, self.image, self.network, self.context = set(tools), vm, list(runtimes), image, network, context
        self.fail, self.calls = dict.fromkeys(fail, "boom") if not isinstance(fail, dict) else fail, []

    def which(self, name):
        return f"/opt/homebrew/bin/{name}" if name in self.tools else None

    def run(self, cmd, timeout=30, input=None):
        self.calls.append(cmd)
        key = " ".join(cmd[:3])
        for k, err in self.fail.items():
            if key.startswith(k) or " ".join(cmd).startswith(k):
                return 1, "", err
        exe = cmd[0].rsplit("/", 1)[-1]
        if exe not in self.tools:
            return 127, "", f"{exe}: not found"
        docker_up = self.vm == "running" and self.context.startswith("colima") or self.context == "desktop-linux"
        match cmd:
            case ["brew", "install", *pkgs] | [_, "install", *pkgs] if exe == "brew":
                self.tools |= {p for p in pkgs if p != "docker-buildx"}
                self.vm = "stopped"
                return 0, "", ""
            case ["colima", "status"]:
                return (0, "", "") if self.vm == "running" else (1, "", "not running")
            case ["colima", "start", *_]:
                self.vm, self.context = "running", "colima"
                return 0, "", ""
            case ["colima", "ssh", *_]:
                self.rt.append("runsc")
                return 0, "", ""
            case ["docker", "info", *_]:
                return (0, "{" + ",".join(f'"{r}":{{}}' for r in self.rt) + "}", "") if docker_up else (1, "", "Cannot connect to the Docker daemon")
            case ["docker", "context", "show"]:
                return 0, self.context + "\n", ""
            case ["docker", "context", "use", ctx]:
                self.context = ctx
                return 0, "", ""
            case ["docker", "image", "inspect", _]:
                return (0, "[]", "") if self.image and docker_up else (1, "", "No such image")
            case ["docker", "build", *_]:
                self.image = True
                return 0, "", ""
            case ["docker", "network", "inspect", *_]:
                return (0, self.network + "\n", "") if self.network else (1, "", "network not found")
            case ["docker", "network", "rm", _]:
                self.network = None
                return 0, "", ""
            case ["docker", "network", "create", *_]:
                self.network = "true"
                return 0, "", ""
        return 0, "", ""


@pytest.fixture
def mac(monkeypatch, tmp_path):
    def make(**kw):
        m = Machine(**kw)
        monkeypatch.setattr(doctor, "run", m.run)
        monkeypatch.setattr(doctor.shutil, "which", m.which)
        monkeypatch.setattr(doctor, "brew", lambda: m.which("brew"))
        monkeypatch.setattr(doctor.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(doctor.time, "sleep", lambda s: None)
        monkeypatch.setattr(doctor, "COLIMA_CONFIG", tmp_path / "colima.yaml")
        return m
    return make


def steps_of(cfg, install):
    out = []
    ok = doctor.setup(cfg, lambda n, p, d: out.append((n, p, d)), install=install)
    return ok, out


def test_ready_machine_needs_nothing(mac):
    mac()
    r = doctor.diagnose(CFG)
    assert r["ok"] and [i["id"] for i in r["items"]] == ["docker", "gvisor", "image", "network"]
    assert all(i["fix"] is None for i in r["items"])


def test_fresh_mac_lists_every_install_and_homebrew_first(mac):
    mac(tools=())
    r = doctor.diagnose(CFG)
    assert not r["ok"] and r["items"][0]["id"] == "homebrew" and r["items"][0]["fix"]["auto"] is False
    assert "install.sh" in r["items"][0]["fix"]["manual"]
    docker = next(i for i in r["items"] if i["id"] == "docker")
    assert docker["fix"]["auto"] and "homebrew" in docker["fix"]["needs"] and r["downloads"]


def test_stopped_colima_just_needs_starting(mac, tmp_path):
    m = mac(vm="stopped")
    (tmp_path / "colima.yaml").write_text("docker:\n  runtimes:\n    runsc:\n      path: /usr/bin/runsc\n")
    r = doctor.diagnose(CFG)
    docker = next(i for i in r["items"] if i["id"] == "docker")
    assert docker["fix"]["label"].startswith("Start the Colima") and docker["fix"]["needs"] == []
    assert "homebrew" not in [i["id"] for i in r["items"]]
    assert [i["ok"] for i in r["items"]] == [False, None, None, None] and r["minutes"] == 1 and not r["downloads"]
    ok, out = steps_of(CFG, install=False)
    assert ok and ("start the Linux VM", True, "Colima is running") in out
    assert ["colima", "start"] in m.calls  # an existing VM keeps its own size


def test_setup_from_nothing_installs_starts_and_builds(mac, tmp_path):
    m = mac(tools=("brew",), vm="stopped", runtimes=("runc",), image=False, network=None, context="default")
    (tmp_path / "colima.yaml").write_text("docker: {}\n")
    ok, out = steps_of(CFG, install=True)
    names = [n for n, p, _ in out if p]
    assert ok, out
    assert names == ["install colima and docker", "start the Linux VM", "docker reachable", "install gVisor in the VM",
                     "keep gVisor across VM restarts", "gVisor runtime available", "sandbox image", "internal network"]
    assert "runsc" in (tmp_path / "colima.yaml").read_text()
    assert any(c[:2] == ["docker", "build"] for c in m.calls)


def test_setup_asks_before_installing(mac):
    m = mac(tools=("brew",))
    ok, out = steps_of(CFG, install=False)
    assert not ok and out == [("docker reachable", False, "Docker isn't installed. Setup can install Colima and Docker with Homebrew.")]
    assert not any(c[:2] == ["/opt/homebrew/bin/brew", "install"] or c[:2] == ["brew", "install"] for c in m.calls)


def test_build_failure_shows_dockers_error(mac):
    mac(image=False, fail={"docker build": "failed to resolve source metadata for docker.io/library/python:3.12-slim"})
    ok, out = steps_of(CFG, install=False)
    assert not ok and out[-1][0] == "sandbox image" and "python:3.12-slim" in out[-1][2]


def test_network_that_reaches_the_internet_is_replaced(mac):
    m = mac(network="false")
    assert not next(i for i in doctor.diagnose(CFG)["items"] if i["id"] == "network")["ok"]
    ok, _ = steps_of(CFG, install=False)
    assert ok and ["docker", "network", "rm", "harness-net"] in m.calls and m.network == "true"


def test_run_never_raises():
    assert doctor.run(["definitely-not-a-tool-xyz"])[0] == 127
    assert doctor.run(["sleep", "5"], timeout=0.2)[0] == 124


def test_checks_report_a_container_that_wont_start(monkeypatch):
    monkeypatch.setattr(isolation.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, '{"runc":{}}', ""))
    monkeypatch.setattr(isolation, "run", lambda cmd, timeout=30: (0, "true\n", ""))

    class Box:
        def __init__(self, *a): pass
        def remove(self): pass
        def start(self, timeout=None):
            raise subprocess.CalledProcessError(125, "docker run", stderr=b"docker: Error response from daemon: unknown or invalid runtime name: runsc")
    monkeypatch.setattr(isolation, "DockerSandbox", Box)
    results = isolation.run_checks(CFG)
    assert [n for n, _, _ in results] == ["docker reachable", "sandbox image built", "network is --internal", "runtime is runsc"]
    name, passed, detail = results[-1]
    assert not passed and "invalid runtime name" in detail and "setup" in detail


def test_checks_report_a_container_that_hangs(monkeypatch):
    monkeypatch.setattr(isolation.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "{}", ""))
    monkeypatch.setattr(isolation, "run", lambda cmd, timeout=30: (0, "true\n", ""))

    class Box:
        def __init__(self, *a): pass
        def remove(self): pass
        def start(self, timeout=None):
            raise subprocess.TimeoutExpired("docker run", timeout)
    monkeypatch.setattr(isolation, "DockerSandbox", Box)
    name, passed, detail = isolation.run_checks(CFG)[-1]
    assert name == "runtime is runsc" and not passed and "didn't start within" in detail
