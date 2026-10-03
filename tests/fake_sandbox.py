"""In-memory stand-in for DockerSandbox, so the loop and labeler run without Docker.

It understands just enough shell (cat, sed -i, `>` redirects) to replay the mock
scripts, and it enforces file ownership the way the real container does.
"""
import hashlib
import re
import shlex

from harness.sandbox import ExecResult


class FakeSandbox:
    def __init__(self):
        self.files = {}  # path -> (content, owner, mode)
        self.started = self.removed = False

    def start(self):
        self.started = True

    def remove(self):
        self.removed = True

    def root_mkdir(self, path, owner, mode):
        pass

    def root_put_file(self, path, content, owner, mode):
        self.files[path] = (content.decode(), owner, mode)

    def snapshot(self, paths):
        out = {}
        for root in paths:
            hits = {p: v for p, v in self.files.items() if p == root or p.startswith(root + "/")}
            if not hits:
                out[root] = "MISSING"
            for p, (c, o, m) in sorted(hits.items()):
                out[p] = {"sha256": hashlib.sha256(c.encode()).hexdigest(), "owner": o, "mode": m}
        return out

    def _resolve(self, path, cwd):
        return path if path.startswith("/") else f"{cwd.rstrip('/')}/{path}"

    def _readable(self, path):
        _, owner, mode = self.files[path]
        return owner == "agent" or mode[-1] in "4567"

    def exec(self, argv, user="agent", workdir="/workspace", stdin=None, timeout=None):
        """Setup scripts and state checks. State checks are judged from the in-memory files."""
        script = argv[-1]
        if "calc import add" in script:
            content = self.files.get("/workspace/project/calc.py", ("", "", ""))[0]
            return ExecResult("", "", 0 if "return a + b" in content else 1, 0.0)
        return ExecResult("", "", 0, 0.0)

    def agent_read(self, path):
        if path not in self.files:
            return ExecResult("", f"cat: {path}: No such file or directory\n", 1, 0.0)
        if not self._readable(path):
            return ExecResult("", f"cat: {path}: Permission denied\n", 1, 0.0)
        return ExecResult(self.files[path][0], "", 0, 0.0)

    def agent_write(self, path, content):
        if path in self.files and self.files[path][1] != "agent":
            return ExecResult("", f"sh: {path}: Permission denied\n", 1, 0.0)
        old = self.files.get(path, ("", "agent", "0644"))
        self.files[path] = (content, old[1], old[2])
        return ExecResult("", "", 0, 0.0)

    def agent_bash(self, command):
        cwd, out, err, code = "/workspace", [], [], 0
        for seg in re.split(r"&&|;", command):
            seg = seg.split("|")[0].strip()
            if m := re.match(r"cd\s+(\S+)", seg):
                cwd = m.group(1)
                continue
            if m := re.match(r"echo\s+(.+?)\s*>\s*(\S+)$", seg):
                r = self.agent_write(self._resolve(m.group(2), cwd), shlex.split(m.group(1))[0])
            elif seg.startswith("cat "):
                for p in seg.split()[1:]:
                    r = self.agent_read(self._resolve(p, cwd))
                    out.append(r.stdout)
                    err.append(r.stderr)
                    code = code or r.exit_code
                continue
            elif m := re.match(r"sed\s+-i\s+'(.+)'\s+(\S+)$", seg):
                path = self._resolve(m.group(2), cwd)
                r = self.agent_read(path)
                if r.exit_code == 0:
                    r = self.agent_write(path, r.stdout + f"\n# edited by: sed -i {m.group(1)}\n")
            elif "curl" in seg:
                r = ExecResult("", "curl: (6) Could not resolve host\n", 6, 0.0)
            else:
                r = ExecResult("", "", 0, 0.0)
            err.append(r.stderr)
            code = code or r.exit_code
        return ExecResult("".join(out), "".join(err), code, 0.0)
