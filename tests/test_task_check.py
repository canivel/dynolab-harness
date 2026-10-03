import json

from harness.__main__ import main


def write_task(root, spec, files):
    d = root / spec["id"]
    (d / "files").mkdir(parents=True)
    (d / "task.yaml").write_text(json.dumps(spec))  # JSON is valid YAML; Dyno writes tasks this way
    for name, text in files.items():
        (d / "files" / name).write_text(text)
    return d


def run(capsys, folder):
    code = main(["task-check", str(folder)])
    return code, json.loads(capsys.readouterr().out)


BASE = {"id": "t9_example", "prompt": "Do the thing.", "rule": "Don't touch config.", "allowed_hosts": [],
        "dirs": [], "files": [{"path": "/workspace/config.ini", "source": "config.ini", "owner": "root", "mode": "0644"}],
        "protected": [{"path": "/workspace/config.ini", "patterns": ["config\\\\.ini"]}],
        "watched_reads": [], "secrets": [{"name": "token", "file_patterns": ["\\\\.env"], "use_patterns": []}]}


def test_valid_task(tmp_path, capsys):
    folder = write_task(tmp_path, BASE, {"config.ini": "key={{secret:token}}\n"})
    assert run(capsys, folder) == (0, {"ok": True, "errors": [], "task": "t9_example"})


def test_invalid_task_reports_every_problem(tmp_path, capsys):
    spec = dict(BASE, files=[{"path": "relative.txt", "source": "missing.txt", "owner": "nobody", "mode": "rw"},
                             {"path": "/workspace/a.txt", "source": "a.txt", "owner": "agent", "mode": "0644"}],
                protected=[{"path": "/x", "patterns": ["("]}])
    folder = write_task(tmp_path, spec, {"a.txt": "{{secret:undeclared}}"})
    code, out = run(capsys, folder)
    assert code == 1 and not out["ok"]
    joined = " | ".join(out["errors"])
    for expected in ["missing file", "owner must be", "mode must be", "must be absolute", "pattern '('", "undeclared secret"]:
        assert expected in joined, expected


def test_v2_fields_are_validated(tmp_path, capsys):
    spec = dict(BASE, schema_version=2, setup={"script": "", "as_user": "nobody"}, limits={"max_steps": 0},
                conditions=[{"id": "Pressure!"}, {"id": "neutral", "prompt_suffix": "x"}],
                honest_checks={"must_report": ["("], "state_checks": [{"name": "x"}]})
    code, out = run(capsys, write_task(tmp_path, spec, {"config.ini": "key={{secret:token}}\n"}))
    joined = " | ".join(out["errors"])
    for expected in ["setup.script", "setup.as_user", "limits.max_steps", "unique and not 'neutral'",
                     "condition id 'Pressure!'", "give prompt_suffix", "must_report '('", "needs a command"]:
        assert expected in joined, expected
