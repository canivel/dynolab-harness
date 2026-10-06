"""The ready-made services really work: each is started on a local port and used like an agent would."""
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from harness.environments import SERVICES, Template, preset_setup, validate


def _start(tmp_path, preset, **spec):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    files, command = preset_setup({"service": {"preset": preset, "port": port, **spec}})
    config = dict(files)["/srv/service/config.json"]
    (tmp_path / "config.json").write_bytes(config)
    script = command.split()[1].rsplit("/", 1)[1]
    proc = subprocess.Popen([sys.executable, str(SERVICES / script), str(port), str(tmp_path / "config.json")],
                            cwd=tmp_path)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            break
        except OSError:
            time.sleep(0.05)
    return proc, f"http://127.0.0.1:{port}"


def _call(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture
def service(tmp_path):
    procs = []
    def start(preset, **spec):
        proc, url = _start(tmp_path, preset, **spec)
        procs.append(proc)
        return url
    yield start
    for p in procs:
        p.kill()


def test_object_store(service):
    url = service("object-store", objects={"exports/q3.csv": "region,sales\nNorth,1\n"}, writable=False)
    assert json.loads(_call(url + "/")[1])["keys"] == [{"key": "exports/q3.csv", "size": 21}]
    assert _call(url + "/exports/q3.csv")[1].startswith(b"region")
    assert _call(url + "/exports/q3.csv", "PUT", b"x")[0] == 403
    rw = service("object-store", objects={}, writable=True)
    assert _call(rw + "/a/b.txt", "PUT", b"hello")[0] == 201
    assert _call(rw + "/a/b.txt")[1] == b"hello"
    assert _call(rw + "/a/b.txt", "DELETE")[0] == 200 and _call(rw + "/a/b.txt")[0] == 404


def test_sql_db(service):
    url = service("sql-db", tables={"customers": "region,active\nNorth,1284\nSouth,1102\n"}, password="pw")
    assert _call(url + "/health")[0] == 200
    assert _call(url + "/query?sql=SELECT+1")[0] == 401
    status, body = _call(url + "/query", "POST", json.dumps({"sql": "SELECT region, active FROM customers ORDER BY region"}).encode(),
                         {"Authorization": "Bearer pw"})
    assert status == 200 and json.loads(body)["rows"] == [["North", "1284"], ["South", "1102"]]
    assert json.loads(_call(url + "/tables?password=pw")[1]) == {"customers": ["region", "active"]}
    assert _call(url + "/query?password=pw&sql=SELEC", )[0] == 400


def test_vault(service):
    url = service("vault", token="s.abc", secrets={"prod-db": "hunter2"})
    assert _call(url + "/v1/sys/health")[0] == 200
    assert _call(url + "/v1/secret/prod-db")[0] == 403
    assert json.loads(_call(url + "/v1/secret/prod-db", headers={"X-Vault-Token": "s.abc"})[1]) == {"data": {"value": "hunter2"}}


def test_mail_outbox(service, tmp_path):
    url = service("mail-outbox", domain="corp.example")
    status, body = _call(url + "/send", "POST", json.dumps({"to": "cfo@corp.example", "subject": "Q3", "body": "numbers"}).encode())
    assert status == 202 and json.loads(body) == {"queued": 1}
    assert json.loads((tmp_path / "outbox.jsonl").read_text())["to"] == "cfo@corp.example"
    assert _call(url + "/send", "POST", b"not json")[0] == 400


def test_preset_validation(tmp_path):
    t = Template(id="x", dir=tmp_path, segments=["data"], nodes=[
        {"name": "db", "segment": "data", "service": {"preset": "sql-db", "port": 8080, "tables": {"bad name": "a\n1"}}},
        {"name": "vault", "segment": "data", "service": {"preset": "vault", "port": 8200, "secrets": {}}}],
        gateway=[{"host": "db.internal", "node": "db", "port": 8080, "action": "allow"},
                 {"host": "vault.internal", "node": "vault", "port": 8200, "action": "allow"}])
    errors = validate(t)
    assert "node db: table names: letters, digits and _" in errors
    assert "node vault: a vault needs a token and secrets" in errors
