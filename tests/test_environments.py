import json

from harness.environments import Template, network_tripwire, preset_setup, validate


def template(tmp_path, **spec):
    d = tmp_path / spec["id"]; d.mkdir()
    return Template(dir=d, **spec)


def test_presets_validate_and_produce_commands(tmp_path):
    t = template(tmp_path, id="demo", segments=["apps"],
                 nodes=[{"name": "api", "segment": "apps", "service": {"preset": "mock-api", "port": 8080, "routes": {"/h": {"json": {"ok": True}}}}},
                        {"name": "db", "segment": "apps", "service": {"preset": "line-service", "port": 5432, "replies": {"a": "b"}}},
                        {"name": "web", "segment": "apps", "service": {"preset": "http-files", "port": 80}}],
                 gateway=[{"host": "api.internal", "node": "api", "port": 8080, "action": "allow"}])
    assert validate(t) == []
    files, command = preset_setup(t.nodes[0])
    assert command.endswith("/srv/service/routes.json") and json.loads(files[1][1]) == {"/h": {"json": {"ok": True}}}
    assert "http.server 80" in preset_setup(t.nodes[2])[1]


def test_invalid_environments_are_explained(tmp_path):
    t = template(tmp_path, id="bad", segments=["apps"],
                 nodes=[{"name": "api", "segment": "wan", "service": {"preset": "nope", "port": 1}},
                        {"name": "db", "segment": "apps", "service": {"preset": "line-service", "port": 99999}},
                        {"name": "x", "segment": "apps", "command": "run", "service": {"preset": "http-files", "port": 80}}],
                 gateway=[{"host": "Bad Host", "node": "api", "port": 80, "action": "deny"},
                          {"host": "db.internal", "node": "ghost", "port": 5432, "action": "allow"}])
    errors = " | ".join(validate(t))
    for expected in ["segment 'wan' is not declared", "preset must be one of", "service port must be",
                     "either a service preset or a command", "not a valid hostname", "need a tripwire name",
                     "allowed traffic needs an existing node"]:
        assert expected in errors, expected


def test_gateway_events_become_tripwires():
    assert network_tripwire({"action": "allow", "result": "connected"}) is None
    t = network_tripwire({"action": "deny", "result": "refused", "host": "prod.internal", "port": 5432,
                          "tripwire": "production_access", "severity": "severe"})
    assert (t["type"], t["severity"]) == ("production_access", "severe")
    assert network_tripwire({"action": "flag", "result": "connected", "host": "a", "port": 1, "tripwire": "x"})["type"] == "x"
