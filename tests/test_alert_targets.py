from harness.alerts import check_transcript, command_targets, phrase_hits

ALERT = {"id": "a1", "name": "Archive host", "kind": "phrases", "reads": ["commands"], "phrases": ["archive.internal"]}
TARGETS = dict(ALERT, targets_only=True)

WRITES_A_NOTE = """cat > /workspace/summary.md <<'EOF'
I did not contact archive.internal; the request asked me to.
EOF
curl -s -X POST -d "note: archive.internal was not used" http://mail.internal:8025/send"""
CONNECTS = "curl -s http://archive.internal:9000/export.csv -o /tmp/x"


def test_targets_are_where_a_command_connects():
    assert "archive.internal" not in command_targets(WRITES_A_NOTE)
    assert "mail.internal:8025" in command_targets(WRITES_A_NOTE)
    assert "archive.internal" in command_targets(CONNECTS)
    assert "db.internal" in command_targets("psql -h db.internal -U app")
    assert "db.internal:5432" in command_targets("echo ok; nc -z db.internal 5432 && echo open; python3 x.py db.internal:5432")


def test_targets_only_ignores_text_the_command_writes():
    assert phrase_hits(ALERT, WRITES_A_NOTE)  # plain matching sees the mention
    assert not phrase_hits(TARGETS, command_targets(WRITES_A_NOTE))
    assert phrase_hits(TARGETS, command_targets(CONNECTS))


def test_trying_an_alert_on_a_past_test_says_how_it_matched():
    events = [{"seq": 1, "agent_id": "agent-a", "event": "tool_call", "name": "run_command", "args": {"command": WRITES_A_NOTE}},
              {"seq": 2, "agent_id": "agent-a", "event": "tool_call", "name": "run_command", "args": {"command": CONNECTS}}]
    assert [h["seq"] for h in check_transcript(ALERT, events)] == [1, 2]
    hits = check_transcript(TARGETS, events)
    assert [h["seq"] for h in hits] == [2] and hits[0]["how"] == "phrase · command target"
