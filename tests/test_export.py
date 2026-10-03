import json

from harness import evidence
from harness.config import load_config
from harness.export import export_run
from harness.labeler import label_episode
from harness.model import ScriptedModel
from harness.scaffold import run_episode
from harness.tasks import load_task

from fake_sandbox import FakeSandbox


def make_run(tmp_path, monkeypatch):
    monkeypatch.setattr("harness.scaffold.image_digest", lambda image: "sha256:test")
    run = tmp_path / "run"
    for behaviour in ("honest", "rule_break"):
        ep = run / f"t2-{behaviour}"
        run_episode(model=ScriptedModel.for_task("t2_unreachable_data", behaviour), task=load_task("t2_unreachable_data"),
                    cfg=load_config(), episode_dir=ep, episode_id=ep.name, seed=1, sandbox=FakeSandbox())
        label_episode(ep)
        # give the transcript some reasoning text, as a real model would
        lines = [json.loads(l) for l in (ep / "transcript.jsonl").read_text().splitlines()]
        for e in lines:
            if e["event"] == "model":
                e["reasoning"] = "I should not use the production token."
        (ep / "transcript.jsonl").write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    return run


def test_export_redacts_honeypots_and_verifies(tmp_path, monkeypatch):
    run = make_run(tmp_path, monkeypatch)
    secrets = [v for p in run.glob("*/secrets.json") for v in json.loads(p.read_text()).values()]
    summary = export_run(run, tmp_path / "bundle", meta={"title": "T2 controls"})
    bundle = tmp_path / "bundle"
    everything = "".join(p.read_text(errors="replace") for p in bundle.rglob("*") if p.is_file())
    assert secrets and not any(s in everything for s in secrets)
    assert "<honeypot:prod_token>" in everything
    assert not list(bundle.rglob("secrets.json"))
    assert summary["schema"] == "dynolab.agent-evaluation/1" and summary["title"] == "T2 controls"
    assert summary["reasoning_included"] and summary["redactions"]["honeypot_values_replaced"] > 0
    assert {e["outcome"] for e in summary["episodes"]} == {"honest_blocked", "rule_break"}
    assert summary["tasks"][0]["id"] == "t2_unreachable_data" and len(summary["tasks"][0]["hash"]) == 64
    assert (bundle / "tasks" / "t2_unreachable_data" / "task.yaml").exists()
    assert evidence.verify(bundle) == []
    assert "I should not use the production token." in everything


def test_export_without_reasoning(tmp_path, monkeypatch):
    run = make_run(tmp_path, monkeypatch)
    summary = export_run(run, tmp_path / "bundle", reasoning=False)
    text = "".join(p.read_text() for p in (tmp_path / "bundle").rglob("transcript.jsonl"))
    assert "I should not use the production token." not in text
    assert not summary["reasoning_included"] and summary["redactions"]["reasoning_fields_removed"] > 0
    assert json.loads((tmp_path / "bundle" / "summary.json").read_text())["reasoning_included"] is False
