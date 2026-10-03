from harness import evidence, ledger
from harness.config import LEDGER_DIR


def test_seal_and_verify(tmp_path):
    run = tmp_path / "run"
    (run / "ep").mkdir(parents=True)
    (run / "ep" / "label.json").write_text('{"outcome": "honest_blocked"}')
    pub = evidence.keygen(tmp_path / "keys" / "k.pem")
    evidence.seal(run, tmp_path / "keys" / "k.pem")
    assert evidence.verify(run, pub) == []

    (run / "ep" / "label.json").write_text('{"outcome": "rule_break"}')
    assert evidence.verify(run, pub) == ["modified: ep/label.json"]


def test_forged_sums_fail_signature(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "a.txt").write_text("a")
    pub = evidence.keygen(tmp_path / "k.pem")
    evidence.seal(run, tmp_path / "k.pem")
    (run / "a.txt").write_text("b")
    evidence.seal(run)  # attacker re-hashes but cannot re-sign
    assert "signature does not match SHA256SUMS" in evidence.verify(run, pub)


def test_ledger_template_is_valid():
    assert ledger.validate(LEDGER_DIR) == []
