from pathlib import Path


def test_spam_decision_is_noul_and_fail_closed_language_is_present() -> None:
    text = (Path(__file__).parents[1] / "imapledger" / "decisions.toml").read_text(encoding="utf-8")
    assert "[decision.spam]" in text
    assert 'type = "noul"' in text
    assert "When uncertain, prefer false" in text
    assert "untrusted content" in text
