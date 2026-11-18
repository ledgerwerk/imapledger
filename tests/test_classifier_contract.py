from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pyjev
import pyjev.decisions as decision_module
import pytest
from pyjev import NoulResult
from pyjev.decisions import ChoiceDecision, NoulDecision

from imapledger.classifier import PyJevSpamClassifier
from imapledger.message import MailMessage


def test_spam_decision_is_noul_and_fail_closed_language_is_present() -> None:
    text = (Path(__file__).parents[1] / "imapledger" / "decisions.toml").read_text(encoding="utf-8")
    assert "[decision.spam]" in text
    assert 'type = "noul"' in text
    assert "When uncertain, prefer false" in text
    assert "untrusted content" in text


class FakeJev:
    def __init__(self, result):
        self.result = result
        self.evaluations = []
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.exited = True

    def evaluate(self, decision, *, state):
        self.evaluations.append((decision, state))
        return self.result


def _install_classifier(monkeypatch, decision, result):
    loaded = []
    jev = FakeJev(result)

    def load_decision(name, *, config):
        loaded.append((name, config))
        return decision

    monkeypatch.setattr(decision_module, "load_decision", load_decision)
    monkeypatch.setattr(pyjev, "Jev", lambda: jev)
    return loaded, jev


def _result(value=0.8, *, model="model-test", request_id="request-test"):
    return NoulResult(value=value, model=model, usage={}, raw={}, request_id=request_id)


def _message(uid=1):
    return MailMessage(uid, "subject", "sender@example.org", (), "", "body")


def test_spam_decision_is_loaded_once_and_metadata_is_preserved(monkeypatch, tmp_path: Path):
    decision = NoulDecision(name="spam", question="Is this spam?")
    result = _result()
    loaded, jev = _install_classifier(monkeypatch, decision, result)
    classifier = PyJevSpamClassifier(config=tmp_path / "decisions.toml")

    with classifier:
        assessments = [classifier.assess(_message(uid)) for uid in (1, 2)]

    assert loaded == [("spam", tmp_path / "decisions.toml")]
    assert jev.entered and jev.exited
    assert [item[0] for item in jev.evaluations] == [decision, decision]
    assert [assessment.probability for assessment in assessments] == [0.8, 0.8]
    assert assessments[0].model == "model-test"
    assert assessments[0].request_id == "request-test"


def test_classifier_rejects_non_noul_decision(monkeypatch):
    choice = ChoiceDecision(name="spam", question="Is this spam?", options={"yes": None, "no": None})
    loaded, _ = _install_classifier(monkeypatch, choice, _result())

    with pytest.raises(TypeError, match="decision must be Noul"):
        PyJevSpamClassifier().__enter__()

    assert len(loaded) == 1


def test_classifier_rejects_non_noul_result(monkeypatch):
    decision = NoulDecision(name="spam", question="Is this spam?")
    _install_classifier(monkeypatch, decision, SimpleNamespace(value=0.8))
    classifier = PyJevSpamClassifier()

    with classifier:
        with pytest.raises(TypeError, match="non-Noul result"):
            classifier.assess(_message())


@pytest.mark.parametrize("value", [-0.01, 1.01, float("nan")])
def test_classifier_rejects_probability_outside_zero_one(monkeypatch, value):
    decision = NoulDecision(name="spam", question="Is this spam?")
    _install_classifier(monkeypatch, decision, _result(value))
    classifier = PyJevSpamClassifier()

    with classifier:
        with pytest.raises(ValueError, match="outside \\[0, 1\\]"):
            classifier.assess(_message())
