from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pyjev
import pyjev.decisions as decision_module
import pytest
from pyjev.decisions import BundleDecision, ChoiceDecision, NoulDecision
from pyjev.results import BundleResult, NoulResult

from imapledger.classifier import SIGNAL_NAMES, PyJevSpamClassifier
from imapledger.message import MailMessage


def test_spam_decision_is_a_bundle_with_required_noul_children() -> None:
    config = Path(__file__).parents[1] / "imapledger" / "decisions.toml"
    decision = decision_module.load_decision("spam-evidence", config=config)

    assert isinstance(decision, BundleDecision)
    assert set(SIGNAL_NAMES).issubset(decision.questions)
    assert all(isinstance(decision.questions[name], NoulDecision) for name in SIGNAL_NAMES)


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


def _decision():
    return BundleDecision(
        name="spam-evidence",
        questions={name: NoulDecision(name=name, question=f"Question for {name}") for name in SIGNAL_NAMES},
    )


def _result(values=None):
    values = values or {}
    answers = {
        name: NoulResult(value=values.get(name, 0.8), model="child-model", usage={}, raw={}) for name in SIGNAL_NAMES
    }
    return BundleResult(answers=answers, model="bundle-model", usage={}, raw={}, request_id="request-test")


def _message(uid=1):
    return MailMessage(uid, "subject", "sender@example.org", (), "", "body")


def _install_classifier(monkeypatch, decision, result):
    loaded = []
    jev = FakeJev(result)

    def load_decision(name, *, config):
        loaded.append((name, config))
        return decision

    monkeypatch.setattr(decision_module, "load_decision", load_decision)
    monkeypatch.setattr(pyjev, "Jev", lambda: jev)
    return loaded, jev


def test_bundle_is_loaded_once_and_evaluated_once_per_message(monkeypatch, tmp_path: Path) -> None:
    decision = _decision()
    loaded, jev = _install_classifier(monkeypatch, decision, _result())
    classifier = PyJevSpamClassifier(config=tmp_path / "decisions.toml")

    with classifier:
        assessments = [classifier.assess(_message(uid)) for uid in (1, 2)]

    assert loaded == [("spam-evidence", tmp_path / "decisions.toml")]
    assert jev.entered and jev.exited
    assert [item[0] for item in jev.evaluations] == [decision, decision]
    assert all("uid" not in item[1] for item in jev.evaluations)
    assert assessments[0].signals.unsolicited_bulk == 0.8
    assert assessments[0].signals.delete_safe == 0.8
    assert assessments[0].model == "bundle-model"
    assert assessments[0].request_id == "request-test"


def test_classifier_rejects_non_bundle_decision(monkeypatch):
    choice = ChoiceDecision(name="spam-evidence", question="Spam?", options={"yes": None, "no": None})
    loaded, _ = _install_classifier(monkeypatch, choice, _result())

    with pytest.raises(TypeError, match="must be a BundleDecision"):
        PyJevSpamClassifier().__enter__()

    assert len(loaded) == 1


def test_classifier_rejects_bundle_missing_required_question(monkeypatch):
    decision = BundleDecision(name="spam-evidence", questions={})
    _install_classifier(monkeypatch, decision, _result())

    with pytest.raises(ValueError, match="missing a required question"):
        PyJevSpamClassifier().__enter__()


def test_classifier_rejects_non_noul_bundle_child(monkeypatch):
    questions = {name: NoulDecision(name=name, question="Question") for name in SIGNAL_NAMES}
    questions["identity_deception"] = ChoiceDecision(
        name="identity_deception", question="Identity?", options={"yes": None, "no": None}
    )
    _install_classifier(monkeypatch, BundleDecision(name="spam-evidence", questions=questions), _result())

    with pytest.raises(TypeError, match="must be Noul decisions"):
        PyJevSpamClassifier().__enter__()


def test_classifier_rejects_non_bundle_result(monkeypatch):
    _install_classifier(monkeypatch, _decision(), SimpleNamespace(answers={}))
    classifier = PyJevSpamClassifier()

    with classifier, pytest.raises(TypeError, match="non-Bundle result"):
        classifier.assess(_message())


def test_classifier_rejects_missing_bundle_answer(monkeypatch):
    result = _result()
    result.answers.pop("identity_deception")
    _install_classifier(monkeypatch, _decision(), result)
    classifier = PyJevSpamClassifier()

    with classifier, pytest.raises(TypeError, match="identity_deception returned non-Noul"):
        classifier.assess(_message())


def test_classifier_rejects_wrong_bundle_answer_type(monkeypatch):
    result = _result()
    result.answers["identity_deception"] = SimpleNamespace(value=0.8)
    _install_classifier(monkeypatch, _decision(), result)
    classifier = PyJevSpamClassifier()

    with classifier, pytest.raises(TypeError, match="identity_deception returned non-Noul"):
        classifier.assess(_message())


@pytest.mark.parametrize("value", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_classifier_rejects_invalid_signal_probability(monkeypatch, value):
    result = _result({"phishing_or_scam": value})
    _install_classifier(monkeypatch, _decision(), result)
    classifier = PyJevSpamClassifier()

    with classifier, pytest.raises(ValueError, match="probability"):
        classifier.assess(_message())
