from __future__ import annotations

import pyjev
import pyjev.decisions as decision_module
import pytest
from pyjev.decisions import BundleDecision, NoulDecision
from pyjev.results import BundleResult, NoulResult

from imapledger.classifier import SIGNAL_NAMES
from imapledger.message import MailMessage
from imapledger.routing_evaluator import SemanticRoutingEvaluator
from imapledger.routing_models import EvaluationState, RoutingAction, RoutingRule, RuleSet, RuleType
from imapledger.rules import RuleMatch


class FakeJev:
    def __init__(self, values: dict[str, object], *, failure: Exception | None = None, extra_key: bool = False):
        self.values = values
        self.failure = failure
        self.extra_key = extra_key
        self.calls: list[tuple[BundleDecision, dict[str, object]]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None

    def evaluate(self, decision: BundleDecision, *, state: dict[str, object]) -> BundleResult:
        self.calls.append((decision, state))
        if self.failure is not None:
            raise self.failure
        keys = list(decision.questions)
        answers = {
            key: NoulResult(
                value=self.values.get(key, 0.05),
                model="child-model",
                usage={},
                raw={},
            )
            for key in keys
        }
        if self.extra_key:
            answers["unexpected"] = NoulResult(value=0.99, model="child-model", usage={}, raw={})
        return BundleResult(
            answers=answers,
            model="bundle-model",
            usage={},
            raw={},
            request_id="request-test",
        )


def _install_jev(monkeypatch: pytest.MonkeyPatch, fake: FakeJev) -> None:
    spam_bundle = BundleDecision(
        name="spam-evidence",
        questions={name: NoulDecision(name=name, question=f"Question for {name}") for name in SIGNAL_NAMES},
    )
    monkeypatch.setattr(decision_module, "load_decision", lambda name, *, config: spam_bundle)
    monkeypatch.setattr(pyjev, "Jev", lambda: fake)


def _message(uid: int = 77) -> MailMessage:
    return MailMessage(
        uid,
        "subject",
        "sender@example.org",
        (),
        "",
        "mail body",
        from_address="sender@example.org",
    )


def _semantic(rule_id: str, destination: str, threshold: float = 0.9) -> RoutingRule:
    return RoutingRule(
        id=rule_id,
        enabled=True,
        type=RuleType.SEMANTIC,
        destination=destination,
        description=f"Messages belonging to {rule_id}.",
        match_at=threshold,
    )


def _routing_key(rule_id: str) -> str:
    return f"route_{rule_id}"


def test_spam_and_semantic_questions_share_one_bundle_and_first_match_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values: dict[str, object] = {name: 0.1 for name in SIGNAL_NAMES}
    values["unsolicited_bulk"] = 0.99
    values["delete_safe"] = 0.95
    values[_routing_key("advertising")] = 0.99
    fake = FakeJev(values)
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (
            RoutingRule("spam", True, RuleType.SPAM, "INBOX.Trash"),
            _semantic("advertising", "INBOX.Advertising"),
        ),
        fallback_destination="INBOX.Processed",
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.winner_rule_id == "spam"
    assert plan.destination == "INBOX.Trash"
    assert plan.model == "bundle-model"
    assert plan.request_id == "request-test"
    assert len(fake.calls) == 1
    decision, state = fake.calls[0]
    assert set(decision.questions) == set(SIGNAL_NAMES) | {_routing_key("advertising")}
    assert "security_note" in state
    assert plan.rule_results[1].confidence == 0.99


def test_first_semantic_match_wins_even_when_later_rule_also_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({_routing_key("advertising"): 0.93, _routing_key("newsletter"): 0.97})
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (
            _semantic("advertising", "INBOX.Advertising", 0.9),
            _semantic("newsletter", "INBOX.Newsletter", 0.88),
        ),
        fallback_destination="INBOX.Processed",
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert [item.state for item in plan.rule_results] == [EvaluationState.MATCH, EvaluationState.MATCH]
    assert plan.winner_rule_id == "advertising"
    assert plan.destination == "INBOX.Advertising"


def test_no_match_keeps_in_place_and_selected_rule_never_uses_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (_semantic("invoice", "INBOX.Invoice"), _semantic("newsletter", "INBOX.Newsletter")),
        fallback_destination="INBOX.Processed",
    )

    with SemanticRoutingEvaluator() as evaluator:
        full_plan = evaluator.plan("INBOX.Archive", _message(), rules)
        selected_plan = evaluator.plan("INBOX.Archive", _message(), rules, rule_scope="invoice")

    assert full_plan.winner_rule_id is None
    assert full_plan.destination is None
    assert full_plan.action is RoutingAction.KEEP_IN_PLACE
    assert selected_plan.mode == "single-rule"
    assert selected_plan.rule_results[0].rule_id == "invoice"
    assert selected_plan.rule_results[0].state is EvaluationState.NO_MATCH
    assert selected_plan.destination is None
    assert set(fake.calls[1][0].questions) == {_routing_key("invoice")}


def test_deterministic_header_match_needs_no_model_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (
            RoutingRule(
                "github",
                True,
                RuleType.HEADER,
                "INBOX.Development",
                match=RuleMatch(from_domain="example.org"),
            ),
        ),
        fallback_destination="INBOX.Processed",
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert fake.calls == []
    assert plan.winner_rule_id == "github"
    assert plan.destination == "INBOX.Development"


def test_spam_review_remains_a_no_match_with_review_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({}))
    rules = RuleSet((RoutingRule("spam", True, RuleType.SPAM, "INBOX.Trash"),), "INBOX.Processed")

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.rule_results[0].state is EvaluationState.NO_MATCH
    assert plan.rule_results[0].detail is not None
    assert plan.rule_results[0].detail.startswith("review:")
    assert plan.destination is None
    assert plan.action is RoutingAction.KEEP_IN_PLACE


def test_winning_rule_to_current_folder_is_already_there(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({_routing_key("newsletter"): 0.95}))
    rules = RuleSet((_semantic("newsletter", "INBOX"),))

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX", _message(), rules)

    assert plan.winner_rule_id == "newsletter"
    assert plan.destination == "INBOX"
    assert plan.action is RoutingAction.ALREADY_THERE


def test_model_exception_produces_error_and_never_selects_a_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({}, failure=RuntimeError("offline")))
    rules = RuleSet((_semantic("invoice", "INBOX.Invoice"),), "INBOX.Processed")

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.rule_results[0].state is EvaluationState.ERROR
    assert plan.rule_results[0].detail == "offline"
    assert plan.winner_rule_id is None
    assert plan.destination is None


def test_unknown_result_key_produces_error_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({}, extra_key=True))
    rules = RuleSet((_semantic("invoice", "INBOX.Invoice"),), "INBOX.Processed")

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.rule_results[0].state is EvaluationState.ERROR
    assert "unknown or missing" in (plan.rule_results[0].detail or "")
    assert plan.destination is None


@pytest.mark.parametrize("probability", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_invalid_model_probabilities_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    probability: object,
) -> None:
    _install_jev(monkeypatch, FakeJev({_routing_key("invoice"): probability}))
    rules = RuleSet((_semantic("invoice", "INBOX.Invoice"),), "INBOX.Processed")

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.rule_results[0].state is EvaluationState.ERROR
    assert plan.destination is None


def test_evaluator_requires_open_context_and_valid_rule_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    evaluator = SemanticRoutingEvaluator()
    rules = RuleSet((_semantic("invoice", "INBOX.Invoice"),))
    with pytest.raises(RuntimeError, match="not open"):
        evaluator.plan("INBOX.Archive", _message(), rules)

    _install_jev(monkeypatch, FakeJev({}))
    with evaluator:
        with pytest.raises(ValueError, match="enabled rule not found"):
            evaluator.plan("INBOX.Archive", _message(), rules, rule_scope="unknown")


def test_deterministic_matcher_on_semantic_rule_skips_model_evaluation(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rule = RoutingRule(
        id="invoice",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="INBOX.Trash",
        description="Invoice notices",
        match_any=(RuleMatch(from_address="sender@example.org"),),
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((rule,)))

    assert fake.calls == []
    assert plan.rule_results[0].state is EvaluationState.MATCH
    assert plan.rule_results[0].detail == "deterministic matcher match"
    assert plan.winner_rule_id == "invoice"
