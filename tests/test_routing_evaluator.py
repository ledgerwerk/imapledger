from __future__ import annotations

import pytest
from pyjev.decisions import BundleDecision
from pyjev.results import BundleResult, NoulResult

from imapledger.message import MailMessage
from imapledger.routing_actions import RuleAction
from imapledger.routing_evaluator import SemanticRoutingEvaluator
from imapledger.routing_models import (
    EvaluationState,
    RoutingAction,
    RoutingRule,
    RuleEvidenceSettings,
    RuleSet,
    RuleType,
)
from imapledger.rule_recipes.spam import SIGNAL_NAMES
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
        answers = {
            key: NoulResult(value=self.values.get(key, 0.05), model="child-model", usage={}, raw={})
            for key in decision.questions
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
    import imapledger.routing_evaluator as evaluator_module

    monkeypatch.setattr(evaluator_module, "Jev", lambda: fake)


def _message(uid: int = 77, *, x_spam_flag: str = "") -> MailMessage:
    return MailMessage(
        uid,
        "subject",
        "sender@example.org",
        (),
        "",
        "mail body",
        from_address="sender@example.org",
        x_spam_flag=x_spam_flag,
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


def _spam_rule(rule_id: str = "spam", destination: str = "INBOX.Trash", **options) -> RoutingRule:
    return RoutingRule(
        id=rule_id,
        enabled=True,
        type=RuleType.RECIPE,
        recipe="spam",
        action=RuleAction.MOVE,
        destination=destination,
        options=options,
    )


def _semantic_key(rule_id: str) -> str:
    return f"semantic__{rule_id}"


def _recipe_key(rule_id: str, name: str) -> str:
    return f"recipe__{rule_id}__{name}"


def test_recipe_and_semantic_questions_share_one_bundle_and_keep_order(monkeypatch: pytest.MonkeyPatch) -> None:
    values: dict[str, object] = {name: 0.1 for name in SIGNAL_NAMES}
    values[_recipe_key("spam", "unsolicited_bulk")] = 0.99
    values[_recipe_key("spam", "action_safe")] = 0.95
    values[_semantic_key("advertising")] = 0.99
    fake = FakeJev(values)
    _install_jev(monkeypatch, fake)
    rules = RuleSet((_spam_rule(), _semantic("advertising", "INBOX.Advertising")))

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert plan.winner_rule_id == "spam"
    assert plan.destination == "INBOX.Trash"
    assert plan.model == "bundle-model"
    assert plan.request_id == "request-test"
    assert len(fake.calls) == 1
    decision, state = fake.calls[0]
    assert set(decision.questions) == {
        *(_recipe_key("spam", name) for name in SIGNAL_NAMES),
        _semantic_key("advertising"),
    }
    assert "source_folder" in state["mailbox_context"]
    assert plan.rule_results[1].confidence == 0.99


def test_first_semantic_match_wins_even_when_later_rule_also_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({_semantic_key("advertising"): 0.93, _semantic_key("newsletter"): 0.97})
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (
            _semantic("advertising", "INBOX.Advertising", 0.9),
            _semantic("newsletter", "INBOX.Newsletter", 0.88),
        )
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), rules)

    assert [item.state for item in plan.rule_results] == [EvaluationState.MATCH, EvaluationState.MATCH]
    assert plan.winner_rule_id == "advertising"
    assert plan.destination == "INBOX.Advertising"


def test_uncertain_spam_is_no_match_and_later_rules_continue(monkeypatch: pytest.MonkeyPatch) -> None:
    values: dict[str, object] = {_recipe_key("spam", name): 0.1 for name in SIGNAL_NAMES}
    values[_recipe_key("spam", "action_safe")] = 0.1
    values[_semantic_key("newsletter")] = 0.97
    fake = FakeJev(values)
    _install_jev(monkeypatch, fake)
    rules = RuleSet(
        (_spam_rule(), _semantic("newsletter", "INBOX.Newsletter")),
        evidence=RuleEvidenceSettings(trusted_provider_headers=("X-Spam-Flag",)),
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(x_spam_flag="YES"), rules)

    assert plan.rule_results[0].state is EvaluationState.NO_MATCH
    assert plan.rule_results[0].detail == "provider-marker-needs-corroboration"
    assert plan.winner_rule_id == "newsletter"
    assert plan.destination == "INBOX.Newsletter"


def test_no_match_stays_in_place_and_selected_rule_does_not_use_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rules = RuleSet((_semantic("invoice", "INBOX.Invoice"), _semantic("newsletter", "INBOX.Newsletter")))

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
    assert set(fake.calls[1][0].questions) == {_semantic_key("invoice")}


def test_deterministic_header_rule_needs_no_model_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rule = RoutingRule(
        "github",
        True,
        RuleType.HEADER,
        "INBOX.Development",
        match=RuleMatch(from_domain="example.org"),
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((rule,)))

    assert fake.calls == []
    assert plan.winner_rule_id == "github"
    assert plan.destination == "INBOX.Development"


def test_deterministic_recipe_match_skips_model_questions(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeJev({})
    _install_jev(monkeypatch, fake)
    rule = RoutingRule(
        "spam-fast-path",
        True,
        RuleType.RECIPE,
        destination="INBOX.Trash",
        action=RuleAction.MOVE,
        recipe="spam",
        match_any=(RuleMatch(from_address="sender@example.org"),),
    )

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((rule,)))

    assert fake.calls == []
    assert plan.winner_rule_id == "spam-fast-path"
    assert plan.rule_results[0].detail == "deterministic matcher match"


def test_recipe_model_exception_produces_error_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({}, failure=RuntimeError("offline")))

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((_spam_rule(),)))

    assert plan.rule_results[0].state is EvaluationState.ERROR
    assert plan.rule_results[0].detail == "offline"
    assert plan.winner_rule_id is None
    assert plan.destination is None


def test_unknown_result_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jev(monkeypatch, FakeJev({}, extra_key=True))

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((_semantic("invoice", "INBOX.Invoice"),)))

    assert plan.rule_results[0].state is EvaluationState.ERROR
    assert "unknown or missing" in (plan.rule_results[0].detail or "")
    assert plan.destination is None


@pytest.mark.parametrize("probability", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_invalid_model_probabilities_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    probability: object,
) -> None:
    _install_jev(monkeypatch, FakeJev({_semantic_key("invoice"): probability}))

    with SemanticRoutingEvaluator() as evaluator:
        plan = evaluator.plan("INBOX.Archive", _message(), RuleSet((_semantic("invoice", "INBOX.Invoice"),)))

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
