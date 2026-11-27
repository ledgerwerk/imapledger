from __future__ import annotations

import pytest
from pyjev.decisions import NoulDecision

from imapledger.evidence import build_message_evidence
from imapledger.message import MailMessage
from imapledger.routing_actions import RuleAction
from imapledger.routing_models import EvaluationState, RoutingModelError
from imapledger.rule_recipes import (
    SIGNAL_NAMES,
    SpamRecipe,
    get_recipe,
    get_runtime_recipe,
    list_recipes,
    materialize_recipe,
)


def _evidence(*, spam_flag: str = "", subject: str = "subject"):
    message = MailMessage(
        uid=1,
        subject=subject,
        sender="sender@example.org",
        recipients=(),
        date="",
        body="body",
        from_address="sender@example.org",
        x_spam_flag=spam_flag,
    )
    return build_message_evidence(message, trusted_provider_headers=("X-Spam-Flag",))


def _results(**overrides: float) -> dict[str, float]:
    results = {name: 0.10 for name in SIGNAL_NAMES}
    results.update(overrides)
    return results


def test_spam_recipe_is_discoverable_and_materializes_an_ordinary_rule() -> None:
    recipe = get_recipe("spam")
    assert recipe.title == "Spam / scam"
    assert recipe.category == "Safety"
    assert recipe.uses_model is True
    assert recipe.default_action is RuleAction.MOVE
    assert recipe.default_rule_id == "spam"
    assert recipe.revision == "spam-v2"
    assert {item.id for item in list_recipes()} == {"spam", "newsletter", "receipt", "delivery-failure"}
    assert [item.id for item in list_recipes(search="scam")] == ["spam"]

    rule = materialize_recipe("spam", rule_id="junk-filter", action=RuleAction.KEEP)
    assert rule.id == "junk-filter"
    assert rule.type.value == "recipe"
    assert rule.recipe == "spam"
    assert rule.action is RuleAction.KEEP
    assert rule.destination is None
    assert rule.options["phishing_match_at"] == 0.90
    with pytest.raises(RoutingModelError, match="requires a non-empty destination"):
        materialize_recipe("spam")


def test_static_recipes_materialize_normal_semantic_rules() -> None:
    receipt = materialize_recipe(
        "receipt",
        rule_id="orders",
        action=RuleAction.MOVE,
        destination="INBOX.Important",
    )
    assert receipt.type.value == "semantic"
    assert receipt.description == "Purchase receipts and order confirmations"
    assert receipt.recipe is None
    assert receipt.destination == "INBOX.Important"


def test_spam_recipe_options_are_defaulted_and_validated() -> None:
    recipe = get_runtime_recipe("spam")
    options = recipe.validate_options({"phishing_match_at": 0.91})
    assert options["phishing_match_at"] == 0.91
    assert options["legitimate_veto_at"] == 0.80
    with pytest.raises(ValueError, match="unknown Spam recipe option"):
        recipe.validate_options({"delete_safe_at": 0.88})
    with pytest.raises(ValueError, match="between 0 and 1"):
        recipe.validate_options({"action_safe_at": 1.1})
    with pytest.raises(ValueError, match="probability"):
        recipe.validate_options({"action_safe_at": True})


def test_spam_recipe_decision_bundle_contains_action_independent_signals() -> None:
    recipe = SpamRecipe()
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    questions = recipe.questions(rule=rule)

    assert set(questions) == set(SIGNAL_NAMES)
    assert all(isinstance(question, NoulDecision) for question in questions.values())
    assert "action_safe" in questions
    assert "delete_safe" not in questions


def test_strong_legitimate_evidence_vetoes_otherwise_positive_signals() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    decision = recipe.interpret(
        rule=rule,
        results=_results(phishing_or_scam=0.99, action_safe=0.99, legitimate_expected=0.80),
        evidence=_evidence(),
    )

    assert decision.state is EvaluationState.NO_MATCH
    assert decision.reasons == ("strong-legitimate-or-expected",)


def test_high_phishing_signal_matches_without_delete_classification() -> None:
    recipe = get_runtime_recipe("spam")
    decision = recipe.interpret(
        rule=materialize_recipe("spam", action=RuleAction.KEEP),
        results=_results(phishing_or_scam=0.90),
        evidence=_evidence(),
    )

    assert decision.state is EvaluationState.MATCH
    assert decision.reasons == ("strong-phishing-or-scam",)
    assert not hasattr(decision, "verdict")


def test_identity_deception_requires_action_safe_corroboration() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    insufficient = recipe.interpret(
        rule=rule,
        results=_results(identity_deception=0.99, action_safe=0.79),
        evidence=_evidence(),
    )
    supported = recipe.interpret(
        rule=rule,
        results=_results(identity_deception=0.90, action_safe=0.80),
        evidence=_evidence(),
    )

    assert insufficient.state is EvaluationState.NO_MATCH
    assert supported.state is EvaluationState.MATCH
    assert supported.reasons == ("identity-deception", "action-safe-corroboration")


def test_bulk_match_requires_action_safe_support() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    insufficient = recipe.interpret(
        rule=rule,
        results=_results(unsolicited_bulk=0.99, action_safe=0.87),
        evidence=_evidence(),
    )
    supported = recipe.interpret(
        rule=rule,
        results=_results(unsolicited_bulk=0.92, action_safe=0.88),
        evidence=_evidence(),
    )

    assert insufficient.state is EvaluationState.NO_MATCH
    assert supported.state is EvaluationState.MATCH
    assert supported.reasons == ("unsolicited-bulk", "action-safe-corroboration")


def test_trusted_provider_spam_requires_semantic_support() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    evidence = _evidence(spam_flag="YES")
    marker_only = recipe.interpret(rule=rule, results=_results(), evidence=evidence)
    supported = recipe.interpret(
        rule=rule,
        results=_results(action_safe=0.80, legitimate_expected=0.49),
        evidence=evidence,
    )

    assert evidence.provider.trusted_spam is True
    assert marker_only.state is EvaluationState.NO_MATCH
    assert marker_only.reasons == ("provider-marker-needs-corroboration",)
    assert supported.state is EvaluationState.MATCH
    assert supported.reasons == ("trusted-provider-junk", "semantic-support")


def test_provider_marker_and_insufficient_evidence_are_non_matches() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    provider = recipe.interpret(rule=rule, results=_results(), evidence=_evidence(spam_flag="YES"))
    insufficient = recipe.interpret(rule=rule, results=_results(), evidence=_evidence())

    assert provider.state is EvaluationState.NO_MATCH
    assert insufficient.state is EvaluationState.NO_MATCH
    assert insufficient.reasons == ("insufficient-evidence",)


def test_invalid_signal_probabilities_fail_closed() -> None:
    recipe = get_runtime_recipe("spam")
    rule = materialize_recipe("spam", action=RuleAction.KEEP)
    for value in (-0.01, 1.01, float("nan"), float("inf"), True):
        with pytest.raises(ValueError, match="finite probability"):
            recipe.interpret(rule=rule, results=_results(action_safe=value), evidence=_evidence())
