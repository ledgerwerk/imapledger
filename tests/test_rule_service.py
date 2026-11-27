from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.routing_actions import RuleAction
from imapledger.routing_config import (
    RoutingConfigError,
    rules_content_fingerprint,
    write_routing_rules,
)
from imapledger.routing_models import RoutingRule, RuleEvidenceSettings, RuleSet, RuleType
from imapledger.routing_rule_service import RoutingRuleService
from imapledger.rule_recipes import materialize_recipe
from imapledger.rules import RuleMatch


def test_rule_mutations_preserve_actions_recipes_options_scope_and_evidence(tmp_path: Path) -> None:
    recipe = materialize_recipe(
        "spam",
        rule_id="spam",
        action=RuleAction.KEEP,
        source_folders=("INBOX",),
        options={"phishing_match_at": 0.93},
    )
    rules = RuleSet(
        (recipe,),
        default_match_at=0.84,
        evidence=RuleEvidenceSettings(trusted_provider_headers=("X-Spam-Flag",)),
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(rules, path)
    service = RoutingRuleService(path)

    service.set_enabled("spam", False)
    saved = service.load()

    assert saved.rules[0].enabled is False
    assert saved.rules[0].id == "spam"
    assert saved.rules[0].action is RuleAction.KEEP
    assert saved.rules[0].recipe == "spam"
    assert saved.rules[0].options == recipe.options
    assert saved.rules[0].source_folders == ("INBOX",)
    assert saved.default_match_at == 0.84
    assert saved.evidence == rules.evidence


def test_learned_matcher_preserves_rule_behavior_and_shared_evidence(tmp_path: Path) -> None:
    rule = RoutingRule(
        id="expected-sender",
        enabled=True,
        type=RuleType.SEMANTIC,
        action=RuleAction.KEEP,
        description="Expected messages from a known sender",
        source_folders=("INBOX",),
    )
    rules = RuleSet(
        (rule,),
        evidence=RuleEvidenceSettings(trusted_authserv_ids=("mx.example.org",)),
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(rules, path)
    service = RoutingRuleService(path)
    matcher = RuleMatch(from_address="sender@example.org")

    service.add_learned_matcher(
        "expected-sender",
        matcher,
        source_folder="INBOX",
        expected_rules_fingerprint=rules_content_fingerprint(rules),
    )
    saved = service.load()

    assert saved.rules[0].action is RuleAction.KEEP
    assert saved.rules[0].source_folders == ("INBOX",)
    assert saved.rules[0].match_any == (matcher,)
    assert saved.evidence == rules.evidence


def test_duplicate_rule_ids_are_rejected_and_spam_id_is_not_reserved(tmp_path: Path) -> None:
    rule = RoutingRule(
        id="spam",
        enabled=True,
        type=RuleType.SEMANTIC,
        action=RuleAction.KEEP,
        description="Messages about canned meat",
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(RuleSet((rule,)), path)
    service = RoutingRuleService(path)

    with pytest.raises(RoutingConfigError, match="duplicate rule ID: spam"):
        service.add(rule)

    service.remove("spam")
    assert service.load().rules == ()
