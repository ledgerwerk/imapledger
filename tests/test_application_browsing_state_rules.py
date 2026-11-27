from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.application.rules import RuleLearningOperation, RuleMigrationOperation
from imapledger.message import MailMessage
from imapledger.routing_actions import RuleAction
from imapledger.routing_config import RoutingConfigError, write_routing_rules
from imapledger.routing_models import RoutingRule, RuleType
from imapledger.routing_models import RuleSet as RoutingRuleSet
from imapledger.routing_rule_service import RoutingRuleService
from imapledger.rule_candidates import build_rule_candidates
from imapledger.rule_learning import ExistingRuleProposal
from imapledger.rules import RuleMatch


def test_rule_migration_apply_uses_preview_and_rejects_stale_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    source = (
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "github"\n'
        'enabled = true\nsource_folders = ["Spam"]\naction = "move"\n'
        'destination = "Archive"\nmatch = { from_domain = "github.com" }\n'
    )
    path.write_text(source, encoding="utf-8")
    operation = RuleMigrationOperation(path)
    preview = operation.preview()
    assert path.read_text(encoding="utf-8") == source

    path.write_text(source + "\n# changed\n", encoding="utf-8")
    with pytest.raises(RoutingConfigError, match="changed after migration preview"):
        operation.apply(preview)

    fresh_preview = operation.preview()
    applied = operation.apply(fresh_preview)
    assert applied.applied is True
    assert applied.rules.rules[0].id == "github"
    assert "schema = 4" in path.read_text(encoding="utf-8")


def test_rule_learning_saves_only_against_unchanged_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    message = MailMessage(
        uid=12,
        subject="delivery failure",
        sender="Mailer Daemon <mailer-daemon@example.net>",
        recipients=(),
        date="",
        body="not used",
        from_display_name="Mailer Daemon",
        from_address="mailer-daemon@example.net",
        reply_to="",
        sender_header="",
        return_path="",
        list_id="",
        precedence="",
        auto_submitted="",
    )
    candidate = next(item for item in build_rule_candidates(message) if item.id == "from_address_exact")
    proposal = ExistingRuleProposal(candidate, 0.96, 0.96, 0.98, "auto", "model", "request")
    monkeypatch.setattr("imapledger.application.rules.learn_existing_rule_proposal", lambda **kwargs: proposal)

    target_rule = RoutingRule(
        id="delivery-failure",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="Archive",
        description="Delivery failure notices",
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(RoutingRuleSet((target_rule,)), path)
    service = RoutingRuleService(path)
    operation = RuleLearningOperation()
    preview = operation.propose(
        message,
        folder="Spam",
        target_rule_id=target_rule.id,
        existing_rules=service.load(),
    )
    assert preview.proposed_matcher == candidate.match
    assert preview.status == "auto"

    second_rule = RoutingRule(
        id="other",
        enabled=True,
        type=RuleType.HEADER,
        destination="Archive",
        match=RuleMatch(subject="urgent"),
        source_folders=("Spam",),
    )
    service.add(second_rule)
    with pytest.raises(RoutingConfigError, match="rules changed after proposal"):
        operation.save(preview, service)
    assert service.load().rules == (target_rule, second_rule)


def test_rule_learning_appends_matcher_to_existing_semantic_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = MailMessage(
        uid=12,
        subject="delivery failure",
        sender="Mailer Daemon <mailer-daemon@example.net>",
        recipients=(),
        date="",
        body="",
        from_address="mailer-daemon@example.net",
    )
    candidate = next(item for item in build_rule_candidates(message) if item.id == "from_address_exact")
    proposal = ExistingRuleProposal(candidate, 0.96, 0.96, 0.98, "auto")
    monkeypatch.setattr("imapledger.application.rules.learn_existing_rule_proposal", lambda **kwargs: proposal)
    target = RoutingRule(
        id="delivery-failure",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="Archive",
        description="Delivery failure notices",
        match_any=(RuleMatch(list_id="bounces.example.net"),),
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(RoutingRuleSet((target,)), path)
    service = RoutingRuleService(path)
    operation = RuleLearningOperation()
    preview = operation.propose(
        message,
        folder="Spam",
        target_rule_id=target.id,
        existing_rules=service.load(),
    )

    result = operation.save(preview, service)

    saved_rule = service.load().rules[0]
    assert result.changed_rule_id == target.id
    assert saved_rule.type is RuleType.SEMANTIC
    assert saved_rule.description == target.description
    assert saved_rule.match_any == (target.match_any[0], candidate.match)


def test_rule_learning_preview_reports_higher_priority_matcher_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = MailMessage(
        uid=12,
        subject="delivery failure",
        sender="Mailer Daemon <mailer-daemon@example.net>",
        recipients=(),
        date="",
        body="",
        from_address="mailer-daemon@example.net",
    )
    candidate = next(item for item in build_rule_candidates(message) if item.id == "from_address_exact")
    proposal = ExistingRuleProposal(candidate, 0.96, 0.96, 0.98, "auto")
    monkeypatch.setattr("imapledger.application.rules.learn_existing_rule_proposal", lambda **kwargs: proposal)
    earlier = RoutingRule(
        id="mailer-daemon",
        enabled=True,
        type=RuleType.HEADER,
        destination="Archive",
        match=candidate.match,
        source_folders=("Spam",),
    )
    target = RoutingRule(
        id="delivery-failure",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="Archive",
        description="Delivery failure notices",
    )
    rules = RoutingRuleSet((earlier, target))
    path = tmp_path / "rules.toml"
    write_routing_rules(rules, path)
    service = RoutingRuleService(path)
    operation = RuleLearningOperation()
    preview = operation.propose(
        message,
        folder="Spam",
        target_rule_id=target.id,
        existing_rules=service.load(),
    )

    assert preview.status == "conflict"
    assert preview.conflict_rule_id == earlier.id
    with pytest.raises(RoutingConfigError, match="higher-priority rule mailer-daemon"):
        operation.save(preview, service)
    assert service.load() == rules


def test_spam_id_is_an_ordinary_removable_rule(tmp_path: Path) -> None:

    spam = RoutingRule(
        id="spam",
        enabled=True,
        type=RuleType.SEMANTIC,
        action=RuleAction.KEEP,
        description="Messages about canned meat",
    )
    path = tmp_path / "rules.toml"
    write_routing_rules(RoutingRuleSet((spam,)), path)
    service = RoutingRuleService(path)

    result = service.remove("spam")

    assert result.rules.rules == ()
    assert service.load().rules == ()
