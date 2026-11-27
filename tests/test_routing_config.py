from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.mailbox import FolderInfo
from imapledger.routing_config import (
    RoutingConfigError,
    ensure_builtin_spam_rule,
    load_routing_rules,
    migrate_legacy_rules,
    render_routing_rules,
    resolve_spam_destination,
    rules_fingerprint,
    write_routing_rules,
)
from imapledger.routing_models import RoutingModelError, RoutingRule, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _semantic(
    rule_id: str,
    destination: str,
    *,
    match_at: float = 0.9,
    match_any: tuple[RuleMatch, ...] = (),
) -> RoutingRule:
    return RoutingRule(
        id=rule_id,
        enabled=True,
        type=RuleType.SEMANTIC,
        destination=destination,
        description=f"Category {rule_id}\nfor retained mail.",
        match_at=match_at,
        match_any=match_any,
    )


def test_schema_three_rules_round_trip_and_keep_priority_order(tmp_path: Path) -> None:
    rules = RuleSet(
        (
            RoutingRule("spam", True, RuleType.SPAM, "INBOX.Trash", description="Spam policy"),
            _semantic(
                "newsletter",
                "INBOX.Newsletter",
                match_at=0.88,
                match_any=(RuleMatch(list_id="weekly.example.com"), RuleMatch(from_address="news@example.org")),
            ),
            RoutingRule(
                "github",
                True,
                RuleType.HEADER,
                "INBOX.Development",
                match_any=(RuleMatch(from_domain="github.com"),),
            ),
        ),
        default_match_at=0.91,
    )
    path = tmp_path / "rules.toml"

    write_routing_rules(rules, path)

    assert load_routing_rules(path) == rules
    assert [rule.id for rule in load_routing_rules(path).rules] == ["spam", "newsletter", "github"]
    assert "schema = 3" in path.read_text(encoding="utf-8")
    serialized = path.read_text(encoding="utf-8")
    assert 'match_any = [{ list_id = "weekly.example.com" }, { from_address = "news@example.org" }]' in serialized
    assert "fallback_destination" not in path.read_text(encoding="utf-8")


def test_missing_schema_two_file_returns_empty_rule_set(tmp_path: Path) -> None:
    assert load_routing_rules(tmp_path / "missing.toml") == RuleSet()


@pytest.mark.parametrize(
    ("rule_text", "error"),
    [
        ('id = "newsletter"\ntype = "semantic"\ndestination = "INBOX.Newsletter"', "requires a description"),
        (
            'id = "newsletter"\ntype = "semantic"\ndestination = "INBOX.Newsletter"\n'
            'description = "A newsletter"\nmatch_at = 1.1',
            "between 0 and 1",
        ),
        ('id = "header"\ntype = "header"\ndestination = "INBOX.Dev"', "requires at least one matcher"),
        (
            'id = "spam"\ntype = "spam"\ndestination = "INBOX.Trash"\nmatch_at = 0.9',
            "only valid for semantic",
        ),
    ],
)
def test_schema_two_rule_validation_rejects_invalid_rules(tmp_path: Path, rule_text: str, error: str) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(f"[rules]\nschema = 2\n\n[[rules.rule]]\n{rule_text}\n", encoding="utf-8")

    with pytest.raises(RoutingConfigError, match=error):
        load_routing_rules(path)


def test_duplicate_ids_and_missing_destination_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 2\n\n[[rules.rule]]\nid = "same"\ntype = "spam"\n'
        'destination = "INBOX.Trash"\n\n[[rules.rule]]\nid = "same"\n'
        'type = "spam"\ndestination = "INBOX.Other"\n',
        encoding="utf-8",
    )
    with pytest.raises(RoutingConfigError, match="duplicate rule id"):
        load_routing_rules(path)

    path.write_text('[rules]\nschema = 2\n\n[[rules.rule]]\nid = "spam"\ntype = "spam"\n', encoding="utf-8")
    with pytest.raises(RoutingConfigError, match="destination"):
        load_routing_rules(path)


def test_fingerprint_is_stable_and_tracks_enabled_behavior_and_spam_config() -> None:
    disabled = RoutingRule("later", False, RuleType.SPAM, "INBOX.Trash")
    first = RuleSet((_semantic("newsletter", "INBOX.Newsletter"), disabled))
    reordered = RuleSet((disabled, _semantic("newsletter", "INBOX.Newsletter")))

    fingerprint = rules_fingerprint(first, spam_policy={"delete_safe_at": 0.88})
    assert fingerprint == rules_fingerprint(first, spam_policy={"delete_safe_at": 0.88})
    assert fingerprint == rules_fingerprint(reordered, spam_policy={"delete_safe_at": 0.88})
    assert fingerprint != rules_fingerprint(first, spam_policy={"delete_safe_at": 0.89})
    assert fingerprint != rules_fingerprint(
        RuleSet((_semantic("newsletter", "INBOX.Newsletter", match_any=(RuleMatch(list_id="weekly"),)), disabled))
    )
    assert fingerprint != rules_fingerprint(RuleSet((_semantic("newsletter", "INBOX.Newsletter", match_at=0.91),)))


def test_config_store_destinations_remain_protected_but_same_source_is_a_noop() -> None:
    rules = RuleSet((_semantic("newsletter", "INBOX.Newsletter"),))
    rules.validate_destinations("INBOX.Newsletter", config_store_folder="INBOX.Config")

    with pytest.raises(RoutingModelError, match="config-store"):
        RuleSet((_semantic("newsletter", "INBOX.Config"),)).validate_destinations(
            "INBOX.Archive", config_store_folder="INBOX.Config"
        )
    with pytest.raises(RoutingModelError, match="config-store"):
        rules.validate_destinations("INBOX.Config", config_store_folder="INBOX.Config")


def test_schema_one_migration_preview_does_not_write_and_apply_converts_rules(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    original = (
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "github"\n'
        'enabled = true\nsource_folders = ["INBOX.Junk"]\naction = "move"\n'
        'destination = "INBOX.Development"\nmatch = { from_domain = "github.com" }\n'
    )
    path.write_text(original, encoding="utf-8")

    preview = migrate_legacy_rules(path)

    assert preview.applied is False
    assert preview.source_schema == 1
    assert preview.rules.rules[0].type is RuleType.HEADER
    assert preview.rules.rules[0].source_folders == ("INBOX.Junk",)
    assert path.read_text(encoding="utf-8") == original

    applied = migrate_legacy_rules(path, apply=True)

    assert applied.applied is True
    assert load_routing_rules(path) == applied.rules
    assert "schema = 3" in path.read_text(encoding="utf-8")


def test_schema_one_keep_action_migration_refuses_unsafe_conversion(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "keep"\nsource_folders = ["INBOX.Junk"]\n'
        'action = "keep"\nmatch = { list_id = "list.example" }\n',
        encoding="utf-8",
    )

    with pytest.raises(RoutingConfigError, match="only MOVE rules"):
        migrate_legacy_rules(path, apply=True)

    assert "schema = 1" in path.read_text(encoding="utf-8")


def test_schema_two_rendering_is_deterministic() -> None:
    rules = RuleSet((_semantic("newsletter", "INBOX.Newsletter"),), "INBOX.Processed")

    assert render_routing_rules(rules) == render_routing_rules(rules)


def test_schema_two_migration_drops_fallback_and_maps_match_to_match_any(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 2\nfallback_destination = "INBOX.Processed"\n\n'
        '[[rules.rule]]\nid = "github"\ntype = "header"\ndestination = "INBOX.Dev"\n'
        'match = { from_address = "ci@example.org" }\n',
        encoding="utf-8",
    )

    preview = migrate_legacy_rules(path)

    assert preview.source_schema == 2
    assert preview.rules.fallback_destination is None
    assert preview.rules.rules[0].match_any == (RuleMatch(from_address="ci@example.org"),)
    assert any("fallback destination" in warning for warning in preview.warnings)
    applied = migrate_legacy_rules(path, apply=True, spam_destination="INBOX.Trash")
    assert applied.rules.rules[0].id == "spam"
    assert applied.rules.rules[0].built_in is True
    assert applied.rules.rules[1].source_folders == ()
    assert "schema = 3" in path.read_text(encoding="utf-8")
    assert "fallback_destination" not in path.read_text(encoding="utf-8")


def test_spam_bootstrap_uses_only_a_valid_conservative_destination() -> None:
    folders = (
        FolderInfo("INBOX.Config", ".", frozenset(), None, None),
        FolderInfo("INBOX.Trash", ".", frozenset({b"\\TRASH"}), None, None),
        FolderInfo("INBOX.Archive", ".", frozenset(), None, None),
    )
    rules = RuleSet((_semantic("newsletter", "INBOX.Newsletter"),))

    assert resolve_spam_destination("INBOX.Archive", folders, config_store_folder="INBOX.Config") == "INBOX.Archive"
    assert resolve_spam_destination("missing", folders, config_store_folder="INBOX.Config") == "INBOX.Trash"
    assert ensure_builtin_spam_rule(rules, "INBOX.Trash").rules[0].id == "spam"
    assert ensure_builtin_spam_rule(rules, None) == rules


def test_spam_bootstrap_does_not_guess_when_trash_is_ambiguous_or_unselectable() -> None:
    folders = (
        FolderInfo("INBOX.Trash", ".", frozenset({b"\\TRASH"}), None, None),
        FolderInfo("Other.Trash", ".", frozenset({b"\\TRASH"}), None, None),
        FolderInfo("INBOX.Deleted", ".", frozenset({b"\\NOSELECT"}), None, None),
    )

    assert resolve_spam_destination(None, folders) is None
