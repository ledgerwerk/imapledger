from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.routing_actions import RuleAction
from imapledger.routing_config import (
    RULE_SCHEMA,
    RoutingConfigError,
    load_routing_rules,
    migrate_legacy_rules,
    render_routing_rules,
    rules_content_fingerprint,
    rules_fingerprint,
    write_routing_rules,
)
from imapledger.routing_models import (
    RoutingModelError,
    RoutingRule,
    RuleEvidenceSettings,
    RuleSet,
    RuleType,
)
from imapledger.rules import RuleMatch


def _semantic(
    rule_id: str,
    destination: str | None,
    *,
    action: RuleAction = RuleAction.MOVE,
    match_at: float = 0.9,
    match_any: tuple[RuleMatch, ...] = (),
) -> RoutingRule:
    return RoutingRule(
        id=rule_id,
        enabled=True,
        type=RuleType.SEMANTIC,
        action=action,
        destination=destination,
        description=f"Category {rule_id}\nfor retained mail.",
        match_at=match_at,
        match_any=match_any,
    )


def test_schema_four_rules_round_trip_with_evidence_recipes_actions_and_order(tmp_path: Path) -> None:
    rules = RuleSet(
        (
            RoutingRule(
                id="spam",
                enabled=True,
                type=RuleType.RECIPE,
                recipe="spam",
                action=RuleAction.MOVE,
                destination="INBOX.Trash",
                options={"phishing_match_at": 0.9, "action_safe_at": 0.85},
            ),
            _semantic(
                "newsletter",
                "INBOX.Newsletter",
                match_at=0.88,
                match_any=(RuleMatch(list_id="weekly.example.com"), RuleMatch(from_address="news@example.org")),
            ),
            RoutingRule(
                id="github",
                enabled=True,
                type=RuleType.HEADER,
                action=RuleAction.KEEP,
                match_any=(RuleMatch(from_domain="github.com"),),
            ),
        ),
        default_match_at=0.91,
        evidence=RuleEvidenceSettings(("mx.example.org",), ("X-Spam-Flag",)),
    )
    path = tmp_path / "rules.toml"

    write_routing_rules(rules, path)

    assert load_routing_rules(path) == rules
    assert [rule.id for rule in load_routing_rules(path).rules] == ["spam", "newsletter", "github"]
    serialized = path.read_text(encoding="utf-8")
    assert f"schema = {RULE_SCHEMA}" in serialized
    assert 'action = "move"' in serialized
    assert 'action = "keep"' in serialized
    assert "[rules.evidence]" in serialized
    assert 'match_any = [{ list_id = "weekly.example.com" }, { from_address = "news@example.org" }]' in serialized


def test_semantic_spam_id_is_not_special_and_empty_rules_are_safe(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 4\n\n[[rules.rule]]\nid = "spam"\ntype = "semantic"\n'
        'description = "Spam the canned meat"\ndestination = "INBOX.Food"\n',
        encoding="utf-8",
    )

    rules = load_routing_rules(path)

    assert rules.rules[0].id == "spam"
    assert rules.rules[0].type is RuleType.SEMANTIC
    assert rules.rules[0].action is RuleAction.MOVE
    assert load_routing_rules(tmp_path / "missing.toml") == RuleSet()


def test_move_destination_shorthand_is_inferred_and_rendered_explicitly() -> None:
    rules = load_routing_rules_from_text(
        '[rules]\nschema = 4\n\n[[rules.rule]]\nid = "newsletter"\ntype = "semantic"\n'
        'description = "newsletter"\ndestination = "INBOX.Newsletter"\n'
    )

    assert rules.rules[0].action is RuleAction.MOVE
    assert 'action = "move"' in render_routing_rules(rules)


@pytest.mark.parametrize(
    ("rule_text", "error"),
    [
        ('id = "x"\ntype = "semantic"\naction = "keep"', "requires a description"),
        (
            'id = "x"\ntype = "semantic"\naction = "move"\ndescription = "x"\nmatch_at = 1.1',
            "between 0 and 1",
        ),
        ('id = "x"\ntype = "header"\naction = "keep"', "requires at least one matcher"),
        ('id = "x"\ntype = "recipe"\naction = "keep"', "requires a valid recipe ID"),
        ('id = "x"\ntype = "semantic"\ndescription = "x"', "requires an action or destination"),
        (
            'id = "x"\ntype = "semantic"\naction = "keep"\n'
            'description = "x"\ndestination = "X"',
            "must not have a destination",
        ),
        (
            'id = "x"\ntype = "semantic"\naction = "delete"\n'
            'destination = "X"\ndescription = "x"',
            "must not have a destination",
        ),
        ('id = "x"\ntype = "semantic"\naction = "move"\ndescription = "x"', "requires a non-empty destination"),
    ],
)
def test_schema_four_validation_rejects_invalid_rules(tmp_path: Path, rule_text: str, error: str) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(f"[rules]\nschema = 4\n\n[[rules.rule]]\n{rule_text}\n", encoding="utf-8")

    with pytest.raises(RoutingConfigError, match=error):
        load_routing_rules(path)


def test_recipe_config_rejects_unsupported_options(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 4\n\n[[rules.rule]]\nid = "spam"\ntype = "recipe"\n'
        'recipe = "spam"\naction = "keep"\n\n[rules.rule.options]\n'
        'delete_safe_at = 0.88\n',
        encoding="utf-8",
    )

    with pytest.raises(RoutingConfigError, match="unknown Spam recipe option"):
        load_routing_rules(path)


def load_routing_rules_from_text(text: str) -> RuleSet:
    import tomllib

    from imapledger.routing_config import _parse_routing_rule

    payload = tomllib.loads(text)
    table = payload["rules"]
    return RuleSet(tuple(_parse_routing_rule(value, index) for index, value in enumerate(table.get("rule", []), 1)))


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 4\n\n[[rules.rule]]\nid = "same"\ntype = "header"\naction = "keep"\n'
        'match_any = [{ from_domain = "one.example" }]\n\n[[rules.rule]]\nid = "same"\n'
        'type = "header"\naction = "keep"\nmatch_any = [{ from_domain = "two.example" }]\n',
        encoding="utf-8",
    )
    with pytest.raises(RoutingConfigError, match="duplicate rule id"):
        load_routing_rules(path)


def test_fingerprint_tracks_rule_behavior_and_shared_evidence() -> None:
    first = RuleSet(
        (_semantic("newsletter", "INBOX.Newsletter"),),
        evidence=RuleEvidenceSettings(("mx.example.org",), ("X-Spam-Flag",)),
    )
    same = RuleSet(
        (_semantic("newsletter", "INBOX.Newsletter"),),
        evidence=RuleEvidenceSettings(("mx.example.org",), ("X-Spam-Flag",)),
    )
    assert rules_fingerprint(first) == rules_fingerprint(same)
    assert rules_fingerprint(first) != rules_fingerprint(
        RuleSet((_semantic("newsletter", "INBOX.Archive"),), evidence=first.evidence)
    )
    assert rules_fingerprint(first) != rules_fingerprint(
        RuleSet(first.rules, evidence=RuleEvidenceSettings(("other.example",), ("X-Spam-Flag",)))
    )
    assert rules_fingerprint(first) != rules_fingerprint(
        RuleSet(
            (
                RoutingRule(
                    "junk",
                    True,
                    RuleType.RECIPE,
                    action=RuleAction.KEEP,
                    recipe="spam",
                    options={"threshold": 0.8},
                ),
            )
        )
    )



def test_recipe_fingerprint_tracks_recipe_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    from imapledger.rule_recipes.spam import SPAM_RECIPE_SPEC, SpamRecipe

    rule = RoutingRule(
        "spam-detector",
        True,
        RuleType.RECIPE,
        action=RuleAction.KEEP,
        recipe="spam",
    )
    rules = RuleSet((rule,))
    original = rules_fingerprint(rules)
    monkeypatch.setattr(SpamRecipe, "spec", replace(SPAM_RECIPE_SPEC, revision="spam-v3"))

    assert rules_fingerprint(rules) != original

def test_content_fingerprint_tracks_disabled_rules_and_reordering() -> None:
    disabled = RoutingRule(
        "later", False, RuleType.RECIPE, action=RuleAction.KEEP, recipe="spam"
    )
    first = RuleSet((_semantic("newsletter", "INBOX.Newsletter"), disabled))
    reordered = RuleSet((disabled, _semantic("newsletter", "INBOX.Newsletter")))

    assert rules_content_fingerprint(first) != rules_content_fingerprint(reordered)


def test_move_destinations_and_config_store_protection_ignore_keep_delete() -> None:
    keep = RoutingRule(
        "keep", True, RuleType.HEADER, action=RuleAction.KEEP,
        match_any=(RuleMatch(from_domain="a.example"),),
    )
    delete = RoutingRule(
        "delete", True, RuleType.HEADER, action=RuleAction.DELETE,
        match_any=(RuleMatch(from_domain="b.example"),),
    )
    move = RoutingRule(
        "move", True, RuleType.HEADER, action=RuleAction.MOVE,
        destination="INBOX.News", match_any=(RuleMatch(from_domain="c.example"),),
    )
    rules = RuleSet((keep, delete, move))

    assert rules.move_destinations() == ("INBOX.News",)
    rules.validate_destinations("INBOX.News", config_store_folder="INBOX.Config")
    with pytest.raises(RoutingModelError, match="config-store"):
        RuleSet(
            (
                RoutingRule(
                    "move",
                    True,
                    RuleType.HEADER,
                    destination="INBOX.Config",
                    match_any=(RuleMatch(from_domain="c.example"),),
                ),
            )
        ).validate_destinations("INBOX.News", config_store_folder="INBOX.Config")


def test_schema_three_migration_converts_spam_to_an_ordinary_recipe(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    original = (
        '[rules]\nschema = 3\ndefault_match_at = 0.88\n\n[[rules.rule]]\nid = "spam"\n'
        'enabled = true\ntype = "spam"\ndestination = "INBOX.Trash"\n\n[[rules.rule]]\n'
        'id = "newsletter"\nenabled = true\ntype = "semantic"\ndestination = "INBOX.News"\n'
        'description = "newsletter"\nmatch_at = 0.9\nsource_folders = ["INBOX.Junk"]\n'
        'match_any = [{ list_id = "weekly.example" }]\n'
    )
    path.write_text(original, encoding="utf-8")

    preview = migrate_legacy_rules(path)

    assert preview.applied is False
    assert preview.source_schema == 3
    assert preview.rules.rules[0].id == "spam"
    assert preview.rules.rules[0].type is RuleType.RECIPE
    assert preview.rules.rules[0].recipe == "spam"
    assert preview.rules.rules[0].action is RuleAction.MOVE
    assert preview.rules.rules[0].destination == "INBOX.Trash"
    assert not hasattr(preview.rules.rules[0], "built_in")
    assert path.read_text(encoding="utf-8") == original

    applied = migrate_legacy_rules(path, apply=True)
    assert applied.applied is True
    assert load_routing_rules(path) == applied.rules
    assert "schema = 4" in path.read_text(encoding="utf-8")




def test_schema_one_migration_converts_rules_and_schema_two_match_to_match_any(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "github"\nenabled = true\n'
        'source_folders = ["INBOX.Junk"]\naction = "move"\ndestination = "INBOX.Dev"\n'
        'match = { from_domain = "github.com" }\n',
        encoding="utf-8",
    )
    preview = migrate_legacy_rules(path)
    assert preview.source_schema == 1
    assert preview.rules.rules[0].type is RuleType.HEADER
    assert preview.rules.rules[0].action is RuleAction.MOVE
    assert preview.rules.rules[0].source_folders == ("INBOX.Junk",)

    path.write_text(
        '[rules]\nschema = 2\nfallback_destination = "INBOX.Processed"\n\n'
        '[[rules.rule]]\nid = "github"\ntype = "header"\ndestination = "INBOX.Dev"\n'
        'match = { from_address = "ci@example.org" }\n',
        encoding="utf-8",
    )
    converted = migrate_legacy_rules(path)
    assert converted.source_schema == 2
    assert converted.rules.rules[0].match_any == (RuleMatch(from_address="ci@example.org"),)
    assert any("fallback destination" in warning for warning in converted.warnings)
