from __future__ import annotations

import os
from pathlib import Path

import pytest

import imapledger.rules as rules_module
from imapledger.config import ActionKind, MessageAction
from imapledger.message import MailMessage
from imapledger.rules import (
    MailRule,
    RuleError,
    RuleMatch,
    RuleSet,
    generate_rule_id,
    load_rules,
    validate_rule_id,
    write_rules,
)


def _message(**values: object) -> MailMessage:
    defaults: dict[str, object] = {
        "uid": 43627,
        "subject": "Ihre E-Mail konnte nicht zugestellt werden",
        "sender": "Mailer Daemon <mailer-daemon@gmx.net>",
        "recipients": (),
        "date": "",
        "body": "",
        "from_display_name": "Mailer Daemon",
        "from_address": "mailer-daemon@gmx.net",
        "return_path": "mailer-daemon@gmx.net",
        "list_id": "",
        "auto_submitted": "",
    }
    defaults.update(values)
    return MailMessage(**defaults)  # type: ignore[arg-type]


def _rule(
    rule_id: str = "mailer-daemon-gmx-net",
    *,
    enabled: bool = True,
    source_folders: tuple[str, ...] = ("INBOX.Junk",),
    action: MessageAction | None = None,
    match: RuleMatch | None = None,
) -> MailRule:
    return MailRule(
        id=rule_id,
        enabled=enabled,
        source_folders=source_folders,
        action=action or MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        match=match or RuleMatch(from_address="mailer-daemon@gmx.net"),
    )


def test_nonexistent_rules_file_is_empty(tmp_path: Path) -> None:
    assert load_rules(tmp_path / "missing.toml") == RuleSet()


def test_rules_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    rules = RuleSet(
        (
            _rule(),
            _rule(
                "keep-example",
                action=MessageAction(ActionKind.KEEP),
                match=RuleMatch(list_id="list.example.org"),
            ),
        )
    )

    write_rules(rules, path)

    assert load_rules(path) == rules
    assert 'match = { from_address = "mailer-daemon@gmx.net" }' in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("schema", ["2", "true", '"1"', "1.0"])
def test_invalid_schema_is_rejected(tmp_path: Path, schema: str) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(f"[rules]\nschema = {schema}\n", encoding="utf-8")

    with pytest.raises(RuleError, match="schema"):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "same"\n'
        'source_folders = ["Junk"]\naction = "keep"\nmatch = { list_id = "one" }\n'
        '\n[[rules.rule]]\nid = "same"\nsource_folders = ["Junk"]\n'
        'action = "keep"\nmatch = { list_id = "two" }\n',
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(path)


@pytest.mark.parametrize("rule_id", ["", "Upper", "-bad", "has space", "x" * 65])
def test_invalid_rule_ids_are_rejected(rule_id: str) -> None:
    with pytest.raises(RuleError, match="rule id"):
        validate_rule_id(rule_id)
    with pytest.raises(RuleError, match="rule id"):
        _rule(rule_id)


def test_generated_rule_ids_are_readable_and_unique() -> None:
    match = RuleMatch(from_address="mailer-daemon@gmx.net")

    assert generate_rule_id(match) == "mailer-daemon-gmx-net"
    assert generate_rule_id(match, ["mailer-daemon-gmx-net"]) == "mailer-daemon-gmx-net-2"


def test_empty_match_is_rejected() -> None:
    with pytest.raises(RuleError, match="at least one field"):
        RuleMatch()


def test_unknown_match_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "unknown-field"\n'
        'source_folders = ["Junk"]\naction = "keep"\n'
        'match = { arbitrary = "value" }\n',
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="unknown match key"):
        load_rules(path)


def test_move_requires_destination_and_keep_rejects_destination(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "missing-destination"\n'
        'source_folders = ["Junk"]\naction = "move"\nmatch = { list_id = "one" }\n',
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="requires a destination"):
        load_rules(path)

    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "keep-destination"\n'
        'source_folders = ["Junk"]\naction = "keep"\ndestination = "Trash"\n'
        'match = { list_id = "one" }\n',
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="must not have a destination"):
        load_rules(path)


def test_delete_action_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    path.write_text(
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "delete"\n'
        'source_folders = ["Junk"]\naction = "delete"\nmatch = { list_id = "one" }\n',
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="only keep and move"):
        load_rules(path)


def test_rule_source_folder_and_destination_are_validated(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    write_rules(RuleSet((_rule(),)), path)

    with pytest.raises(RuleError, match="not configured in spam.folders"):
        load_rules(path, source_folders=("INBOX.Spam",))

    source_destination = _rule(action=MessageAction(ActionKind.MOVE, "INBOX.Spam"))
    write_rules(RuleSet((source_destination,)), path)
    with pytest.raises(RuleError, match="must not be a configured spam source"):
        load_rules(path, source_folders=("INBOX.Junk", "INBOX.Spam"))


def test_exact_address_domain_normalization_and_and_semantics() -> None:
    match = RuleMatch(from_address="Mailer-Daemon@GMX.NET.", auto_submitted=" Auto-Replied ")

    assert match.from_address == "mailer-daemon@gmx.net"
    assert match.auto_submitted == "auto-replied"
    assert match.matches(_message(from_address="MAILER-DAEMON@gmx.net", auto_submitted="AUTO-REPLIED"))
    assert not match.matches(_message(from_address="someone@gmx.net", auto_submitted="AUTO-REPLIED"))
    assert not match.matches(_message(from_address="mailer-daemon@gmx.net", auto_submitted="no"))
    assert RuleMatch(from_domain="GMX.NET.").matches(_message())


def test_match_normalizes_list_id_and_subject_comparison() -> None:
    match = RuleMatch(list_id="  notices.example.org  ", subject_prefix="ihre E-Mail")

    assert match.list_id == "notices.example.org"
    assert match.matches(_message(list_id="notices.example.org"))
    assert not match.matches(_message(list_id="other.example.org"))


def test_first_match_wins_and_disabled_or_out_of_scope_rules_are_ignored() -> None:
    broad = _rule("first", match=RuleMatch(from_domain="gmx.net"))
    exact = _rule("second")
    disabled = _rule("disabled", enabled=False, match=RuleMatch(from_domain="gmx.net"))
    rules = RuleSet((disabled, broad, exact))

    assert rules.first_match("INBOX.Junk", _message()) == broad
    assert rules.first_match("INBOX.Spam", _message()) is None


def test_move_destinations_include_enabled_move_rules_in_order() -> None:
    rules = RuleSet(
        (
            _rule("one"),
            _rule("disabled", enabled=False, action=MessageAction(ActionKind.MOVE, "INBOX.Other")),
            _rule("two", action=MessageAction(ActionKind.MOVE, "INBOX.Trash"), match=RuleMatch(list_id="second")),
        )
    )

    assert rules.move_destinations() == ("INBOX.Trash",)


def test_writer_uses_atomic_writer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    calls: list[tuple[Path, str]] = []

    def fake_atomic_write(target: Path, contents: str) -> None:
        calls.append((target, contents))
        target.write_text(contents, encoding="utf-8")

    monkeypatch.setattr(rules_module, "atomic_write_text", fake_atomic_write)

    write_rules(RuleSet((_rule(),)), path)

    assert calls[0][0] == path
    assert "[[rules.rule]]" in calls[0][1]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions are unavailable")
def test_rules_file_mode_is_0600(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"

    write_rules(RuleSet((_rule(),)), path)

    assert path.stat().st_mode & 0o777 == 0o600
