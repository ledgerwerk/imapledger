from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from imapledger.config import ActionKind, MessageAction
from imapledger.mailbox import MailboxItem, MessageSelection
from imapledger.message import MailMessage
from imapledger.rule_service import RuleService
from imapledger.rule_test_service import RuleTestService
from imapledger.rules import MailRule, RuleError, RuleMatch, RuleSet, load_rules, write_rules


def _rule(
    rule_id: str = "first",
    *,
    match: RuleMatch | None = None,
    action: MessageAction | None = None,
    enabled: bool = True,
    source_folders: tuple[str, ...] = ("INBOX.Junk",),
) -> MailRule:
    return MailRule(
        id=rule_id,
        enabled=enabled,
        source_folders=source_folders,
        action=action or MessageAction(ActionKind.MOVE, "INBOX.Trash"),
        match=match or RuleMatch(from_address=f"{rule_id}@example.org"),
    )


def test_service_add_update_toggle_remove_and_reorder_preserves_order(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    service = RuleService(path, source_folders=("INBOX.Junk",))
    service.add(_rule("first"))
    service.add(_rule("second"))

    service.move("second", -1)
    assert [rule.id for rule in load_rules(path).rules] == ["second", "first"]

    replacement = _rule("second", action=MessageAction(ActionKind.KEEP))
    service.update("second", replacement)
    service.set_enabled("second", False)
    assert not load_rules(path).rules[0].enabled

    service.remove("second")
    assert [rule.id for rule in load_rules(path).rules] == ["first"]


def test_service_reloads_disk_before_add_and_rejects_duplicate_id(tmp_path: Path) -> None:
    path = tmp_path / "rules.toml"
    service = RuleService(path, source_folders=("INBOX.Junk",))
    write_rules(RuleSet((_rule("external"),)), path)

    with pytest.raises(RuleError, match="duplicate rule ID"):
        service.add(_rule("external", match=RuleMatch(list_id="external-list")))


def test_service_rejects_equivalent_and_conflicting_matchers(tmp_path: Path) -> None:
    service = RuleService(tmp_path / "rules.toml", source_folders=("INBOX.Junk",))
    service.add(_rule("first"))

    with pytest.raises(RuleError, match="equivalent rule already exists: first"):
        service.add(_rule("second", match=RuleMatch(from_address="first@example.org")))
    with pytest.raises(RuleError, match="conflicting rule already exists: first"):
        service.add(
            _rule(
                "second",
                match=RuleMatch(from_address="first@example.org"),
                action=MessageAction(ActionKind.KEEP),
            )
        )


def test_service_rejects_unconfigured_sources_and_invalid_order_offset(tmp_path: Path) -> None:
    service = RuleService(tmp_path / "rules.toml", source_folders=("INBOX.Junk",))
    with pytest.raises(RuleError, match="not configured in spam.folders"):
        service.add(_rule("outside", source_folders=("INBOX",)))
    with pytest.raises(RuleError, match="offset must be"):
        service.move("missing", 2)


def test_rule_test_service_is_bounded_read_only_and_only_reports_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    message = MailMessage(
        uid=7,
        subject="matched subject",
        sender="test@example.org",
        recipients=(),
        date="",
        body="",
        from_address="test@example.org",
    )
    calls: list[dict[str, object]] = []

    class FakeMailbox:
        def __init__(self, **kwargs: object) -> None:
            calls.append(kwargs)

        def __enter__(self) -> FakeMailbox:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def iter_messages(self, selection: MessageSelection):
            assert selection.limit == 2
            yield MailboxItem(uid=7, message=message)
            yield MailboxItem(uid=8, skip_reason="oversized")

    monkeypatch.setattr("imapledger.rule_test_service.ScopedMailbox", FakeMailbox)
    settings = SimpleNamespace(
        imap=SimpleNamespace(host="example.org", port=993, username="user"),
        spam=SimpleNamespace(folders=("INBOX.Junk",), max_message_bytes=1000, max_body_chars=100),
    )
    result = RuleTestService(settings, "secret").test(_rule("test"), limit=2)  # type: ignore[arg-type]

    assert result.scanned == 2
    assert [(item.uid, item.subject) for item in result.matches] == [(7, "matched subject")]
    assert calls[0]["writable"] is False
    assert calls[0]["password"] == "secret"


def test_rule_test_service_rejects_unbounded_or_out_of_scope_test() -> None:
    settings = SimpleNamespace(
        imap=SimpleNamespace(host="example.org", port=993, username="user"),
        spam=SimpleNamespace(folders=("INBOX.Junk",), max_message_bytes=1000, max_body_chars=100),
    )
    service = RuleTestService(settings, "secret")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        service.test(_rule("test"), limit=0)
    with pytest.raises(RuleError, match="not configured in spam.folders"):
        service.test(_rule("test", source_folders=("INBOX",)), limit=5)
