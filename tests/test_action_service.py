from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.action_service import ActionService
from imapledger.analysis_service import MessageAnalysis
from imapledger.classification_state import SpamOutcome
from imapledger.config import ActionKind, ImapSettings, MessageAction, Settings, SpamActions, SpamSettings
from imapledger.mailbox import DeleteResult, MailboxSnapshot, MoveResult
from imapledger.policy import SpamVerdict
from imapledger.rules import RuleSet


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("Spam",),
            actions=SpamActions(
                spam=MessageAction(ActionKind.MOVE, "Trash"),
                not_spam=MessageAction(ActionKind.KEEP),
            ),
        ),
    )


def _analysis(folder="Spam", action=None):
    settings = _settings()
    return MessageAnalysis(
        folder=folder,
        uid=9,
        persisted_outcome=None,
        rule_id=None,
        outcome=SpamOutcome.SPAM,
        verdict=SpamVerdict.DELETE,
        signals=None,
        reasons=("test",),
        configured_action=action or settings.spam.actions.spam,
        decision_source="semantic",
    )


class FakeMailbox:
    def __init__(self, *, uidvalidity=42, uids=frozenset({9})):
        self.current_snapshot = MailboxSnapshot(uidvalidity, uids)
        self.moves = []
        self.deletes = []
        self.entered = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *args):
        return None

    def snapshot(self):
        return self.current_snapshot

    def move_uid(self, uid, destination):
        self.moves.append((uid, destination))
        return MoveResult((uid,), destination)

    def delete_uid(self, uid):
        self.deletes.append(uid)
        return DeleteResult((uid,))


def _service(mailbox, preflight=None):
    checks = []

    def run_preflight(*args, **kwargs):
        checks.append(kwargs)
        return SimpleNamespace(ok=True, errors=())

    service = ActionService(
        _settings(),
        "secret",
        RuleSet(),
        mailbox_factory=lambda **kwargs: mailbox,
        preflight=preflight or run_preflight,
    )
    return service, checks


def test_action_service_requires_user_confirmation_before_any_preflight_or_mutation():
    mailbox = FakeMailbox()
    service, checks = _service(mailbox)

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=False)

    assert not receipt.applied
    assert not receipt.confirmed
    assert "confirmation" in receipt.detail
    assert checks == []
    assert mailbox.moves == []


def test_action_service_applies_only_configured_move_and_returns_confirmed_receipt():
    mailbox = FakeMailbox()
    service, checks = _service(mailbox)

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert mailbox.moves == [(9, "Trash")]
    assert receipt.applied and receipt.confirmed
    assert receipt.destination == "Trash"
    assert checks[0]["destinations"] == ("Trash",)
    assert checks[0]["requires_delete"] is False


def test_action_service_rejects_stale_snapshot_and_non_source_folder():
    mailbox = FakeMailbox(uidvalidity=43)
    service, _ = _service(mailbox)

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied
    assert "UIDVALIDITY changed" in receipt.detail
    assert mailbox.moves == []
    with pytest.raises(ValueError, match="not configured as a source"):
        service.apply(_analysis(folder="INBOX"), uidvalidity=42, confirmed_by_user=True)


def test_action_service_rejects_unconfigured_action():
    service, _ = _service(FakeMailbox())
    analysis = _analysis(action=MessageAction(ActionKind.MOVE, "Arbitrary"))

    with pytest.raises(ValueError, match="not configured"):
        service.apply(analysis, uidvalidity=42, confirmed_by_user=True)


def test_action_service_reports_preflight_failure_without_opening_writable_mailbox():
    mailbox = FakeMailbox()
    service, _ = _service(mailbox, preflight=lambda *args, **kwargs: SimpleNamespace(ok=False, errors=()))

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert not mailbox.entered
    assert not receipt.applied
    assert "preflight rejected" in receipt.detail


def test_action_service_uses_delete_capability_preflight_and_uidplus_path():
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )
    mailbox = FakeMailbox()
    checks = []

    def preflight(*args, **kwargs):
        checks.append(kwargs)
        return SimpleNamespace(ok=True, errors=())

    service = ActionService(
        settings,
        "secret",
        RuleSet(),
        mailbox_factory=lambda **kwargs: mailbox,
        preflight=preflight,
    )
    analysis = _analysis(action=settings.spam.actions.spam)

    receipt = service.apply(analysis, uidvalidity=42, confirmed_by_user=True)

    assert mailbox.deletes == [9]
    assert receipt.applied and receipt.confirmed
    assert checks[0]["requires_delete"] is True
