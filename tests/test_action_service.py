from __future__ import annotations

import imaplib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from imapledger.action_service import ActionService
from imapledger.analysis_service import MessageAnalysis
from imapledger.classification_state import ClassificationStateBackend, SpamOutcome
from imapledger.config import (
    ActionKind,
    ClassificationStateSettings,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
)
from imapledger.mailbox import DeleteResult, MailboxSnapshot, MoveResult, ScopedMailbox
from imapledger.policy import SpamVerdict
from tests.fakes import FolderAwareFakeClient, raw_message


class SearchAllTooLargeActionClient(FolderAwareFakeClient):
    def search(self, criteria="ALL", charset=None):
        if criteria == "ALL":
            self.calls.append("search")
            self.searches.append(criteria)
            raise imaplib.IMAP4.error("got more than 1000000 bytes")
        return super().search(criteria, charset)


def _settings(*, state_backend=ClassificationStateBackend.NONE) -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("Spam",),
            actions=SpamActions(
                spam=MessageAction(ActionKind.MOVE, "Trash"),
                not_spam=MessageAction(ActionKind.KEEP),
            ),
            state=ClassificationStateSettings(state_backend),
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
        self.state_writes = []

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

    def set_classification_keyword(self, uid, *, keyword, peer_keywords):
        self.state_writes.append((uid, keyword, peer_keywords))


def _service(mailbox, preflight=None, *, settings=None):
    checks = []

    def run_preflight(*args, **kwargs):
        checks.append(kwargs)
        return SimpleNamespace(ok=True, errors=())

    service = ActionService(
        settings or _settings(),
        "secret",
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


def _real_mailbox_service(client, settings):
    mailbox_options = []

    def mailbox_factory(**kwargs):
        mailbox_options.append(kwargs)
        return ScopedMailbox(**kwargs, client_factory=lambda *args, **options: client)

    return ActionService(settings, "secret", mailbox_factory=mailbox_factory), mailbox_options


@pytest.mark.parametrize("action_kind", ["move", "delete", "keyword"])
def test_action_service_uses_exact_uid_scope_when_search_all_fails(action_kind):
    settings = _settings()
    analysis = _analysis()
    if action_kind == "delete":
        spam_action = MessageAction(ActionKind.DELETE)
        actions = replace(settings.spam.actions, spam=spam_action)
        settings = replace(settings, spam=replace(settings.spam, actions=actions))
        analysis = replace(analysis, configured_action=spam_action)
    elif action_kind == "keyword":
        settings = _settings(state_backend=ClassificationStateBackend.IMAP_KEYWORDS)
        analysis = replace(
            analysis,
            outcome=SpamOutcome.NOT_SPAM,
            configured_action=settings.spam.actions.not_spam,
        )

    client = SearchAllTooLargeActionClient({"Spam": {9: raw_message("spam", "sender@example.org")}, "Trash": {}})
    service, mailbox_options = _real_mailbox_service(client, settings)

    receipt = service.apply(analysis, uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed, receipt.detail
    assert mailbox_options[0]["uid_scope"] == ()
    assert mailbox_options[1]["uid_scope"] == (9,)
    assert client.searches
    assert all(criteria == ["UID", 9] for criteria in client.searches)
    assert "ALL" not in client.searches
    if action_kind == "move":
        assert receipt.destination == "Trash"
        assert client.moves == [((9,), "Trash")]
    elif action_kind == "delete":
        assert client.expunged == [(9,)]
        assert client.moves == []
    else:
        assert receipt.state_keyword == "imapledger-v1-notspam"
        assert client.added
        assert client.moves == []


@pytest.mark.parametrize("stale", [False, True])
def test_action_service_refuses_missing_uid_or_stale_uidvalidity_with_real_mailbox(stale):
    uidvalidities = {"Spam": 43 if stale else 42, "Trash": 42}
    source_messages = (
        {20: raw_message("other", "sender@example.org")}
        if not stale
        else {9: raw_message("spam", "sender@example.org")}
    )
    client = SearchAllTooLargeActionClient(
        {"Spam": source_messages, "Trash": {}},
        uidvalidities=uidvalidities,
    )
    service, _ = _real_mailbox_service(client, _settings())

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied and not receipt.confirmed
    assert "UIDVALIDITY changed" in receipt.detail if stale else "UID is no longer" in receipt.detail
    assert client.moves == []
    assert all(criteria == ["UID", 9] for criteria in client.searches)


@pytest.mark.parametrize("failure", ["destination", "move-capability"])
def test_action_service_preflight_rejects_missing_move_resource(failure):
    client = SearchAllTooLargeActionClient({"Spam": {9: raw_message("spam", "sender@example.org")}, "Trash": {}})
    if failure == "destination":
        client.existing_folders.remove("Trash")
        client.folders.pop("Trash")
    else:
        client._capabilities = (b"IMAP4rev1", b"UIDPLUS")
    service, mailbox_options = _real_mailbox_service(client, _settings())

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied and not receipt.confirmed
    assert client.moves == []
    assert len(mailbox_options) == 1
    assert mailbox_options[0]["uid_scope"] == ()
    assert client.searches == []


def test_action_service_rejects_stale_uidvalidity_and_missing_uid():
    stale_mailbox = FakeMailbox(uidvalidity=43)
    service, _ = _service(stale_mailbox)

    receipt = service.apply(_analysis(), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied
    assert "UIDVALIDITY changed" in receipt.detail
    assert stale_mailbox.moves == []

    missing_mailbox = FakeMailbox(uids=frozenset())
    service, _ = _service(missing_mailbox)
    receipt = service.apply(_analysis(folder="INBOX"), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied
    assert "UID is no longer" in receipt.detail
    assert missing_mailbox.moves == []


def test_action_service_allows_confirmed_classification_action_from_any_folder():
    mailbox = FakeMailbox()
    service, _ = _service(mailbox)

    receipt = service.apply(_analysis(folder="INBOX"), uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied
    assert receipt.destination == "Trash"
    assert mailbox.moves == [(9, "Trash")]


def test_action_service_applies_review_move_from_any_folder():
    defaults = _settings()
    review_action = MessageAction(ActionKind.MOVE, "Review")
    settings = replace(
        defaults,
        spam=replace(
            defaults.spam,
            actions=replace(defaults.spam.actions, review=review_action),
        ),
    )
    analysis = replace(
        _analysis(folder="Archive"),
        outcome=SpamOutcome.REVIEW,
        configured_action=review_action,
    )
    mailbox = FakeMailbox()
    service, _ = _service(mailbox, settings=settings)

    receipt = service.apply(analysis, uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed
    assert mailbox.moves == [(9, "Review")]


def test_action_service_persists_not_spam_keep_state_from_any_folder():
    settings = _settings(state_backend=ClassificationStateBackend.IMAP_KEYWORDS)
    analysis = replace(
        _analysis(folder="Archive"),
        outcome=SpamOutcome.NOT_SPAM,
        configured_action=settings.spam.actions.not_spam,
    )
    mailbox = FakeMailbox()
    service, _ = _service(mailbox, settings=settings)

    receipt = service.apply(analysis, uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed
    assert mailbox.state_writes[0][:2] == (9, "imapledger-v1-notspam")
    assert mailbox.moves == []
    assert mailbox.deletes == []


def test_action_service_same_folder_move_is_confirmed_noop():
    mailbox = FakeMailbox()
    service, _ = _service(mailbox)

    receipt = service.apply(_analysis(folder="Trash"), uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed
    assert "already resides" in receipt.detail
    assert mailbox.moves == []


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
        mailbox_factory=lambda **kwargs: mailbox,
        preflight=preflight,
    )
    analysis = _analysis(action=settings.spam.actions.spam)

    receipt = service.apply(analysis, uidvalidity=42, confirmed_by_user=True)

    assert mailbox.deletes == [9]
    assert receipt.applied and receipt.confirmed
    assert checks[0]["requires_delete"] is True
