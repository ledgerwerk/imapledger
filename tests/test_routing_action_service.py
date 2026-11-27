from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.config import ImapSettings, Settings
from imapledger.mailbox import DeleteResult, MailboxSnapshot, MoveResult
from imapledger.routing_action_service import RoutingActionService
from imapledger.routing_actions import RuleAction
from imapledger.routing_config import rules_fingerprint
from imapledger.routing_models import EvaluationState, RoutingPlan, RoutingRule, RuleEvaluation, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _settings() -> Settings:
    return Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org"))


def _rules(action: RuleAction, destination: str | None = None) -> RuleSet:
    return RuleSet(
        (
            RoutingRule(
                id="header-match",
                enabled=True,
                type=RuleType.HEADER,
                action=action,
                destination=destination,
                match=RuleMatch(subject="receipt"),
            ),
        )
    )


def _plan(rules: RuleSet, action: RuleAction, destination: str | None = None) -> RoutingPlan:
    return RoutingPlan(
        folder="INBOX",
        uid=9,
        rule_results=(RuleEvaluation("header-match", EvaluationState.MATCH),),
        winner_rule_id="header-match",
        destination=destination,
        mode="full",
        rules_fingerprint=rules_fingerprint(rules),
        configured_action=action,
    )


class FakeMailbox:
    def __init__(self, *, uidvalidity: int = 42, uids: frozenset[int] = frozenset({9})) -> None:
        self.current_snapshot = MailboxSnapshot(uidvalidity, uids)
        self.moves: list[tuple[int, str]] = []
        self.deletes: list[int] = []
        self.kwargs: dict[str, object] = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def snapshot(self) -> MailboxSnapshot:
        return self.current_snapshot

    def move_uid(self, uid: int, destination: str) -> MoveResult:
        self.moves.append((uid, destination))
        return MoveResult((uid,), destination)

    def delete_uid(self, uid: int) -> DeleteResult:
        self.deletes.append(uid)
        return DeleteResult((uid,))


def _service(
    rules: RuleSet,
    mailbox: FakeMailbox,
    *,
    current_rules: RuleSet | None = None,
) -> tuple[RoutingActionService, list[dict[str, object]], list[dict[str, object]]]:
    preflights: list[dict[str, object]] = []
    mailboxes: list[dict[str, object]] = []

    def preflight(*args, **kwargs):
        preflights.append(kwargs)
        return SimpleNamespace(ok=True, errors=())

    def mailbox_factory(**kwargs):
        mailboxes.append(kwargs)
        return mailbox

    service = RoutingActionService(
        _settings(),
        "secret",
        rules,
        rules_provider=(lambda: current_rules) if current_rules is not None else None,
        mailbox_factory=mailbox_factory,
        preflight=preflight,
    )
    return service, preflights, mailboxes


def test_routing_action_requires_confirmation_before_preflight_or_mailbox_access() -> None:
    rules = _rules(RuleAction.MOVE, "Archive")
    mailbox = FakeMailbox()
    service, preflights, mailboxes = _service(rules, mailbox)

    receipt = service.apply(
        _plan(rules, RuleAction.MOVE, "Archive"),
        uidvalidity=42,
        confirmed_by_user=False,
    )

    assert not receipt.applied
    assert not receipt.confirmed
    assert "confirmation" in receipt.detail
    assert preflights == []
    assert mailboxes == []
    assert mailbox.moves == []


def test_move_applies_the_exact_uid_and_current_destination() -> None:
    rules = _rules(RuleAction.MOVE, "Archive")
    mailbox = FakeMailbox()
    service, preflights, mailboxes = _service(rules, mailbox)

    receipt = service.apply(
        _plan(rules, RuleAction.MOVE, "Archive"),
        uidvalidity=42,
        confirmed_by_user=True,
    )

    assert receipt.applied and receipt.confirmed
    assert mailbox.moves == [(9, "Archive")]
    assert preflights[0]["uid_scope"] == (9,)
    assert preflights[0]["destinations"] == ("Archive",)
    assert preflights[0]["requires_delete"] is False
    assert mailboxes[0]["uid_scope"] == (9,)
    assert mailboxes[0]["allowed_destinations"] == ("Archive",)


def test_keep_confirms_the_exact_message_without_mailbox_mutation() -> None:
    rules = _rules(RuleAction.KEEP)
    mailbox = FakeMailbox()
    service, preflights, mailboxes = _service(rules, mailbox)

    receipt = service.apply(_plan(rules, RuleAction.KEEP), uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed
    assert mailbox.moves == []
    assert mailbox.deletes == []
    assert preflights[0]["destinations"] == ()
    assert mailboxes[0]["writable"] is False


def test_delete_requires_explicit_authorization_before_mailbox_access() -> None:
    rules = _rules(RuleAction.DELETE)
    mailbox = FakeMailbox()
    service, preflights, mailboxes = _service(rules, mailbox)

    receipt = service.apply(_plan(rules, RuleAction.DELETE), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied
    assert not receipt.confirmed
    assert "allow-delete" in receipt.detail
    assert preflights == []
    assert mailboxes == []
    assert mailbox.deletes == []


def test_action_service_rejects_non_boolean_delete_authorization() -> None:
    rules = _rules(RuleAction.DELETE)
    mailbox = FakeMailbox()
    service, preflights, _ = _service(rules, mailbox)

    with pytest.raises(ValueError, match="allow_delete must be a boolean"):
        service.apply(
            _plan(rules, RuleAction.DELETE),
            uidvalidity=42,
            confirmed_by_user=True,
            allow_delete="yes",
        )

    assert preflights == []
    assert mailbox.deletes == []


def test_authorized_delete_uses_exact_uid_and_delete_preflight() -> None:
    rules = _rules(RuleAction.DELETE)
    mailbox = FakeMailbox()
    service, preflights, mailboxes = _service(rules, mailbox)

    receipt = service.apply(
        _plan(rules, RuleAction.DELETE),
        uidvalidity=42,
        confirmed_by_user=True,
        allow_delete=True,
    )

    assert receipt.applied and receipt.confirmed
    assert mailbox.deletes == [9]
    assert preflights[0]["destinations"] == ()
    assert preflights[0]["requires_delete"] is True
    assert mailboxes[0]["allow_delete"] is True


def test_action_service_refuses_changed_uidvalidity_and_missing_uid() -> None:
    rules = _rules(RuleAction.MOVE, "Archive")
    for mailbox in (FakeMailbox(uidvalidity=43), FakeMailbox(uids=frozenset({10}))):
        service, _, _ = _service(rules, mailbox)
        receipt = service.apply(
            _plan(rules, RuleAction.MOVE, "Archive"),
            uidvalidity=42,
            confirmed_by_user=True,
        )
        assert not receipt.applied
        assert not receipt.confirmed
        assert mailbox.moves == []


def test_action_service_refuses_a_stale_rules_fingerprint() -> None:
    planned_rules = _rules(RuleAction.MOVE, "Archive")
    mailbox = FakeMailbox()
    service, preflights, _ = _service(planned_rules, mailbox, current_rules=_rules(RuleAction.MOVE, "Other"))

    receipt = service.apply(
        _plan(planned_rules, RuleAction.MOVE, "Archive"),
        uidvalidity=42,
        confirmed_by_user=True,
    )

    assert not receipt.applied
    assert not receipt.confirmed
    assert "Rules changed" in receipt.detail
    assert preflights == []
    assert mailbox.moves == []
