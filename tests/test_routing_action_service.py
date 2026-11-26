from __future__ import annotations

from types import SimpleNamespace

from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.mailbox import MailboxSnapshot, MoveResult
from imapledger.routing_action_service import RoutingActionService
from imapledger.routing_config import rules_fingerprint
from imapledger.routing_models import EvaluationState, RoutingPlan, RoutingRule, RuleEvaluation, RuleSet, RuleType
from imapledger.rules import RuleMatch


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )


def _rules(destination: str = "Archive") -> RuleSet:
    return RuleSet(
        (
            RoutingRule(
                id="header-match",
                enabled=True,
                type=RuleType.HEADER,
                destination=destination,
                match=RuleMatch(subject="receipt"),
            ),
        ),
        fallback_destination="Processed",
    )


def _plan(settings: Settings, rules: RuleSet) -> RoutingPlan:
    fingerprint = rules_fingerprint(
        rules,
        spam_policy=settings.spam.policy.thresholds(),
        spam_evidence_config={
            "trusted_authserv_ids": [],
            "trusted_provider_headers": [],
        },
    )
    return RoutingPlan(
        folder="INBOX",
        uid=9,
        rule_results=(RuleEvaluation("header-match", EvaluationState.MATCH),),
        winner_rule_id="header-match",
        destination="Archive",
        mode="full",
        rules_fingerprint=fingerprint,
    )


class FakeMailbox:
    def __init__(self, *, uidvalidity: int = 42, uids: frozenset[int] = frozenset({9})) -> None:
        self.current_snapshot = MailboxSnapshot(uidvalidity, uids)
        self.moves: list[tuple[int, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def snapshot(self) -> MailboxSnapshot:
        return self.current_snapshot

    def move_uid(self, uid: int, destination: str) -> MoveResult:
        self.moves.append((uid, destination))
        return MoveResult((uid,), destination)


def _service(
    settings: Settings,
    rules: RuleSet,
    mailbox: FakeMailbox,
    *,
    current_rules: RuleSet | None = None,
) -> tuple[RoutingActionService, list[dict[str, object]]]:
    preflights: list[dict[str, object]] = []

    def preflight(*args, **kwargs):
        preflights.append(kwargs)
        return SimpleNamespace(ok=True, errors=())

    service = RoutingActionService(
        settings,
        "secret",
        rules,
        rules_provider=(lambda: current_rules) if current_rules is not None else None,
        mailbox_factory=lambda **kwargs: mailbox,
        preflight=preflight,
    )
    return service, preflights


def test_routing_action_requires_confirmation_before_preflight_or_mailbox_access() -> None:
    settings = _settings()
    rules = _rules()
    mailbox = FakeMailbox()
    service, preflights = _service(settings, rules, mailbox)

    receipt = service.apply(_plan(settings, rules), uidvalidity=42, confirmed_by_user=False)

    assert not receipt.applied
    assert not receipt.confirmed
    assert "confirmation" in receipt.detail
    assert preflights == []
    assert mailbox.moves == []


def test_routing_action_applies_the_exact_uid_and_current_destination() -> None:
    settings = _settings()
    rules = _rules()
    mailbox = FakeMailbox()
    service, preflights = _service(settings, rules, mailbox)

    receipt = service.apply(_plan(settings, rules), uidvalidity=42, confirmed_by_user=True)

    assert receipt.applied and receipt.confirmed
    assert mailbox.moves == [(9, "Archive")]
    assert preflights[0]["uid_scope"] == (9,)
    assert preflights[0]["destinations"] == ("Archive",)


def test_routing_action_refuses_changed_uidvalidity_and_missing_uid() -> None:
    settings = _settings()
    rules = _rules()

    for mailbox in (FakeMailbox(uidvalidity=43), FakeMailbox(uids=frozenset({10}))):
        service, _ = _service(settings, rules, mailbox)
        receipt = service.apply(_plan(settings, rules), uidvalidity=42, confirmed_by_user=True)
        assert not receipt.applied
        assert not receipt.confirmed
        assert mailbox.moves == []


def test_routing_action_refuses_a_stale_rules_fingerprint() -> None:
    settings = _settings()
    planned_rules = _rules()
    mailbox = FakeMailbox()
    service, preflights = _service(settings, planned_rules, mailbox, current_rules=_rules("Other"))

    receipt = service.apply(_plan(settings, planned_rules), uidvalidity=42, confirmed_by_user=True)

    assert not receipt.applied
    assert not receipt.confirmed
    assert "Rules changed" in receipt.detail
    assert preflights == []
    assert mailbox.moves == []
