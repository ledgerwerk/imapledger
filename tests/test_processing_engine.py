from __future__ import annotations

from types import SimpleNamespace

import pytest

from imapledger.config import ImapSettings, Settings
from imapledger.mailbox import MailboxItem, MailboxRunMetadata
from imapledger.message import MailMessage
from imapledger.processing_engine import ProcessingEngine
from imapledger.progress_store import ProgressStore, account_identity_key
from imapledger.routing_actions import RuleAction
from imapledger.routing_models import EvaluationState, RoutingPlan, RoutingRule, RuleEvaluation, RuleSet, RuleType
from imapledger.rules import RuleMatch


class _FakeEvaluator:
    failing_uids: set[int] = set()
    matching_uids: set[int] = {1}
    destination_override: str | None = None

    def __init__(self, **_: object) -> None:
        pass

    def __enter__(self) -> _FakeEvaluator:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def fingerprint(self, rules: RuleSet) -> str:
        return f"rules-{rules.rules!r}"

    def plan(self, folder: str, message: MailMessage, rules: RuleSet, *, rule_scope: str | None = None) -> RoutingPlan:
        if message.uid in self.failing_uids:
            raise RuntimeError("private provider details must not be stored")
        candidates = rules.enabled_rules(folder)
        if rule_scope is not None:
            candidates = tuple(rule for rule in candidates if rule.id == rule_scope)
        matched = message.uid in self.matching_uids
        result = tuple(
            RuleEvaluation(
                rule.id,
                EvaluationState.MATCH if matched else EvaluationState.NO_MATCH,
            )
            for rule in candidates
        )
        winner = candidates[0] if matched and candidates else None
        mode = "single-rule" if rule_scope is not None else "full"
        if winner is not None:
            destination = winner.destination
        else:
            destination = None
        if self.destination_override is not None:
            destination = self.destination_override
        return RoutingPlan(
            folder=folder,
            uid=message.uid,
            rule_results=result,
            winner_rule_id=winner.id if winner is not None else None,
            destination=destination,
            mode=mode,
            configured_action=winner.action if winner is not None else None,
            rule_scope=rule_scope,
            rules_fingerprint=self.fingerprint(rules),
            model="fake-model",
            request_id="fake-request",
        )


class _FakeMailbox:
    def __init__(self, uids: tuple[int, ...], *, writable: bool, destinations: tuple[str, ...] = ()) -> None:
        self.folder = "INBOX"
        self.writable = writable
        self.uids = list(uids)
        self.destinations = set(destinations)
        self.high_watermark_uid = max(uids, default=0)
        self.moved: list[tuple[int, str]] = []

        self.deleted: list[int] = []

    def metadata(self) -> MailboxRunMetadata:
        return MailboxRunMetadata(uidvalidity=7, uidnext=self.high_watermark_uid + 1)

    def validate_destination(self, destination: str) -> None:
        if destination not in self.destinations:
            raise ValueError("missing destination")

    def find_next_uids(
        self,
        *,
        cursor_uid: int | None,
        high_watermark_uid: int,
        direction: str,
        limit: int,
        lower_bound_uid: int = 0,
    ) -> tuple[int, ...]:
        candidates = [uid for uid in self.uids if lower_bound_uid < uid <= high_watermark_uid]
        if direction == "oldest":
            candidates = [uid for uid in candidates if uid > (cursor_uid or lower_bound_uid)]
            return tuple(sorted(candidates)[:limit])
        candidates = [
            uid for uid in candidates if uid < (cursor_uid if cursor_uid is not None else high_watermark_uid + 1)
        ]
        return tuple(sorted(candidates, reverse=True)[:limit])

    def fetch_items(self, uids: tuple[int, ...], *, high_watermark_uid: int) -> tuple[MailboxItem, ...]:
        return tuple(
            MailboxItem(uid, MailMessage(uid, "subject", "sender@example.org", (), "", "body"))
            for uid in uids
            if uid in self.uids
        )

    def move_uid(self, uid: int, destination: str) -> SimpleNamespace:
        self.uids.remove(uid)
        self.moved.append((uid, destination))
        return SimpleNamespace(moved=(uid,))

    def delete_uid(self, uid: int) -> SimpleNamespace:
        self.uids.remove(uid)
        self.deleted.append(uid)
        return SimpleNamespace(deleted=(uid,))


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
    )


def _rules(
    *,
    destination: str | None = "Invoices",
    action: RuleAction = RuleAction.MOVE,
) -> RuleSet:
    return RuleSet(
        (
            RoutingRule(
                id="invoice",
                enabled=True,
                type=RuleType.HEADER,
                action=action,
                destination=destination,
                match=RuleMatch(subject="invoice"),
            ),
        ),
    )


def _engine(monkeypatch, tmp_path, rules: RuleSet) -> tuple[ProcessingEngine, ProgressStore]:
    monkeypatch.setattr("imapledger.processing_engine.SemanticRoutingEvaluator", _FakeEvaluator)
    store = ProgressStore(tmp_path / "progress.sqlite3")
    engine = ProcessingEngine(settings=_settings(), rules=rules, progress_store=store)
    return engine, store


def test_preview_repeats_same_uids_without_advancing_progress_then_apply_checkpoints(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    rules = _rules()
    engine, store = _engine(monkeypatch, tmp_path, rules)
    mailbox = _FakeMailbox((1, 2), writable=True, destinations=("Invoices", "Archive"))

    preview = engine.run(mailbox, apply=False, limit=2, sort_direction="oldest")
    repeated_preview = engine.run(mailbox, apply=False, limit=2, sort_direction="oldest")
    assert tuple(result.uid for result in preview.messages) == (1, 2)
    assert tuple(result.uid for result in repeated_preview.messages) == (1, 2)
    assert tuple(result.outcome for result in preview.messages) == ("would_move", "no_match")
    assert preview.run.cursor_uid is None
    assert preview.run.scanned_count == 0
    assert store.results(preview.run.id) == ()
    assert mailbox.moved == []

    applied = engine.run(mailbox, apply=True, limit=2, sort_direction="oldest")
    assert tuple(mailbox.moved) == ((1, "Invoices"),)
    assert applied.run.scanned_count == 2
    assert applied.run.match_count == 1
    assert applied.run.moved_count == 1
    assert applied.run.status == "active"

    completed = engine.run(mailbox, apply=True, sort_direction="oldest")
    assert completed.run.status == "completed"
    assert completed.run.scanned_count == 2


def test_single_rule_nonmatch_is_checkpointed_without_moving(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((2,), writable=True, destinations=("Invoices",))

    report = engine.run(mailbox, apply=True, rule_scope="invoice", sort_direction="oldest")

    assert report.messages[0].outcome == "no_match"
    assert mailbox.moved == []
    assert report.run.mode == "single-rule"
    assert report.run.no_match_count == 1
    assert report.run.moved_count == 0
    assert store.get_result(report.run.id, 2).outcome == "no_match"


def test_retry_errors_reuses_run_and_replaces_error_with_confirmed_move(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = {1}
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((1,), writable=True, destinations=("Invoices", "Archive"))

    first = engine.run(mailbox, apply=True, sort_direction="oldest")
    assert first.run.status == "completed"
    assert first.run.error_count == 1
    assert store.errors(first.run.id)[0].error_code == "RuntimeError"
    assert mailbox.moved == []

    _FakeEvaluator.failing_uids = set()
    retried = engine.run(mailbox, apply=True, sort_direction="oldest", retry_errors=True)

    assert retried.run.id == first.run.id
    assert retried.messages[0].outcome == "moved"
    assert mailbox.moved == [(1, "Invoices")]
    assert retried.run.status == "completed"
    assert retried.run.error_count == 0
    assert retried.run.moved_count == 1
    assert store.get_result(first.run.id, 1).error_code is None


def test_changed_fingerprint_supersedes_active_run(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1, 2}
    engine, store = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((1, 2), writable=True, destinations=("Invoices", "Other"))
    first = engine.run(mailbox, apply=True, limit=1, sort_direction="oldest")
    assert first.run.status == "active"

    changed = ProcessingEngine(
        settings=_settings(),
        rules=_rules(destination="Other"),
        progress_store=store,
    )
    second = changed.run(mailbox, apply=True, limit=1, sort_direction="oldest")

    assert second.run.id != first.run.id
    assert store.get_run(first.run.id).status == "superseded"
    assert second.messages[0].uid == 2
    assert second.messages[0].destination == "Other"


def test_engine_rejects_destination_not_bound_to_configured_winner(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    _FakeEvaluator.destination_override = "Unconfigured"
    engine, store = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((1,), writable=True, destinations=("Invoices", "Archive"))

    try:
        report = engine.run(mailbox, apply=True, sort_direction="oldest")
    finally:
        _FakeEvaluator.destination_override = None

    assert report.messages[0].error_code == "InvalidRoutingPlan"
    assert mailbox.moved == []
    assert store.get_result(report.run.id, 1).error_code == "InvalidRoutingPlan"


def test_engine_account_key_uses_existing_account_identity_hash(tmp_path, monkeypatch) -> None:
    engine, _ = _engine(monkeypatch, tmp_path, _rules())
    assert engine.account_key == account_identity_key(_settings())


def test_engine_streams_each_result_with_latest_run_counters(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, _ = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((1, 2), writable=True, destinations=("Invoices", "Archive"))
    seen: list[tuple[int, int]] = []

    report = engine.run(
        mailbox,
        apply=True,
        limit=2,
        sort_direction="oldest",
        on_result=lambda message, run: seen.append((message.uid, run.scanned_count)),
    )

    assert tuple(uid for uid, _ in seen) == (1, 2)
    assert tuple(count for _, count in seen) == (1, 2)
    assert tuple(message.uid for message in report.messages) == tuple(uid for uid, _ in seen)


def test_apply_records_already_there_without_attempting_move(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules(destination="INBOX"))
    mailbox = _FakeMailbox((1,), writable=True)

    report = engine.run(mailbox, apply=True, sort_direction="oldest")

    assert report.messages[0].outcome == "already_there"
    assert report.messages[0].destination == "INBOX"
    assert mailbox.moved == []
    assert store.get_result(report.run.id, 1).outcome == "already_there"
    assert report.run.moved_count == 0


def test_retry_streams_results_and_stops_safely_between_uids(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = {1, 2}
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules())
    mailbox = _FakeMailbox((1, 2), writable=True, destinations=("Invoices", "Archive"))
    first = engine.run(mailbox, apply=True, sort_direction="oldest")
    assert first.run.error_count == 2

    _FakeEvaluator.failing_uids = set()
    seen: list[int] = []
    report = engine.run(
        mailbox,
        apply=True,
        retry_errors=True,
        sort_direction="oldest",
        on_result=lambda message, _run: seen.append(message.uid),
        should_stop=lambda: len(seen) == 1,
    )

    assert seen == [1]
    assert [message.uid for message in report.messages] == [1]
    assert report.stopped_by_user is True
    assert report.stopped_on_ambiguous_move is False
    assert report.run.status == "active"
    assert store.get_result(report.run.id, 2).error_code == "RuntimeError"


def test_keep_action_is_counted_as_acted_without_mailbox_mutation(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules(destination=None, action=RuleAction.KEEP))
    mailbox = _FakeMailbox((1,), writable=True)

    report = engine.run(mailbox, apply=True, sort_direction="oldest")
    result = store.get_result(report.run.id, 1)

    assert report.messages[0].outcome == "kept"
    assert report.messages[0].applied and report.messages[0].confirmed
    assert mailbox.moved == []
    assert mailbox.deleted == []
    assert result.configured_action is RuleAction.KEEP
    assert (report.run.acted_count, report.run.kept_count, report.run.moved_count) == (1, 1, 0)


def test_delete_without_authorization_is_blocked_and_persisted(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules(destination=None, action=RuleAction.DELETE))
    mailbox = _FakeMailbox((1,), writable=True)

    report = engine.run(mailbox, apply=True, sort_direction="oldest")
    result = store.get_result(report.run.id, 1)

    assert report.messages[0].outcome == "blocked"
    assert report.messages[0].error_code == "DeleteAuthorizationRequired"
    assert "allow-delete" in report.messages[0].detail
    assert mailbox.deleted == []
    assert result.configured_action is RuleAction.DELETE
    assert result.detail == report.messages[0].detail
    assert report.run.error_count == 1


def test_authorized_delete_records_deleted_outcome_and_counters(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules(destination=None, action=RuleAction.DELETE))
    mailbox = _FakeMailbox((1,), writable=True)

    report = engine.run(mailbox, apply=True, allow_delete=True, sort_direction="oldest")
    result = store.get_result(report.run.id, 1)

    assert report.messages[0].outcome == "deleted"
    assert report.messages[0].applied and report.messages[0].confirmed
    assert mailbox.deleted == [1]
    assert result.configured_action is RuleAction.DELETE
    assert result.outcome == "deleted"
    assert (report.run.acted_count, report.run.deleted_count, report.run.moved_count) == (1, 1, 0)


def test_delete_preview_never_mutates_and_requires_no_authorization(tmp_path, monkeypatch) -> None:
    _FakeEvaluator.failing_uids = set()
    _FakeEvaluator.matching_uids = {1}
    engine, store = _engine(monkeypatch, tmp_path, _rules(destination=None, action=RuleAction.DELETE))
    mailbox = _FakeMailbox((1,), writable=False)

    report = engine.run(mailbox, apply=False, sort_direction="oldest")

    assert report.messages[0].outcome == "would_delete"
    assert mailbox.deleted == []
    assert report.run.scanned_count == 0
    assert store.results(report.run.id) == ()


def test_processing_engine_rejects_non_boolean_delete_authorization(tmp_path, monkeypatch) -> None:
    engine, _ = _engine(monkeypatch, tmp_path, _rules(destination=None, action=RuleAction.DELETE))
    mailbox = _FakeMailbox((1,), writable=True)

    with pytest.raises(ValueError, match="allow_delete must be a boolean"):
        engine.run(mailbox, apply=True, allow_delete="yes")

    assert mailbox.deleted == []
