from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .config import Settings
from .evidence import MailboxContext
from .mailbox import MailboxItem, MailboxRunMetadata, PartialMoveError, ProcessingMailbox
from .progress_store import (
    ProgressResumeError,
    ProgressRun,
    ProgressStore,
    RunMode,
    SortDirection,
    account_identity_key,
)
from .routing_evaluator import SemanticRoutingEvaluator
from .routing_models import EvaluationState, RoutingModelError, RoutingPlan, RuleSet

PROCESSING_BATCH_SIZE = 50


class ProcessingError(RuntimeError):
    """A routing run cannot safely proceed."""


@dataclass(frozen=True, slots=True)
class ProcessedMessage:
    uid: int
    outcome: str
    plan: RoutingPlan | None = None
    destination: str | None = None
    error_code: str | None = None
    applied: bool = False
    confirmed: bool = False


@dataclass(frozen=True, slots=True)
class ProcessingReport:
    run: ProgressRun
    messages: tuple[ProcessedMessage, ...]
    preview: bool
    retry_only: bool
    exhausted: bool
    stopped_on_ambiguous_move: bool = False
    stopped_by_user: bool = False


class ProcessingEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        rules: RuleSet,
        progress_store: ProgressStore,
        account_key: str | None = None,
    ) -> None:
        self.settings = settings
        self.rules = rules
        self.progress_store = progress_store
        self.account_key = account_key or account_identity_key(settings)

    def run(
        self,
        mailbox: ProcessingMailbox,
        *,
        apply: bool,
        limit: int | None = None,
        rule_scope: str | None = None,
        sort_direction: SortDirection = "newest",
        new_run: bool = False,
        retry_errors: bool = False,
        on_result: Callable[[ProcessedMessage, ProgressRun], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> ProcessingReport:
        """Process UIDs in order. Result callbacks run on this thread and propagate exceptions."""
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
            raise ValueError("message limit must be a positive integer")
        if sort_direction not in {"oldest", "newest"}:
            raise ValueError("sort direction must be oldest or newest")
        if new_run and retry_errors:
            raise ProcessingError("--new-run cannot be combined with --retry-errors")
        if retry_errors and not apply:
            raise ProcessingError("--retry-errors requires --apply")

        folder = mailbox.folder
        mode: RunMode = "single-rule" if rule_scope is not None else "full"
        config_store_folder = self.settings.config_store.folder if self.settings.config_store is not None else None
        try:
            self.rules.validate_destinations(folder, config_store_folder=config_store_folder)
        except RoutingModelError as exc:
            raise ProcessingError(str(exc)) from exc
        if rule_scope is not None and not any(rule.id == rule_scope for rule in self.rules.enabled_rules(folder)):
            raise ProcessingError(f"enabled rule not found for source {folder}: {rule_scope}")
        if mode == "full" and self.rules.fallback_destination is None:
            raise ProcessingError("full routing requires rules.fallback_destination")

        destinations = self._destinations(folder, rule_scope)
        metadata = mailbox.metadata()
        if apply:
            if not mailbox.writable:
                raise ProcessingError("apply requires a writable processing mailbox")
            for destination in destinations:
                mailbox.validate_destination(destination)

        evaluator = SemanticRoutingEvaluator(
            context=MailboxContext(
                folder_role="mail",
                already_in_configured_junk_folder=folder in self.settings.spam.folders,
            ),
            trusted_authserv_ids=self.settings.spam.trusted_authserv_ids,
            trusted_provider_headers=self.settings.spam.trusted_provider_headers,
            spam_policy=self.settings.spam.policy,
            config_store_folder=config_store_folder,
        )
        with evaluator:
            fingerprint = evaluator.fingerprint(self.rules)
            if retry_errors:
                return self._retry(
                    mailbox,
                    evaluator,
                    fingerprint=fingerprint,
                    mode=mode,
                    rule_scope=rule_scope,
                    sort_direction=sort_direction,
                    limit=limit,
                    metadata=metadata,
                    on_result=on_result,
                    should_stop=should_stop,
                )
            run = self.progress_store.begin_run(
                account_key=self.account_key,
                source_folder=folder,
                uidvalidity=metadata.uidvalidity,
                high_watermark_uid=metadata.high_watermark_uid,
                rules_fingerprint=fingerprint,
                mode=mode,
                rule_scope=rule_scope,
                sort_direction=sort_direction,
                new_run=new_run,
            )
            return self._scan(
                mailbox,
                evaluator,
                run=run,
                rule_scope=rule_scope,
                apply=apply,
                limit=limit,
                on_result=on_result,
                should_stop=should_stop,
            )

    def _scan(
        self,
        mailbox: ProcessingMailbox,
        evaluator: SemanticRoutingEvaluator,
        *,
        run: ProgressRun,
        rule_scope: str | None,
        apply: bool,
        limit: int | None,
        on_result: Callable[[ProcessedMessage, ProgressRun], None] | None,
        should_stop: Callable[[], bool] | None,
    ) -> ProcessingReport:
        messages: list[ProcessedMessage] = []
        processed = 0
        exhausted = False
        stopped = False
        stopped_by_user = False
        while limit is None or processed < limit:
            remaining = PROCESSING_BATCH_SIZE if limit is None else min(PROCESSING_BATCH_SIZE, limit - processed)
            uids = mailbox.find_next_uids(
                cursor_uid=run.cursor_uid,
                high_watermark_uid=run.high_watermark_uid,
                lower_bound_uid=run.lower_bound_uid,
                limit=remaining,
                direction=run.sort_direction,
            )
            if not uids:
                exhausted = True
                break
            items = {item.uid: item for item in mailbox.fetch_items(uids, high_watermark_uid=run.high_watermark_uid)}
            for uid in uids:
                if should_stop is not None and should_stop():
                    stopped = True
                    stopped_by_user = True
                    break
                item = items.get(uid, MailboxItem(uid, skip_reason="message disappeared before body fetch"))
                result, run, stop = self._process_one(
                    mailbox,
                    evaluator,
                    item,
                    run=run,
                    rule_scope=rule_scope,
                    apply=apply,
                )
                messages.append(result)
                processed += 1
                if on_result is not None:
                    on_result(result, run)
                if stop:
                    stopped = True
                    break
            if stopped:
                break
            if len(uids) < remaining:
                exhausted = True
                break

        if apply and exhausted and not stopped:
            run = self.progress_store.complete_run(run.id)
        return ProcessingReport(
            run=run,
            messages=tuple(messages),
            preview=not apply,
            retry_only=False,
            exhausted=exhausted,
            stopped_on_ambiguous_move=stopped and not stopped_by_user,
            stopped_by_user=stopped_by_user,
        )

    def _process_one(
        self,
        mailbox: ProcessingMailbox,
        evaluator: SemanticRoutingEvaluator,
        item: MailboxItem,
        *,
        run: ProgressRun,
        rule_scope: str | None,
        apply: bool,
    ) -> tuple[ProcessedMessage, ProgressRun, bool]:
        uid = item.uid
        if item.message is None:
            if item.skip_reason is not None and "disappeared" in item.skip_reason:
                outcome = "reconciled_missing"
                code = None
            else:
                outcome = "error"
                code = "MessageUnavailable"
            if apply:
                run = self.progress_store.record_result(
                    run.id,
                    uid=uid,
                    outcome=outcome,
                    error_code=code,
                )
            return ProcessedMessage(uid, outcome, error_code=code), run, False

        try:
            plan = evaluator.plan(mailbox.folder, item.message, self.rules, rule_scope=rule_scope)
        except Exception as exc:
            code = _safe_error_code(exc)
            if apply:
                run = self.progress_store.record_result(run.id, uid=uid, outcome="error", error_code=code)
            return ProcessedMessage(uid, "error", error_code=code), run, False

        if not _plan_matches_run(
            plan,
            folder=mailbox.folder,
            uid=uid,
            run=run,
            rule_scope=rule_scope,
            rules=self.rules,
        ):
            if apply:
                run = self.progress_store.record_result(
                    run.id,
                    uid=uid,
                    outcome="error",
                    error_code="InvalidRoutingPlan",
                )
            return ProcessedMessage(uid, "error", plan=plan, error_code="InvalidRoutingPlan"), run, False

        if any(result.state is EvaluationState.ERROR for result in plan.rule_results):
            if apply:
                run = self.progress_store.record_result(
                    run.id,
                    uid=uid,
                    outcome="error",
                    winner_rule_id=None,
                    destination=None,
                    model=plan.model,
                    request_id=plan.request_id,
                    error_code="RuleEvaluationError",
                )
            return ProcessedMessage(uid, "error", plan=plan, error_code="RuleEvaluationError"), run, False

        if plan.destination is None:
            outcome = "no_match"
            if apply:
                run = self.progress_store.record_result(
                    run.id,
                    uid=uid,
                    outcome=outcome,
                    model=plan.model,
                    request_id=plan.request_id,
                )
            return ProcessedMessage(uid, outcome, plan=plan), run, False

        outcome = "fallback" if plan.winner_rule_id is None else "match"
        if not apply:
            return ProcessedMessage(uid, outcome, plan=plan, destination=plan.destination), run, False

        try:
            moved = mailbox.move_uid(uid, plan.destination)
        except PartialMoveError:
            run = self.progress_store.record_result(
                run.id,
                uid=uid,
                outcome="error",
                winner_rule_id=plan.winner_rule_id,
                destination=plan.destination,
                model=plan.model,
                request_id=plan.request_id,
                error_code="PartialMoveError",
            )
            return (
                ProcessedMessage(
                    uid,
                    "error",
                    plan=plan,
                    destination=plan.destination,
                    error_code="PartialMoveError",
                ),
                run,
                True,
            )
        except Exception as exc:
            code = _safe_error_code(exc)
            run = self.progress_store.record_result(
                run.id,
                uid=uid,
                outcome="error",
                winner_rule_id=plan.winner_rule_id,
                destination=plan.destination,
                model=plan.model,
                request_id=plan.request_id,
                error_code=code,
            )
            return (
                ProcessedMessage(
                    uid,
                    "error",
                    plan=plan,
                    destination=plan.destination,
                    error_code=code,
                ),
                run,
                False,
            )

        if uid not in moved.moved:
            run = self.progress_store.record_result(
                run.id,
                uid=uid,
                outcome="error",
                winner_rule_id=plan.winner_rule_id,
                destination=plan.destination,
                model=plan.model,
                request_id=plan.request_id,
                error_code="MoveUnconfirmed",
            )
            return (
                ProcessedMessage(
                    uid,
                    "error",
                    plan=plan,
                    destination=plan.destination,
                    error_code="MoveUnconfirmed",
                ),
                run,
                True,
            )

        run = self.progress_store.record_result(
            run.id,
            uid=uid,
            outcome=outcome,
            winner_rule_id=plan.winner_rule_id,
            destination=plan.destination,
            applied=True,
            confirmed=True,
            model=plan.model,
            request_id=plan.request_id,
        )
        return (
            ProcessedMessage(
                uid,
                outcome,
                plan=plan,
                destination=plan.destination,
                applied=True,
                confirmed=True,
            ),
            run,
            False,
        )

    def _retry(
        self,
        mailbox: ProcessingMailbox,
        evaluator: SemanticRoutingEvaluator,
        *,
        fingerprint: str,
        mode: RunMode,
        rule_scope: str | None,
        sort_direction: SortDirection,
        limit: int | None,
        metadata: MailboxRunMetadata,
        on_result: Callable[[ProcessedMessage, ProgressRun], None] | None,
        should_stop: Callable[[], bool] | None,
    ) -> ProcessingReport:
        candidates = self.progress_store.list_runs(
            account_key=self.account_key,
            source_folder=mailbox.folder,
            limit=1000,
        )
        run = next(
            (
                candidate
                for candidate in candidates
                if candidate.mode == mode
                and candidate.rule_scope == rule_scope
                and candidate.rules_fingerprint == fingerprint
                and candidate.status in {"active", "completed"}
                and candidate.error_count > 0
            ),
            None,
        )
        if run is None:
            raise ProcessingError("no retryable errors match the current rules and scope")
        if run.uidvalidity != metadata.uidvalidity:
            self.progress_store.invalidate_run(run.id)
            raise ProgressResumeError("UIDVALIDITY changed; retry requires reconciliation")
        if run.high_watermark_uid > metadata.high_watermark_uid:
            raise ProgressResumeError("mailbox UIDNEXT is behind the run high-watermark")
        if run.sort_direction != sort_direction:
            raise ProcessingError("retry sort direction must match the original run")

        was_completed = run.status == "completed"
        uids = self.progress_store.retry_errors(run.id, limit=limit)
        if not uids:
            return ProcessingReport(run, (), preview=False, retry_only=True, exhausted=True)
        messages: list[ProcessedMessage] = []
        items = {item.uid: item for item in mailbox.fetch_items(uids, high_watermark_uid=run.high_watermark_uid)}
        for uid in uids:
            if should_stop is not None and should_stop():
                return ProcessingReport(
                    run,
                    tuple(messages),
                    preview=False,
                    retry_only=True,
                    exhausted=False,
                    stopped_by_user=True,
                )
            result, run, stopped = self._process_one(
                mailbox,
                evaluator,
                items.get(uid, MailboxItem(uid, skip_reason="message disappeared before body fetch")),
                run=run,
                rule_scope=rule_scope,
                apply=True,
            )
            messages.append(result)
            if on_result is not None:
                on_result(result, run)
            if stopped:
                return ProcessingReport(
                    run,
                    tuple(messages),
                    preview=False,
                    retry_only=True,
                    exhausted=False,
                    stopped_on_ambiguous_move=True,
                )
        if was_completed:
            run = self.progress_store.complete_run(run.id)
        return ProcessingReport(run, tuple(messages), preview=False, retry_only=True, exhausted=was_completed)

    def _destinations(self, folder: str, rule_scope: str | None) -> tuple[str, ...]:
        rules = self.rules.enabled_rules(folder)
        if rule_scope is not None:
            rules = tuple(rule for rule in rules if rule.id == rule_scope)
        destinations = [rule.destination for rule in rules]
        if rule_scope is None and self.rules.fallback_destination is not None:
            destinations.append(self.rules.fallback_destination)
        return tuple(dict.fromkeys(destinations))


def _plan_matches_run(
    plan: RoutingPlan,
    *,
    folder: str,
    uid: int,
    run: ProgressRun,
    rule_scope: str | None,
    rules: RuleSet,
) -> bool:
    if (
        plan.folder != folder
        or plan.uid != uid
        or plan.mode != run.mode
        or plan.rules_fingerprint != run.rules_fingerprint
    ):
        return False
    candidates = rules.enabled_rules(folder)
    if rule_scope is not None:
        candidates = tuple(rule for rule in candidates if rule.id == rule_scope)
    if tuple(result.rule_id for result in plan.rule_results) != tuple(rule.id for rule in candidates):
        return False
    if any(result.state is EvaluationState.ERROR for result in plan.rule_results):
        return plan.winner_rule_id is None and plan.destination is None
    if plan.winner_rule_id is not None:
        winner = next((rule for rule in candidates if rule.id == plan.winner_rule_id), None)
        first_match = next(
            (result.rule_id for result in plan.rule_results if result.state is EvaluationState.MATCH),
            None,
        )
        return winner is not None and first_match == winner.id and plan.destination == winner.destination
    if any(result.state is EvaluationState.MATCH for result in plan.rule_results):
        return False
    expected_destination = rules.fallback_destination if run.mode == "full" else None
    return plan.destination == expected_destination


def _safe_error_code(exc: Exception) -> str:
    name = exc.__class__.__name__
    return name if name.isascii() and name.replace("_", "").isalnum() else "ProcessingError"
