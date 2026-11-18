from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol

from .classifier import SemanticSpamSignals, SpamClassifier
from .config import ActionKind, MessageAction, SpamActions
from .evidence import MessageEvidence
from .mailbox import DeleteResult, MailboxItem, MessageSelection, MoveResult, PartialDeleteError, PartialMoveError
from .policy import SpamPolicy, SpamVerdict

Status = Literal["delete", "keep", "review", "skip", "error"]
Inclination = Literal["DELETE-APPROVED", "KEEP", "REVIEW / KEEP", "SKIP", "ERROR / KEEP"]


class SpamOutcome(str, Enum):
    SPAM = "spam"
    NOT_SPAM = "not_spam"
    REVIEW = "review"


VERDICT_OUTCOME = {
    SpamVerdict.DELETE: SpamOutcome.SPAM,
    SpamVerdict.KEEP: SpamOutcome.NOT_SPAM,
    SpamVerdict.REVIEW: SpamOutcome.REVIEW,
}


class Mailbox(Protocol):
    @property
    def folder(self) -> str: ...

    @property
    def writable(self) -> bool: ...

    def selected_count(self, selection: MessageSelection) -> int: ...

    def iter_messages(self, selection: MessageSelection) -> Iterator[MailboxItem]: ...

    def move_uid(self, uid: int, destination: str) -> MoveResult: ...

    def delete_uid(self, uid: int) -> DeleteResult: ...
    def move_uids(self, uids: Sequence[int], destination: str) -> MoveResult: ...

    def delete_uids(self, uids: Sequence[int]) -> DeleteResult: ...


@dataclass(slots=True)
class MessageResult:
    uid: int
    subject: str
    sender: str
    verdict: SpamVerdict | None
    signals: SemanticSpamSignals | None
    reasons: tuple[str, ...]
    status: Status
    inclination: Inclination
    action: MessageAction = field(default_factory=lambda: MessageAction(ActionKind.KEEP))
    outcome: SpamOutcome | None = None
    action_applied: bool = False
    detail: str | None = None
    model: str | None = None
    request_id: str | None = None

    @property
    def deleted(self) -> bool:
        return self.action.action is ActionKind.DELETE and self.action_applied


ResultCallback = Callable[[MessageResult, int, int], None]


@dataclass(slots=True)
class CleanReport:
    folder: str
    apply: bool
    results: list[MessageResult]
    partial_delete_error: PartialDeleteError | None = None
    partial_move_error: PartialMoveError | None = None
    action_error: Exception | None = None

    @property
    def scanned(self) -> int:
        return len(self.results)

    @property
    def spam(self) -> int:
        return sum(row.outcome is SpamOutcome.SPAM for row in self.results)

    @property
    def not_spam(self) -> int:
        return sum(row.outcome is SpamOutcome.NOT_SPAM for row in self.results)

    @property
    def kept(self) -> int:
        return self.not_spam

    @property
    def review(self) -> int:
        return sum(row.outcome is SpamOutcome.REVIEW for row in self.results)

    @property
    def skipped(self) -> int:
        return sum(row.status == "skip" for row in self.results)

    @property
    def errors(self) -> int:
        return sum(row.status == "error" for row in self.results)

    @property
    def moved(self) -> int:
        return sum(row.action.action is ActionKind.MOVE and row.action_applied for row in self.results)

    @property
    def deleted(self) -> int:
        return sum(row.deleted for row in self.results)

    @property
    def kept_in_place(self) -> int:
        return sum(row.action.action is ActionKind.KEEP for row in self.results)

    @property
    def mutation_error(self) -> Exception | None:
        return self.partial_move_error or self.partial_delete_error or self.action_error


class SpamCleaner:
    def __init__(
        self,
        mailbox: Mailbox,
        classifier: SpamClassifier,
        *,
        policy: SpamPolicy | None = None,
        actions: SpamActions | None = None,
    ) -> None:
        self._mailbox = mailbox
        self._classifier = classifier
        self._policy = policy or SpamPolicy()
        self._actions = actions or SpamActions()

    def run(
        self,
        *,
        apply: bool,
        selection: MessageSelection | None = None,
        on_result: ResultCallback | None = None,
    ) -> CleanReport:
        if apply and not self._mailbox.writable:
            raise ValueError("apply=True requires a writable scoped mailbox")
        selection = selection or MessageSelection()
        total = self._mailbox.selected_count(selection)
        report = CleanReport(folder=self._mailbox.folder, apply=apply, results=[])

        def notify(row: MessageResult) -> None:
            if on_result is not None:
                on_result(row, len(report.results), total)

        for item in self._mailbox.iter_messages(selection):
            if item.message is None:
                row = MessageResult(
                    uid=item.uid,
                    subject="",
                    sender="",
                    verdict=None,
                    signals=None,
                    reasons=(),
                    status="skip",
                    inclination="SKIP",
                    detail=item.skip_reason or "message not available",
                )
                report.results.append(row)
                notify(row)
                continue

            message = item.message
            try:
                assessment = self._classifier.assess(message)
                evidence: MessageEvidence = assessment.evidence
                decision = self._policy.decide(assessment.signals, evidence)
            except Exception as exc:  # Fail closed: classifier and policy errors never authorize a mutation.
                row = MessageResult(
                    uid=message.uid,
                    subject=message.subject,
                    sender=message.sender,
                    verdict=None,
                    signals=None,
                    reasons=(),
                    status="error",
                    inclination="ERROR / KEEP",
                    detail=f"{type(exc).__name__}: classification evaluation failed",
                )
                report.results.append(row)
                notify(row)
                continue

            outcome = VERDICT_OUTCOME[decision.verdict]
            action = self._action_for(outcome)
            status = decision.verdict.value
            inclination: Inclination = {
                SpamVerdict.DELETE: "DELETE-APPROVED",
                SpamVerdict.KEEP: "KEEP",
                SpamVerdict.REVIEW: "REVIEW / KEEP",
            }[decision.verdict]
            row = MessageResult(
                uid=message.uid,
                subject=message.subject,
                sender=message.sender,
                verdict=decision.verdict,
                signals=assessment.signals,
                reasons=decision.reasons,
                status=status,
                inclination=inclination,
                action=action,
                outcome=outcome,
                model=assessment.model,
                request_id=assessment.request_id,
            )
            report.results.append(row)
            should_continue = True
            if apply and row.action.action is not ActionKind.KEEP:
                should_continue = self._apply_action(report, row)
            notify(row)
            if not should_continue:
                break

        return report

    def _action_for(self, outcome: SpamOutcome) -> MessageAction:
        return getattr(self._actions, outcome.value)

    def _apply_action(self, report: CleanReport, row: MessageResult) -> bool:
        if row.action.action is ActionKind.KEEP:
            row.action_applied = False
            return True

        try:
            if row.action.action is ActionKind.MOVE:
                result = self._mailbox.move_uid(row.uid, row.action.destination or "")
                confirmed = row.uid in result.moved
                action_name = "Move"
            else:
                result = self._mailbox.delete_uid(row.uid)
                confirmed = row.uid in result.deleted
                action_name = "Deletion"
        except PartialMoveError as exc:
            report.partial_move_error = exc
            if row.uid in exc.moved:
                row.action_applied = True
            else:
                row.detail = "Move was not confirmed; see the operation error."
            return False
        except PartialDeleteError as exc:
            report.partial_delete_error = exc
            if row.uid in exc.deleted:
                row.action_applied = True
            else:
                row.detail = "Deletion was not confirmed; see the operation error."
            return False
        except Exception as exc:
            report.action_error = exc
            row.detail = "Action failed before confirmation; see the operation error."
            return False

        if not confirmed:
            report.action_error = RuntimeError(f"{action_name} was not confirmed.")
            row.detail = f"{action_name} was not confirmed; see the operation error."
            return False

        row.action_applied = True
        return True
