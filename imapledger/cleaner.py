from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from .classifier import SemanticSpamSignals, SpamClassifier
from .evidence import MessageEvidence
from .mailbox import DeleteResult, MailboxItem, MessageSelection, PartialDeleteError
from .policy import SpamPolicy, SpamVerdict

Status = Literal["delete", "keep", "review", "skip", "error"]
Inclination = Literal["DELETE-APPROVED", "KEEP", "REVIEW / KEEP", "SKIP", "ERROR / KEEP"]


class Mailbox(Protocol):
    @property
    def folder(self) -> str: ...

    @property
    def writable(self) -> bool: ...

    def selected_count(self, selection: MessageSelection) -> int: ...

    def iter_messages(self, selection: MessageSelection) -> Iterator[MailboxItem]: ...

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
    detail: str | None = None
    deleted: bool = False
    model: str | None = None
    request_id: str | None = None


ResultCallback = Callable[[MessageResult, int, int], None]


@dataclass(slots=True)
class CleanReport:
    folder: str
    apply: bool
    results: list[MessageResult]
    partial_delete_error: PartialDeleteError | None = None

    @property
    def scanned(self) -> int:
        return len(self.results)

    @property
    def spam(self) -> int:
        return sum(row.status == "delete" for row in self.results)

    @property
    def kept(self) -> int:
        return sum(row.status == "keep" for row in self.results)

    @property
    def review(self) -> int:
        return sum(row.status == "review" for row in self.results)

    @property
    def skipped(self) -> int:
        return sum(row.status == "skip" for row in self.results)

    @property
    def errors(self) -> int:
        return sum(row.status == "error" for row in self.results)

    @property
    def deleted(self) -> int:
        return sum(row.deleted for row in self.results)


class SpamCleaner:
    def __init__(self, mailbox: Mailbox, classifier: SpamClassifier, *, policy: SpamPolicy | None = None) -> None:
        self._mailbox = mailbox
        self._classifier = classifier
        self._policy = policy or SpamPolicy()

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
        rows: list[MessageResult] = []
        approved: list[int] = []

        def record(row: MessageResult) -> None:
            rows.append(row)
            if on_result is not None:
                on_result(row, len(rows), total)

        for item in self._mailbox.iter_messages(selection):
            if item.message is None:
                record(
                    MessageResult(
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
                )
                continue

            message = item.message
            try:
                assessment = self._classifier.assess(message)
                evidence: MessageEvidence = assessment.evidence
                decision = self._policy.decide(assessment.signals, evidence)
            except Exception as exc:  # Fail closed: assessment and policy failures never authorize deletion.
                record(
                    MessageResult(
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
                )
                continue

            status = decision.verdict.value
            inclination: Inclination = {
                SpamVerdict.DELETE: "DELETE-APPROVED",
                SpamVerdict.KEEP: "KEEP",
                SpamVerdict.REVIEW: "REVIEW / KEEP",
            }[decision.verdict]
            if decision.verdict is SpamVerdict.DELETE:
                approved.append(message.uid)
            record(
                MessageResult(
                    uid=message.uid,
                    subject=message.subject,
                    sender=message.sender,
                    verdict=decision.verdict,
                    signals=assessment.signals,
                    reasons=decision.reasons,
                    status=status,
                    inclination=inclination,
                    model=assessment.model,
                    request_id=assessment.request_id,
                )
            )

        partial_delete_error = None
        if apply and approved:
            try:
                deletion = self._mailbox.delete_uids(approved)
            except PartialDeleteError as exc:
                partial_delete_error = exc
                confirmed_deleted = set(exc.deleted)
                pending = set(exc.pending)
                for row in rows:
                    if row.uid in pending and row.status == "delete":
                        row.detail = "Deletion was not confirmed; see the operation error."
            else:
                confirmed_deleted = set(deletion.deleted)
            for row in rows:
                if row.uid in confirmed_deleted and row.status == "delete":
                    row.deleted = True

        return CleanReport(
            folder=self._mailbox.folder,
            apply=apply,
            results=rows,
            partial_delete_error=partial_delete_error,
        )
