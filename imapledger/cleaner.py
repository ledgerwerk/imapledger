from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .classifier import SpamClassifier
from .mailbox import ScopedMailbox

Status = Literal["spam", "keep", "skip", "error"]


@dataclass(slots=True)
class MessageResult:
    uid: int
    subject: str
    sender: str
    probability: float | None
    status: Status
    detail: str | None = None
    deleted: bool = False


@dataclass(slots=True)
class CleanReport:
    folder: str
    threshold: float
    apply: bool
    results: list[MessageResult]

    @property
    def scanned(self) -> int:
        return len(self.results)

    @property
    def spam(self) -> int:
        return sum(row.status == "spam" for row in self.results)

    @property
    def kept(self) -> int:
        return sum(row.status == "keep" for row in self.results)

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
    def __init__(self, mailbox: ScopedMailbox, classifier: SpamClassifier, *, threshold: float) -> None:
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")
        self._mailbox = mailbox
        self._classifier = classifier
        self._threshold = threshold

    def run(self, *, apply: bool) -> CleanReport:
        if apply and not self._mailbox.writable:
            raise ValueError("apply=True requires a writable scoped mailbox")
        rows: list[MessageResult] = []
        approved: list[int] = []

        for item in self._mailbox.iter_messages():
            if item.message is None:
                rows.append(
                    MessageResult(
                        uid=item.uid,
                        subject="",
                        sender="",
                        probability=None,
                        status="skip",
                        detail=item.skip_reason or "message not available",
                    )
                )
                continue

            message = item.message
            try:
                probability = self._classifier.probability(message)
            except Exception as exc:  # fail closed: classifier failures never authorize deletion
                rows.append(
                    MessageResult(
                        uid=message.uid,
                        subject=message.subject,
                        sender=message.sender,
                        probability=None,
                        status="error",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue

            is_spam = probability >= self._threshold
            if is_spam:
                approved.append(message.uid)
            rows.append(
                MessageResult(
                    uid=message.uid,
                    subject=message.subject,
                    sender=message.sender,
                    probability=probability,
                    status="spam" if is_spam else "keep",
                )
            )

        if apply and approved:
            self._mailbox.delete_uids(approved)
            approved_set = set(approved)
            for row in rows:
                if row.uid in approved_set and row.status == "spam":
                    row.deleted = True

        return CleanReport(folder=self._mailbox.folder, threshold=self._threshold, apply=apply, results=rows)
