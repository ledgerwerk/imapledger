from contextlib import AbstractContextManager

import pytest

from imapledger.classifier import SemanticSpamSignals, SpamAssessment
from imapledger.cleaner import SpamCleaner
from imapledger.evidence import build_message_evidence
from imapledger.mailbox import (
    DeleteResult,
    ImapOperationError,
    MailboxItem,
    MessageSelection,
    MessageSort,
    PartialDeleteError,
)
from imapledger.message import MailMessage
from imapledger.policy import SpamVerdict


class FakeMailbox(AbstractContextManager):
    folder = "Spam"

    def __init__(self, *, writable: bool):
        self.writable = writable
        self.deleted = []
        self.count_selections = []
        self.iter_selections = []
        self.items = [
            MailboxItem(uid=1, message=MailMessage(1, "phish", "a@example.org", (), "", "buy now")),
            MailboxItem(uid=2, message=MailMessage(2, "real", "b@example.org", (), "", "hello")),
            MailboxItem(uid=3, skip_reason="too large"),
        ]

    def selected_count(self, selection):
        self.count_selections.append(selection)
        return len(self.items)

    def iter_messages(self, selection=None):
        self.iter_selections.append(selection)
        yield from self.items

    def delete_uids(self, uids):
        self.deleted.extend(uids)
        return DeleteResult(deleted=tuple(uids))

    def __exit__(self, *args):
        return None


def _signals(uid: int) -> SemanticSpamSignals:
    if uid in {1, 4}:
        return SemanticSpamSignals(0.10, 0.99, 0.10, 0.10, 0.10)
    if uid == 2:
        return SemanticSpamSignals(0.10, 0.10, 0.10, 0.90, 0.99)
    return SemanticSpamSignals(0.10, 0.10, 0.10, 0.10, 0.10)


def _assessment(message: MailMessage) -> SpamAssessment:
    return SpamAssessment(
        signals=_signals(message.uid),
        evidence=build_message_evidence(message),
        model="model-test",
        request_id=f"request-{message.uid}",
    )


class FakeClassifier:
    def assess(self, message):
        return _assessment(message)


def test_dry_run_never_deletes_and_records_verdict_details() -> None:
    mailbox = FakeMailbox(writable=False)
    report = SpamCleaner(mailbox, FakeClassifier()).run(apply=False)

    assert report.scanned == 3
    assert report.spam == 1
    assert report.kept == 1
    assert report.review == 0
    assert report.skipped == 1
    assert report.deleted == 0
    assert mailbox.deleted == []
    assert [row.inclination for row in report.results] == ["DELETE-APPROVED", "KEEP", "SKIP"]
    assert report.results[2].detail == "too large"
    assert report.results[0].verdict is SpamVerdict.DELETE
    assert report.results[0].signals.phishing_or_scam == 0.99
    assert report.results[0].model == "model-test"
    assert report.results[0].request_id == "request-1"


def test_review_is_a_separate_non_destructive_outcome() -> None:
    class ReviewClassifier:
        def assess(self, message):
            return SpamAssessment(
                signals=SemanticSpamSignals(0.1, 0.1, 0.1, 0.1, 0.99),
                evidence=build_message_evidence(message),
            )

    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, ReviewClassifier()).run(apply=True)

    assert report.review == 2
    assert all(row.status == "review" for row in report.results[:2])
    assert all(row.inclination == "REVIEW / KEEP" for row in report.results[:2])
    assert mailbox.deleted == []


def test_result_callback_covers_every_outcome_and_forwards_selection():
    mailbox = FakeMailbox(writable=False)
    mailbox.items.append(MailboxItem(uid=4, message=MailMessage(4, "review", "c@example.org", (), "", "content")))
    selection = MessageSelection(limit=4, offset=1, sort=MessageSort.OLDEST)
    callbacks = []

    class ErrorOnFourth(FakeClassifier):
        def assess(self, message):
            if message.uid == 4:
                raise RuntimeError("classifier failed")
            return super().assess(message)

    report = SpamCleaner(mailbox, ErrorOnFourth()).run(
        apply=False,
        selection=selection,
        on_result=lambda row, position, total: callbacks.append((row, position, total)),
    )

    assert [row.status for row in report.results] == ["delete", "keep", "skip", "error"]
    assert [row for row, _, _ in callbacks] == report.results
    assert [position for _, position, _ in callbacks] == [1, 2, 3, 4]
    assert [total for _, _, total in callbacks] == [4, 4, 4, 4]
    assert mailbox.count_selections == [selection]
    assert mailbox.iter_selections == [selection]
    assert mailbox.count_selections[0] is selection
    assert mailbox.iter_selections[0] is selection


def test_result_callback_fires_before_scan_completion():
    class StoppingMailbox(FakeMailbox):
        def iter_messages(self, selection=None):
            self.iter_selections.append(selection)
            yield self.items[0]
            raise RuntimeError("scan interrupted")

    mailbox = StoppingMailbox(writable=True)
    callbacks = []
    with pytest.raises(RuntimeError, match="scan interrupted"):
        SpamCleaner(mailbox, FakeClassifier()).run(
            apply=True,
            on_result=lambda row, position, total: callbacks.append((row, position, total)),
        )

    assert [(row.uid, position, total) for row, position, total in callbacks] == [(1, 1, 3)]
    assert mailbox.deleted == []


def test_apply_deletes_only_delete_verdict_uids() -> None:
    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FakeClassifier()).run(apply=True)

    assert mailbox.deleted == [1]
    assert report.deleted == 1
    assert report.kept == 1
    assert report.skipped == 1
    assert [row.inclination for row in report.results] == ["DELETE-APPROVED", "KEEP", "SKIP"]


class FailingClassifier:
    def assess(self, message):
        raise RuntimeError("model error containing private message content")


def test_classifier_error_fails_closed_and_detail_is_safe() -> None:
    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FailingClassifier()).run(apply=True)

    error_row = report.results[0]
    assert error_row.status == "error"
    assert error_row.inclination == "ERROR / KEEP"
    assert error_row.detail == "RuntimeError: classification evaluation failed"
    assert mailbox.deleted == []


class PartialFakeMailbox(FakeMailbox):
    def __init__(self, *, writable: bool):
        super().__init__(writable=writable)
        self.items.append(MailboxItem(uid=4, message=MailMessage(4, "phish", "c@example.org", (), "", "spam")))

    def delete_uids(self, uids):
        self.deleted.extend(uids)
        failure = ImapOperationError(
            operation="imap_uid_expunge",
            message="UID EXPUNGE failed",
            folder="Spam",
            uids=(4,),
            batch=2,
            batch_count=2,
            cause_type="RuntimeError",
        )
        raise PartialDeleteError(deleted=(1,), pending=(4,), failure=failure) from failure


def test_partial_delete_marks_only_confirmed_uids_deleted():
    mailbox = PartialFakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FakeClassifier()).run(apply=True)

    rows = {row.uid: row for row in report.results}
    assert report.partial_delete_error is not None
    assert report.deleted == 1
    assert rows[1].deleted is True
    assert rows[4].deleted is False
    assert rows[4].detail == "Deletion was not confirmed; see the operation error."
