from contextlib import AbstractContextManager

import pytest

from imapledger.classifier import SpamAssessment
from imapledger.cleaner import SpamCleaner
from imapledger.mailbox import (
    DeleteResult,
    ImapOperationError,
    MailboxItem,
    MessageSelection,
    MessageSort,
    PartialDeleteError,
)
from imapledger.message import MailMessage


class FakeMailbox(AbstractContextManager):
    folder = "Spam"
    def __init__(self, *, writable: bool):
        self.writable = writable
        self.deleted = []
        self.count_selections = []
        self.iter_selections = []
        self.items = [
            MailboxItem(uid=1, message=MailMessage(1, "spam", "a@example.org", (), "", "buy now")),
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


class FakeClassifier:
    def assess(self, message):
        return SpamAssessment(
            probability={1: 0.99, 2: 0.20, 4: 0.99}[message.uid],
            model="model-test",
            request_id=f"request-{message.uid}",
        )



def test_dry_run_never_deletes() -> None:
    mailbox = FakeMailbox(writable=False)
    report = SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(apply=False)
    assert report.scanned == 3
    assert report.spam == 1
    assert report.skipped == 1
    assert report.deleted == 0
    assert mailbox.deleted == []
    assert [row.inclination for row in report.results] == ["DELETE-APPROVED", "KEEP", "SKIP"]
    assert report.results[2].detail == "too large"
    assert report.results[0].model == "model-test"
    assert report.results[0].request_id == "request-1"




def test_result_callback_covers_every_outcome_and_forwards_selection():
    mailbox = FakeMailbox(writable=False)
    mailbox.items.append(MailboxItem(uid=4, message=MailMessage(4, "error", "c@example.org", (), "", "content")))
    selection = MessageSelection(limit=4, offset=1, sort=MessageSort.OLDEST)
    callbacks = []

    class ErrorOnFourth(FakeClassifier):
        def assess(self, message):
            if message.uid == 4:
                raise RuntimeError("classifier failed")
            return super().assess(message)

    report = SpamCleaner(mailbox, ErrorOnFourth(), threshold=0.95).run(
        apply=False,
        selection=selection,
        on_result=lambda row, position, total: callbacks.append((row, position, total)),
    )

    assert [row.status for row in report.results] == ["spam", "keep", "skip", "error"]
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
        SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(
            apply=True,
            on_result=lambda row, position, total: callbacks.append((row, position, total)),
        )

    assert [(row.uid, position, total) for row, position, total in callbacks] == [(1, 1, 3)]
    assert mailbox.deleted == []

def test_apply_deletes_only_above_threshold() -> None:
    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(apply=True)
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
    report = SpamCleaner(mailbox, FailingClassifier(), threshold=0.95).run(apply=True)

    error_row = report.results[0]
    assert error_row.status == "error"
    assert error_row.inclination == "ERROR / KEEP"
    assert error_row.detail == "RuntimeError: classifier evaluation failed"
    assert mailbox.deleted == []



class PartialFakeMailbox(FakeMailbox):
    def __init__(self, *, writable: bool):
        super().__init__(writable=writable)
        self.items.append(MailboxItem(uid=4, message=MailMessage(4, "spam", "c@example.org", (), "", "spam")))

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
    report = SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(apply=True)

    rows = {row.uid: row for row in report.results}
    assert report.partial_delete_error is not None
    assert report.deleted == 1
    assert rows[1].deleted is True
    assert rows[4].deleted is False
    assert rows[4].detail == "Deletion was not confirmed; see the operation error."
