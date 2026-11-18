from contextlib import AbstractContextManager

from imapledger.classifier import SpamAssessment
from imapledger.cleaner import SpamCleaner
from imapledger.mailbox import DeleteResult, ImapOperationError, MailboxItem, PartialDeleteError
from imapledger.message import MailMessage


class FakeMailbox(AbstractContextManager):
    folder = "Spam"

    def __init__(self, *, writable: bool):
        self.writable = writable
        self.deleted = []

    def iter_messages(self):
        yield MailboxItem(uid=1, message=MailMessage(1, "spam", "a@example.org", (), "", "buy now"))
        yield MailboxItem(uid=2, message=MailMessage(2, "real", "b@example.org", (), "", "hello"))
        yield MailboxItem(uid=3, skip_reason="too large")

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
    def iter_messages(self):
        yield from super().iter_messages()
        yield MailboxItem(uid=4, message=MailMessage(4, "spam", "c@example.org", (), "", "spam"))

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
