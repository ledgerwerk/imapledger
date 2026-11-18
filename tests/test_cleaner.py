from contextlib import AbstractContextManager

from imapledger.cleaner import SpamCleaner
from imapledger.mailbox import MailboxItem
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

    def __exit__(self, *args):
        return None


class FakeClassifier:
    def probability(self, message):
        return {1: 0.99, 2: 0.20}[message.uid]


def test_dry_run_never_deletes() -> None:
    mailbox = FakeMailbox(writable=False)
    report = SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(apply=False)
    assert report.scanned == 3
    assert report.spam == 1
    assert report.skipped == 1
    assert report.deleted == 0
    assert mailbox.deleted == []


def test_apply_deletes_only_above_threshold() -> None:
    mailbox = FakeMailbox(writable=True)
    report = SpamCleaner(mailbox, FakeClassifier(), threshold=0.95).run(apply=True)
    assert mailbox.deleted == [1]
    assert report.deleted == 1
    assert report.kept == 1
    assert report.skipped == 1
