from __future__ import annotations

from imapledger.config import ImapSettings, Settings
from imapledger.mail_service import MailService
from imapledger.mailbox import MailboxItem, MessageSort
from imapledger.message import MailSummary, parse_message


def test_mail_service_lists_pages_and_opens_messages_read_only(monkeypatch) -> None:
    summary = MailSummary(7, "sender", "subject", "date", "id", 123, frozenset())
    message = parse_message(7, b"From: sender@example.org\r\nSubject: hello\r\n\r\nbody", max_body_chars=100)

    class FakeBrowserMailbox:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.uidvalidity = 42
            self.message_count = 2

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def fetch_summary_page(self, *, offset, limit, sort):
            assert (offset, limit, sort) == (0, 1, MessageSort.NEWEST)
            return (summary,)

        def fetch_uid(self, uid):
            return MailboxItem(uid, message=message)

    monkeypatch.setattr("imapledger.mail_service.BrowserMailbox", FakeBrowserMailbox)
    service = MailService(
        Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org")),
        "secret",
    )

    page = service.list_messages("INBOX", limit=1)
    detail = service.get_message("INBOX", 7)

    assert page.folder == "INBOX"
    assert page.total == 2
    assert page.items == (summary,)
    assert page.has_next
    assert detail.item.message == message
    assert not hasattr(detail, "persisted_state")
