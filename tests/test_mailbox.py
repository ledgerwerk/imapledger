import pytest

from imapledger.mailbox import ScopedMailbox, UnsafeMailboxOperation

RAW = b"From: spammer@example.org\r\nTo: me@example.org\r\nSubject: Buy now\r\n\r\nCheap pills"


class FakeClient:
    def __init__(self, *, capabilities=(b"IMAP4rev1", b"UIDPLUS"), uidvalidity=42, size=None):
        self._capabilities = capabilities
        self.uidvalidity = uidvalidity
        self.size = len(RAW) if size is None else size
        self.selected = []
        self.fetches = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.logged_out = False

    def login(self, username, password):
        self.login_args = (username, password)

    def logout(self):
        self.logged_out = True

    def capabilities(self):
        return self._capabilities

    def select_folder(self, folder, readonly=False):
        self.selected.append((folder, readonly))
        return {b"UIDVALIDITY": self.uidvalidity, b"EXISTS": 1, b"FLAGS": (), b"RECENT": 0}

    def search(self, criteria="ALL", charset=None):
        return [10]

    def fetch(self, messages, data, modifiers=None):
        self.fetches.append((tuple(messages), tuple(data)))
        if tuple(data) == ("RFC822.SIZE",):
            return {10: {b"RFC822.SIZE": self.size}}
        return {10: {b"BODY[]": RAW}}

    def add_flags(self, messages, flags, silent=False):
        self.added.append((tuple(messages), tuple(flags), silent))

    def remove_flags(self, messages, flags, silent=False):
        self.removed.append((tuple(messages), tuple(flags), silent))

    def uid_expunge(self, messages):
        self.expunged.append(tuple(messages))


def factory_for(client):
    return lambda *args, **kwargs: client


def make_mailbox(client, *, writable, max_message_bytes=1_000_000):
    return ScopedMailbox(
        host="imap.example.org",
        port=993,
        username="me@example.org",
        password="secret",
        folder="Spam",
        writable=writable,
        max_message_bytes=max_message_bytes,
        max_body_chars=20_000,
        client_factory=factory_for(client),
    )


def test_writable_mode_requires_uidplus() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1",))
    with pytest.raises(UnsafeMailboxOperation, match="UIDPLUS"):
        with make_mailbox(client, writable=True):
            pass
    assert client.selected == []


def test_dry_run_selects_only_scoped_folder_readonly() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1",))
    with make_mailbox(client, writable=False) as mailbox:
        items = list(mailbox.iter_messages())
    assert [item.uid for item in items] == [10]
    assert items[0].message is not None
    assert client.selected == [("Spam", True)]
    assert client.expunged == []


def test_size_limit_prevents_body_fetch() -> None:
    client = FakeClient(size=10_000)
    with make_mailbox(client, writable=False, max_message_bytes=100) as mailbox:
        items = list(mailbox.iter_messages())
    assert items[0].message is None
    assert "exceeds limit" in (items[0].skip_reason or "")
    assert client.fetches == [((10,), ("RFC822.SIZE",))]


def test_delete_uses_uid_expunge_for_exact_snapshot_uids() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True) as mailbox:
        mailbox.delete_uids([10])
    assert client.selected == [("Spam", False), ("Spam", False)]
    assert client.added == [((10,), ("\\Deleted",), True)]
    assert client.expunged == [(10,)]


def test_delete_rejects_uid_outside_initial_snapshot() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="outside initial"):
            mailbox.delete_uids([999])
    assert client.added == []
    assert client.expunged == []


def test_uidvalidity_change_aborts_before_flagging() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True) as mailbox:
        client.uidvalidity = 43
        with pytest.raises(UnsafeMailboxOperation, match="UIDVALIDITY changed"):
            mailbox.delete_uids([10])
    assert client.added == []
