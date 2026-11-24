from email import policy
from email.parser import BytesHeaderParser

import pytest

from imapledger.classification_state import SpamOutcome, all_state_keywords, keyword_for_outcome
from imapledger.mailbox import (
    BrowserMailbox,
    DeleteResult,
    FolderCatalog,
    FolderInfo,
    ImapOperationError,
    MessageSelection,
    MessageSort,
    MoveResult,
    PartialDeleteError,
    PartialMoveError,
    ReadOnlyMailbox,
    ScopedMailbox,
    UnsafeMailboxOperation,
)
from tests.fakes import FolderAwareFakeClient
from tests.fakes import raw_message as _folder_raw_message

RAW = b"From: spammer@example.org\r\nTo: me@example.org\r\nSubject: Buy now\r\n\r\nCheap pills"


def _test_flag_bytes(flag):
    return flag if isinstance(flag, bytes) else str(flag).encode("ascii")


class FakeClient:
    def __init__(
        self,
        *,
        capabilities=(b"IMAP4rev1", b"UIDPLUS", b"MOVE"),
        uidvalidity=42,
        size=None,
        uids=None,
        permanent_flags=(b"\\Answered", b"\\Flagged", b"\\Draft", b"\\Deleted", b"\\Seen", b"\\*"),
        flags=None,
    ):
        self._capabilities = capabilities
        self.uidvalidity = uidvalidity
        self.size = len(RAW) if size is None else size
        self.uids = [10] if uids is None else list(uids)
        self.selected = []
        self.selected_folder = None
        self.fetches = []
        self.added = []
        self.removed = []
        self.flags = {uid: set(message_flags) for uid, message_flags in (flags or {}).items()}
        self.permanent_flags = permanent_flags
        self.ignore_flag_store = False
        self.searches = []
        self.expunged = []
        self.moves = []
        self.existing_folders = {"INBOX.Trash", "Spam"}
        self.folder_queries = []
        self.logged_out = False
        self.calls = []
        self.fail_on = None
        self.fail_move_on_call = None
        self.failure_text = "FETCH command error: BAD password=secret raw_message=" + RAW.decode()

    def _maybe_fail(self, operation):
        if self.fail_on == operation or (isinstance(self.fail_on, set) and operation in self.fail_on):
            raise RuntimeError(self.failure_text)

    def login(self, username, password):
        self.calls.append("login")
        self._maybe_fail("login")
        self.login_args = (username, password)

    def logout(self):
        self.calls.append("logout")
        self.logged_out = True

    def capabilities(self):
        self.calls.append("capabilities")
        self._maybe_fail("capabilities")
        return self._capabilities

    def select_folder(self, folder, readonly=False):
        self.calls.append("select")
        self._maybe_fail("select")
        self.selected.append((folder, readonly))
        self.selected_folder = folder
        return {
            b"UIDVALIDITY": self.uidvalidity,
            b"EXISTS": len(self.uids),
            b"FLAGS": (),
            b"PERMANENTFLAGS": self.permanent_flags,
            b"RECENT": 0,
        }

    def folder_exists(self, folder):
        self.calls.append("folder_exists")
        self._maybe_fail("folder_exists")
        self.folder_queries.append(folder)
        return folder in self.existing_folders

    def search(self, criteria="ALL", charset=None):
        self.calls.append("search")
        self.searches.append(criteria)
        self._maybe_fail("search")
        if criteria == "ALL":
            return list(self.uids)
        if isinstance(criteria, (list, tuple)):
            if len(criteria) == 2 and str(criteria[0]).upper() == "UID":
                requested = int(criteria[1])
                return [uid for uid in self.uids if uid == requested]
            if len(criteria) % 2:
                raise AssertionError(f"unsupported search criteria: {criteria!r}")
            found = set(self.uids)
            for operation, argument in zip(criteria[::2], criteria[1::2], strict=True):
                operation = str(operation).upper()
                keyword = argument.decode("ascii") if isinstance(argument, bytes) else str(argument)
                if operation not in {"KEYWORD", "UNKEYWORD"}:
                    raise AssertionError(f"unsupported search criteria: {criteria!r}")
                matching = {
                    uid
                    for uid in self.uids
                    if any(
                        (flag.decode("ascii", errors="replace") if isinstance(flag, bytes) else str(flag)).casefold()
                        == keyword.casefold()
                        for flag in self.flags.get(uid, set())
                    )
                }
                found &= matching if operation == "KEYWORD" else set(self.uids) - matching
            return sorted(found)
        raise AssertionError(f"unsupported search criteria: {criteria!r}")

    def fetch(self, messages, data, modifiers=None):
        messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if data == ("RFC822.SIZE",):
            self._maybe_fail("fetch_size")
            return {uid: {b"RFC822.SIZE": self.size} for uid in messages if uid in self.uids}
        if "RFC822.SIZE" in data and "FLAGS" in data:
            self._maybe_fail("fetch_size")
            return {
                uid: {
                    b"RFC822.SIZE": self.size,
                    b"FLAGS": tuple(self.flags.get(uid, set())),
                }
                for uid in messages
                if uid in self.uids
            }
        if data == ("FLAGS",):
            self._maybe_fail("fetch_flags")
            return {uid: {b"FLAGS": tuple(self.flags.get(uid, set()))} for uid in messages if uid in self.uids}
        if any(str(item).startswith("BODY.PEEK[HEADER.FIELDS") for item in data):
            self._maybe_fail("fetch_headers")
            raw_headers = RAW.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            parsed = BytesHeaderParser(policy=policy.default).parsebytes(raw_headers)
            names = ("From", "Subject", "Date", "Message-ID")
            selected_headers = (
                b"".join(f"{name}: {value}\r\n".encode() for name in names for value in parsed.get_all(name, []))
                + b"\r\n"
            )
            return {
                uid: {b"BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]": selected_headers}
                for uid in messages
                if uid in self.uids
            }
        self._maybe_fail("fetch_body")
        return {uid: {b"BODY[]": RAW} for uid in messages if uid in self.uids}

    def move(self, messages, folder):
        if self.fail_move_on_call == len(self.moves) + 1:
            raise RuntimeError(self.failure_text)
        self._maybe_fail("move")
        self.moves.append((tuple(messages), folder))

        self.uids = [uid for uid in self.uids if uid not in messages]

    def add_flags(self, messages, flags, silent=False):
        self._maybe_fail("add_flags")
        messages = tuple(messages)
        flags = tuple(flags)
        self.added.append((messages, flags, silent))
        if not self.ignore_flag_store:
            for uid in messages:
                if uid in self.uids:
                    self.flags.setdefault(uid, set()).update(_test_flag_bytes(flag).lower() for flag in flags)

    def remove_flags(self, messages, flags, silent=False):
        self._maybe_fail("remove_flags")
        messages = tuple(messages)
        flags = tuple(flags)
        self.removed.append((messages, flags, silent))
        if not self.ignore_flag_store:
            remove = {_test_flag_bytes(flag).lower() for flag in flags}
            for uid in messages:
                self.flags.setdefault(uid, set()).difference_update(remove)

    def uid_expunge(self, messages):
        self._maybe_fail("uid_expunge")
        self.expunged.append(tuple(messages))

        self.uids = [uid for uid in self.uids if uid not in messages]
        self.flags = {uid: flags for uid, flags in self.flags.items() if uid not in messages}


def factory_for(client):
    return lambda *args, **kwargs: client


def make_mailbox(
    client,
    *,
    writable,
    folder="Spam",
    max_message_bytes=1_000_000,
    fetch_batch_size=100,
    mutation_batch_size=100,
    delete_batch_size=None,
    allowed_destinations=(),
    allow_delete=None,
    event_callback=None,
    client_factory=None,
):
    if allow_delete is None:
        allow_delete = writable
    return ScopedMailbox(
        host="imap.example.org",
        port=993,
        username="me@example.org",
        password="secret",
        folder=folder,
        writable=writable,
        max_message_bytes=max_message_bytes,
        max_body_chars=20_000,
        fetch_batch_size=fetch_batch_size,
        mutation_batch_size=mutation_batch_size,
        delete_batch_size=delete_batch_size,
        allowed_destinations=allowed_destinations,
        allow_delete=allow_delete,
        client_factory=client_factory or factory_for(client),
        event_callback=event_callback,
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
    assert client.selected == [("Spam", True), ("Spam", True), ("Spam", True)]
    assert client.expunged == []


def test_missing_configured_source_is_reported_before_select_or_search() -> None:
    client = FakeClient()
    client.existing_folders.remove("Spam")

    with pytest.raises(ImapOperationError) as raised:
        with make_mailbox(client, writable=False, folder="INBOX.Spam"):
            pass

    assert raised.value.operation == "imap_source_folder_missing"
    assert raised.value.folder == "INBOX.Spam"
    assert "folder='INBOX.Spam'" in str(raised.value)
    assert client.folder_queries == ["INBOX.Spam"]
    assert client.selected == []
    assert "search" not in client.calls
    assert client.fetches == []
    assert client.moves == []
    assert client.added == []
    assert client.expunged == []
    assert client.logged_out
    assert client.calls == ["login", "capabilities", "folder_exists", "logout"]


def test_source_existence_probe_error_is_safe_and_logs_out() -> None:
    client = FakeClient()
    client.fail_on = "folder_exists"

    with pytest.raises(ImapOperationError) as raised:
        with make_mailbox(client, writable=False):
            pass

    rendered = str(raised.value)
    assert raised.value.operation == "imap_source_folder_exists"
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered
    assert client.selected == []
    assert client.logged_out


def test_existing_source_select_failure_has_distinct_message() -> None:
    client = FakeClient()
    client.fail_on = "select"

    with pytest.raises(ImapOperationError) as raised:
        with make_mailbox(client, writable=False):
            pass

    rendered = str(raised.value)
    assert raised.value.operation == "imap_select_folder"
    assert raised.value.message == "configured source folder exists but could not be selected"
    assert "folder='Spam'" in rendered
    assert client.folder_queries == ["Spam"]
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered
    assert client.logged_out


def test_source_existence_check_precedes_select_and_search() -> None:
    client = FakeClient()
    client.existing_folders.add("INBOX.Spam")

    with make_mailbox(client, writable=False, folder="INBOX.Spam"):
        pass

    assert client.calls == ["login", "capabilities", "folder_exists", "select", "search", "logout"]
    assert client.folder_queries == ["INBOX.Spam"]
    assert client.selected == [("INBOX.Spam", True)]


def test_size_limit_prevents_body_fetch() -> None:
    client = FakeClient(size=10_000)
    with make_mailbox(client, writable=False, max_message_bytes=100) as mailbox:
        items = list(mailbox.iter_messages())
    assert items[0].message is None
    assert "exceeds limit" in (items[0].skip_reason or "")
    assert client.fetches == [((10,), ("RFC822.SIZE",))]


def test_fetch_uid_reads_only_requested_uid_and_uses_body_peek() -> None:
    client = FakeClient(uids=[10, 20])
    with make_mailbox(client, writable=False) as mailbox:
        item = mailbox.fetch_uid(20)

    assert item.uid == 20
    assert item.message is not None and item.message.uid == 20
    assert client.fetches == [((20,), ("RFC822.SIZE",)), ((20,), ("BODY.PEEK[]",))]
    assert client.added == []


def test_browser_mailbox_exact_open_avoids_full_snapshot_and_fetches_flags_with_size() -> None:
    client = FakeClient(uids=range(1, 100_001))
    browser = BrowserMailbox(
        host="imap.example.org",
        port=993,
        username="user",
        password="secret",
        folder="Spam",
        max_message_bytes=10_000,
        max_body_chars=100,
        client_factory=factory_for(client),
    )

    with browser:
        item, state = browser.fetch_uid(10)

    assert item.message is not None
    assert state is not None and state.outcome is None
    assert "ALL" not in client.searches
    assert client.fetches[0] == ((10,), ("RFC822.SIZE", "FLAGS"))
    assert client.fetches[1] == ((10,), ("BODY.PEEK[]",))
    assert client.selected == [("Spam", True)]


def test_browser_page_fetches_only_requested_summaries() -> None:
    client = FakeClient(uids=range(1, 101))
    browser = BrowserMailbox(
        host="imap.example.org",
        port=993,
        username="user",
        password="secret",
        folder="Spam",
        max_message_bytes=10_000,
        max_body_chars=100,
        client_factory=factory_for(client),
    )

    with browser:
        uids = browser.list_page_uids(offset=0, limit=5)
        browser.fetch_summaries(uids)

    assert len(uids) == 5
    assert client.searches == ["ALL"]
    assert client.fetches[0][0] == tuple(uids)
    assert client.removed == []


def test_destination_probe_does_not_redirect_fetch_uid_to_another_folder():
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {10: _folder_raw_message("source message", "spam@example.org")},
            "INBOX.Trash": {10: _folder_raw_message("destination message", "trash@example.org")},
        }
    )
    with make_mailbox(
        client,
        writable=False,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
    ) as mailbox:
        assert mailbox.destination_exists("INBOX.Trash")
        item = mailbox.fetch_uid(10)

    assert item.message is not None
    assert item.message.sender == "spam@example.org"
    assert item.message.subject == "source message"
    assert client.selected[-1] == ("INBOX.spam", True)


def test_iter_messages_remains_source_scoped_after_destination_probe():
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {11: _folder_raw_message("source message", "spam@example.org")},
            "INBOX.Trash": {11: _folder_raw_message("destination message", "trash@example.org")},
        }
    )
    with make_mailbox(
        client,
        writable=False,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
    ) as mailbox:
        assert mailbox.destination_exists("INBOX.Trash")
        item = next(mailbox.iter_messages())

    assert item.message is not None
    assert item.message.sender == "spam@example.org"
    assert item.message.subject == "source message"


def test_streaming_move_drift_does_not_redirect_next_generator_fetch():
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {
                10: _folder_raw_message("source first", "first@example.org"),
                11: _folder_raw_message("source second", "second@example.org"),
            },
            "INBOX.Trash": {
                10: _folder_raw_message("old first", "old-first@example.org"),
                11: _folder_raw_message("old second", "old-second@example.org"),
            },
        }
    )
    with make_mailbox(
        client,
        writable=True,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        messages = mailbox.iter_messages(MessageSelection(sort=MessageSort.OLDEST))
        first = next(messages)
        assert first.message is not None and first.message.subject == "source first"
        mailbox.move_uid(first.uid, "INBOX.Trash")
        second = next(messages)

    assert second.uid == 11
    assert second.message is not None
    assert second.message.sender == "second@example.org"
    assert second.message.subject == "source second"


def test_streaming_move_search_and_action_use_reselected_source():
    source_message = _folder_raw_message("source message", "spam@example.org")
    destination_message = _folder_raw_message("destination message", "trash@example.org")
    client = FolderAwareFakeClient({"INBOX.spam": {10: source_message}, "INBOX.Trash": {10: destination_message}})
    with make_mailbox(
        client,
        writable=True,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        client.selected_folder = "INBOX.Trash"
        result = mailbox.move_uid(10, "INBOX.Trash")

    assert result == MoveResult(moved=(10,), destination="INBOX.Trash")
    assert client.searches == ["ALL", ["UID", 10]]
    assert client.moves == [((10,), "INBOX.Trash")]
    assert client.folders["INBOX.Trash"][10] == source_message
    assert client.selected[-1] == ("INBOX.spam", False)


def test_streaming_delete_search_and_action_use_reselected_source():
    destination_message = _folder_raw_message("destination message", "trash@example.org")
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {10: _folder_raw_message("source message", "spam@example.org")},
            "INBOX.Trash": {10: destination_message},
        }
    )
    with make_mailbox(client, writable=True, folder="INBOX.spam", allow_delete=True) as mailbox:
        client.selected_folder = "INBOX.Trash"
        result = mailbox.delete_uid(10)

    assert result == DeleteResult(deleted=(10,))
    assert client.searches == ["ALL", ["UID", 10]]
    assert client.folders["INBOX.spam"] == {}
    assert client.folders["INBOX.Trash"][10] == destination_message
    assert client.expunged == [(10,)]


def test_fetch_aborts_if_uidvalidity_changes_after_destination_probe():
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {10: _folder_raw_message("source message", "spam@example.org")},
            "INBOX.Trash": {},
        }
    )
    with make_mailbox(
        client,
        writable=False,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
    ) as mailbox:
        assert mailbox.destination_exists("INBOX.Trash")
        client.uidvalidities["INBOX.spam"] = 43
        with pytest.raises(UnsafeMailboxOperation, match="UIDVALIDITY changed"):
            mailbox.fetch_uid(10)

    assert client.fetches == []


@pytest.mark.parametrize("operation", ["move", "delete"])
def test_streaming_mutation_aborts_on_uidvalidity_change_before_search_or_action(operation):
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {10: _folder_raw_message("source message", "spam@example.org")},
            "INBOX.Trash": {},
        }
    )
    with make_mailbox(
        client,
        writable=True,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
        allow_delete=operation == "delete",
    ) as mailbox:
        client.uidvalidities["INBOX.spam"] = 43
        with pytest.raises(UnsafeMailboxOperation, match="UIDVALIDITY changed"):
            if operation == "move":
                mailbox.move_uid(10, "INBOX.Trash")
            else:
                mailbox.delete_uid(10)

    assert client.searches == ["ALL"]
    assert client.moves == []
    assert client.added == []
    assert client.expunged == []


def test_batch_move_reselects_source_between_batches_after_selection_drift():
    source_first = _folder_raw_message("source first", "first@example.org")
    source_second = _folder_raw_message("source second", "second@example.org")
    client = FolderAwareFakeClient(
        {
            "INBOX.spam": {10: source_first, 11: source_second},
            "INBOX.Trash": {},
        }
    )
    with make_mailbox(
        client,
        writable=True,
        folder="INBOX.spam",
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
        mutation_batch_size=1,
    ) as mailbox:
        result = mailbox.move_uids((10, 11), "INBOX.Trash")

    assert result.moved == (10, 11)
    assert client.folders["INBOX.Trash"] == {10: source_first, 11: source_second}
    assert client.moves == [((10,), "INBOX.Trash"), ((11,), "INBOX.Trash")]
    assert client.selected[-1] == ("INBOX.spam", False)


@pytest.mark.parametrize("operation", ["fetch", "move"])
def test_source_reselection_failure_aborts_read_or_mutation(operation):
    client = FakeClient()
    with make_mailbox(
        client,
        writable=operation == "move",
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        client.fail_on = "select"
        with pytest.raises(ImapOperationError) as raised:
            if operation == "fetch":
                mailbox.fetch_uid(10)
            else:
                mailbox.move_uid(10, "INBOX.Trash")

    assert raised.value.operation == "imap_prefetch_select" if operation == "fetch" else "imap_premove_select"
    assert client.fetches == []
    assert client.searches == ["ALL"]
    assert client.moves == []


def test_destination_probe_failure_remains_primary_when_source_restore_fails():
    client = FakeClient()
    with make_mailbox(
        client,
        writable=False,
        allowed_destinations=("INBOX.Trash",),
    ) as mailbox:
        client.fail_on = {"folder_exists", "select"}
        with pytest.raises(ImapOperationError) as raised:
            mailbox.destination_exists("INBOX.Trash")

    assert raised.value.operation == "imap_folder_exists"
    assert "password=secret" not in str(raised.value)
    assert RAW.decode() not in str(raised.value)


def test_fetch_uid_rejects_invalid_and_missing_uids() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=False) as mailbox:
        for uid in (0, -1, True, 10.0):
            with pytest.raises(ValueError, match="positive integer"):
                mailbox.fetch_uid(uid)  # type: ignore[arg-type]
        with pytest.raises(UnsafeMailboxOperation, match="initial mailbox snapshot"):
            mailbox.fetch_uid(11)

    assert client.fetches == []


def test_fetch_uid_skips_oversized_message_without_fetching_body() -> None:
    client = FakeClient(size=10_000)
    with make_mailbox(client, writable=False, max_message_bytes=100) as mailbox:
        item = mailbox.fetch_uid(10)

    assert item.message is None
    assert "exceeds limit" in (item.skip_reason or "")
    assert client.fetches == [((10,), ("RFC822.SIZE",))]


def test_fetch_uid_errors_are_contextual_and_sanitized() -> None:
    client = FakeClient()
    client.fail_on = "fetch_size"
    with make_mailbox(client, writable=False) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.fetch_uid(10)

    assert raised.value.operation == "imap_fetch_size"
    assert "uid=10" in str(raised.value)
    assert "secret" not in str(raised.value)
    assert "Cheap pills" not in str(raised.value)


def test_delete_uses_uid_expunge_for_exact_snapshot_uids() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True) as mailbox:
        mailbox.delete_uids([10])
    assert client.selected == [("Spam", False), ("Spam", False)]
    assert client.added == [((10,), ("\\Deleted",), True)]
    assert client.expunged == [(10,)]


def test_streaming_move_reselects_source_before_exact_uid_validation():
    client = FakeClient(uids=[10, 20])
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        first = mailbox.move_uid(10, "INBOX.Trash")
        second = mailbox.move_uid(20, "INBOX.Trash")

    assert first == MoveResult(moved=(10,), destination="INBOX.Trash")
    assert second == MoveResult(moved=(20,), destination="INBOX.Trash")
    assert client.moves == [((10,), "INBOX.Trash"), ((20,), "INBOX.Trash")]
    assert client.searches == ["ALL", ["UID", 10], ["UID", 20]]
    assert client.selected == [("Spam", False), ("Spam", False), ("Spam", False)]
    assert client.uids == []


def test_streaming_delete_uses_uidplus_and_exact_uid():
    client = FakeClient()
    with make_mailbox(client, writable=True, allow_delete=True) as mailbox:
        result = mailbox.delete_uid(10)

    assert result == DeleteResult(deleted=(10,))
    assert client.searches == ["ALL", ["UID", 10]]
    assert client.selected == [("Spam", False), ("Spam", False)]
    assert client.added == [((10,), ("\\Deleted",), True)]
    assert client.expunged == [(10,)]
    assert client.uids == []


def test_streaming_mutations_preserve_snapshot_and_destination_safety():
    client = FakeClient()
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="outside initial"):
            mailbox.move_uid(999, "INBOX.Trash")
        with pytest.raises(UnsafeMailboxOperation, match="outside the configured allow-list"):
            mailbox.move_uid(10, "INBOX.Other")

    assert client.searches == ["ALL"]
    assert client.moves == []

    source_client = FakeClient()
    with make_mailbox(
        source_client,
        writable=True,
        allowed_destinations=("Spam",),
        allow_delete=False,
    ) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="source folder"):
            mailbox.move_uid(10, "Spam")

    assert source_client.searches == ["ALL"]
    assert source_client.moves == []


def test_streaming_move_requires_writable_scope_and_capability():
    readonly_client = FakeClient()
    with make_mailbox(
        readonly_client,
        writable=False,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="read-only"):
            mailbox.move_uid(10, "INBOX.Trash")

    client = FakeClient()
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        mailbox._capabilities = frozenset((b"IMAP4rev1",))
        with pytest.raises(UnsafeMailboxOperation, match="MOVE disappeared"):
            mailbox.move_uid(10, "INBOX.Trash")

    assert client.moves == []
    assert client.searches == ["ALL"]


def test_streaming_delete_requires_explicit_allow_and_uidplus():
    disallowed_client = FakeClient()
    with make_mailbox(disallowed_client, writable=True, allow_delete=False) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="not allowed"):
            mailbox.delete_uid(10)

    client = FakeClient()
    with make_mailbox(client, writable=True, allow_delete=True) as mailbox:
        mailbox._capabilities = frozenset((b"IMAP4rev1", b"MOVE"))
        with pytest.raises(UnsafeMailboxOperation, match="UIDPLUS disappeared"):
            mailbox.delete_uid(10)

    assert disallowed_client.searches == ["ALL"]
    assert client.searches == ["ALL"]
    assert client.expunged == []


def test_streaming_mutation_rejects_uid_that_disappeared_from_selected_source():
    client = FakeClient()
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        client.uids.clear()
        with pytest.raises(UnsafeMailboxOperation, match="no longer exists"):
            mailbox.move_uid(10, "INBOX.Trash")

    assert client.searches == ["ALL", ["UID", 10]]
    assert client.moves == []
    assert client.selected == [("Spam", False), ("Spam", False)]


def test_streaming_move_failure_is_reported_as_unconfirmed():
    client = FakeClient()
    client.fail_on = "move"
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        with pytest.raises(PartialMoveError) as raised:
            mailbox.move_uid(10, "INBOX.Trash")

    assert raised.value.moved == ()
    assert raised.value.pending == (10,)
    assert raised.value.destination == "INBOX.Trash"
    assert client.searches == ["ALL", ["UID", 10]]
    assert client.moves == []


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


@pytest.mark.parametrize(
    ("failure", "operation"),
    [
        ("login", "imap_login"),
        ("capabilities", "imap_capabilities"),
        ("select", "imap_select_folder"),
        ("search", "imap_search"),
    ],
)
def test_protocol_errors_are_contextual_and_do_not_expose_sensitive_data(failure, operation):
    client = FakeClient()
    client.fail_on = failure
    with pytest.raises(ImapOperationError) as raised:
        with make_mailbox(client, writable=False):
            pass
    rendered = str(raised.value)
    assert f"error [{operation}]" in rendered
    assert "folder='Spam'" in rendered if failure in {"select", "search"} else True
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered
    assert raised.value.__cause__ is not None


def test_size_fetch_is_chunked_for_large_snapshot():
    uids = list(range(1, 10_001))
    client = FakeClient(size=2, uids=uids)
    with make_mailbox(client, writable=False, max_message_bytes=1) as mailbox:
        items = list(mailbox.iter_messages())

    size_fetches = [messages for messages, selector in client.fetches if selector == ("RFC822.SIZE",)]
    assert len(size_fetches) == 100
    assert max(map(len, size_fetches)) == 100
    assert all(len(messages) <= 100 for messages in size_fetches)
    assert [item.uid for item in items] == list(reversed(uids))
    assert all(item.message is None for item in items)
    assert len(client.fetches) == 100


def test_newest_limit_fetches_only_selected_uids():
    client = FakeClient(uids=[1, 2, 3, 4, 5])
    selection = MessageSelection(limit=2)
    with make_mailbox(client, writable=False) as mailbox:
        items = list(mailbox.iter_messages(selection))

    assert [item.uid for item in items] == [5, 4]
    assert [messages for messages, selector in client.fetches if selector == ("RFC822.SIZE",)] == [(5, 4)]
    assert [messages for messages, selector in client.fetches if selector == ("BODY.PEEK[]",)] == [(5,), (4,)]


@pytest.mark.parametrize(
    ("sort", "expected"),
    [
        (MessageSort.NEWEST, [40, 30]),
        (MessageSort.OLDEST, [20, 30]),
    ],
)
def test_offset_is_applied_after_sort(sort, expected):
    client = FakeClient(uids=[10, 20, 30, 40, 50])
    selection = MessageSelection(limit=2, offset=1, sort=sort)
    with make_mailbox(client, writable=False) as mailbox:
        items = list(mailbox.iter_messages(selection))

    assert [item.uid for item in items] == expected


def test_offset_beyond_mailbox_returns_empty_without_fetches():
    client = FakeClient(uids=[1, 2, 3])
    selection = MessageSelection(offset=4)
    with make_mailbox(client, writable=False) as mailbox:
        assert mailbox.selected_count(selection) == 0
        assert list(mailbox.iter_messages(selection)) == []

    assert client.fetches == []


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": -1}, {"offset": -1}])
def test_selection_rejects_invalid_limit_and_offset(kwargs):
    with pytest.raises(ValueError):
        MessageSelection(**kwargs)


def test_selected_size_fetches_remain_chunked_and_exclude_other_uids():
    uids = list(range(1, 10_001))
    client = FakeClient(size=2, uids=uids)
    selection = MessageSelection(limit=150, offset=25)
    with make_mailbox(client, writable=False, max_message_bytes=1, fetch_batch_size=100) as mailbox:
        items = list(mailbox.iter_messages(selection))

    size_fetches = [messages for messages, selector in client.fetches if selector == ("RFC822.SIZE",)]
    expected = tuple(range(9_975, 9_825, -1))
    assert tuple(uid for batch in size_fetches for uid in batch) == expected
    assert len(size_fetches) == 2
    assert max(map(len, size_fetches)) == 100
    assert [item.uid for item in items] == list(expected)
    assert all(selector == ("RFC822.SIZE",) for _, selector in client.fetches)


def test_size_fetch_error_reports_phase_batch_and_uid_range_without_payload():
    client = FakeClient(size=1, uids=[9, 1, 4])
    client.fail_on = "fetch_size"
    with make_mailbox(client, writable=False, fetch_batch_size=2) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            next(mailbox.iter_messages(MessageSelection(sort=MessageSort.OLDEST)))

    rendered = str(raised.value)
    assert "error [imap_fetch_size]" in rendered
    assert "selector=RFC822.SIZE" in rendered
    assert "batch=1/2" in rendered
    assert "uid_count=2" in rendered
    assert "uid_min=1" in rendered and "uid_max=4" in rendered
    assert "server_status=BAD" in rendered
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered


def test_body_fetch_remains_single_uid_and_errors_identify_uid():
    client = FakeClient(size=1, uids=[11, 12])
    client.fail_on = "fetch_body"
    with make_mailbox(client, writable=False) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            next(mailbox.iter_messages(MessageSelection(sort=MessageSort.OLDEST)))

    rendered = str(raised.value)
    assert "error [imap_fetch_body]" in rendered
    assert "selector=BODY.PEEK[]" in rendered
    assert "uid=11" in rendered
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered
    body_fetches = [messages for messages, selector in client.fetches if selector == ("BODY.PEEK[]",)]
    assert body_fetches == [(11,)]


def test_fetch_batch_size_must_be_positive():
    with pytest.raises(ValueError, match="fetch_batch_size must be positive"):
        make_mailbox(FakeClient(), writable=False, fetch_batch_size=0)


def test_verbose_mailbox_events_contain_only_safe_metadata():
    client = FakeClient(size=1)
    events = []
    with make_mailbox(client, writable=False, event_callback=events.append) as mailbox:
        list(mailbox.iter_messages())

    assert any("connect host=imap.example.org port=993 tls=true" in event for event in events)
    assert any("size-fetch batch=1/1 uid_count=1" in event for event in events)
    assert any("body-fetch uid=10" in event for event in events)
    assert all("password" not in event and RAW.decode() not in event for event in events)


def test_delete_error_reports_expunge_and_rollback_failures_without_payload():
    client = FakeClient()
    client.fail_on = {"uid_expunge", "remove_flags"}
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.delete_uids([10])

    rendered = str(raised.value)
    assert "error [imap_uid_expunge]" in rendered
    assert "rollback_error_type=RuntimeError" in rendered
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered

    assert client.added == [((10,), ("\\Deleted",), True)]
    assert client.expunged == []


def test_delete_is_chunked_and_returns_confirmed_uids():
    client = FakeClient(uids=[1, 2, 3, 4, 5])
    with make_mailbox(client, writable=True, delete_batch_size=2) as mailbox:
        result = mailbox.delete_uids([1, 2, 3, 4, 5])

    assert isinstance(result, DeleteResult)
    assert result.deleted == (1, 2, 3, 4, 5)
    assert [item[0] for item in client.added] == [(1, 2), (3, 4), (5,)]
    assert client.expunged == [(1, 2), (3, 4), (5,)]


def test_delete_uids_are_sorted_and_diagnostics_use_true_ranges():
    events = []
    client = FakeClient(uids=[1, 2, 3, 4, 5])
    with make_mailbox(
        client,
        writable=True,
        delete_batch_size=2,
        event_callback=events.append,
    ) as mailbox:
        mailbox.delete_uids([5, 4, 3, 4])

    assert [item[0] for item in client.added] == [(3, 4), (5,)]
    assert client.expunged == [(3, 4), (5,)]
    assert "delete batch=1/2 uid_count=2 uid_min=3 uid_max=4" in events
    assert "delete batch=2/2 uid_count=1 uid_min=5 uid_max=5" in events


def test_partial_delete_reports_only_completed_chunks_and_rolls_back_failing_batch():
    class FailSecondExpunge(FakeClient):
        def uid_expunge(self, messages):
            if len(self.expunged) == 1:
                raise RuntimeError(self.failure_text)
            super().uid_expunge(messages)

    client = FailSecondExpunge(uids=[1, 2, 3, 4, 5])
    with make_mailbox(client, writable=True, delete_batch_size=2) as mailbox:
        with pytest.raises(PartialDeleteError) as raised:
            mailbox.delete_uids([1, 2, 3, 4, 5])

    error = raised.value
    assert error.deleted == (1, 2)
    assert error.pending == (3, 4, 5)
    assert error.operation == "imap_uid_expunge"
    assert error.batch == 2 and error.batch_count == 3
    assert client.expunged == [(1, 2)]
    assert client.removed == [((3, 4), ("\\Deleted",), True)]
    assert "confirmed_deleted_count=2 pending_count=3" in str(error)
    assert "password=secret" not in str(error)
    assert RAW.decode() not in str(error)


def test_store_failure_rolls_back_only_failing_batch():
    class FailSecondStore(FakeClient):
        def add_flags(self, messages, flags, silent=False):
            if len(self.added) == 1:
                self.added.append((tuple(messages), tuple(flags), silent))
                raise RuntimeError(self.failure_text)
            super().add_flags(messages, flags, silent)

    client = FailSecondStore(uids=[1, 2, 3, 4, 5])
    with make_mailbox(client, writable=True, delete_batch_size=2) as mailbox:
        with pytest.raises(PartialDeleteError) as raised:
            mailbox.delete_uids([1, 2, 3, 4, 5])

    assert raised.value.deleted == (1, 2)
    assert raised.value.pending == (3, 4, 5)
    assert raised.value.operation == "imap_add_deleted_flag"
    assert client.removed == [((3, 4), ("\\Deleted",), True)]
    assert client.expunged == [(1, 2)]


def test_uid_mode_and_password_reference_lifetime():
    client = FakeClient()
    factory_options = {}

    def factory(*args, **kwargs):
        factory_options.update(kwargs)
        return client

    mailbox = make_mailbox(client, writable=False, client_factory=factory)
    with mailbox:
        assert mailbox._password == ""
    assert factory_options["use_uid"] is True

    client.fail_on = "login"
    failed_mailbox = make_mailbox(client, writable=False)
    with pytest.raises(ImapOperationError, match="imap_login"):
        failed_mailbox.__enter__()
    assert failed_mailbox._password == ""


def test_writable_keep_only_does_not_require_mutation_capabilities() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1",))

    with make_mailbox(client, writable=True, allow_delete=False):
        pass

    assert client.selected == [("Spam", False)]


def test_move_only_apply_does_not_require_uidplus() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1", b"MOVE"), uids=[10])
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
    ) as mailbox:
        result = mailbox.move_uids([10], "INBOX.Trash")

    assert result == MoveResult(moved=(10,), destination="INBOX.Trash")
    assert client.moves == [((10,), "INBOX.Trash")]
    assert client.expunged == []
    assert client.selected == [("Spam", False), ("Spam", False)]


def test_move_requires_capability_before_selecting_source() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1", b"UIDPLUS"))
    with pytest.raises(UnsafeMailboxOperation, match="requires IMAP MOVE"):
        with make_mailbox(client, writable=True, allowed_destinations=("INBOX.Trash",), allow_delete=False):
            pass
    assert client.selected == []


def test_move_rejects_unallowed_destination_and_source_destination() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True, allowed_destinations=("INBOX.Trash",), allow_delete=False) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="outside the configured allow-list"):
            mailbox.move_uids([10], "INBOX.Other")
    assert client.moves == []

    source_client = FakeClient()
    with make_mailbox(source_client, writable=True, allowed_destinations=("Spam",), allow_delete=False) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="source folder"):
            mailbox.move_uids([10], "Spam")
    assert source_client.moves == []


def test_move_normalizes_uids_and_batches_exact_uid_commands() -> None:
    client = FakeClient(uids=[1, 2, 3, 4, 5])
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
        mutation_batch_size=2,
    ) as mailbox:
        result = mailbox.move_uids([5, 3, 4, 3, 1], "INBOX.Trash")

    assert result.moved == (1, 3, 4, 5)
    assert client.moves == [((1, 3), "INBOX.Trash"), ((4, 5), "INBOX.Trash")]


def test_move_rejects_uid_outside_initial_snapshot() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True, allowed_destinations=("INBOX.Trash",), allow_delete=False) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="outside initial"):
            mailbox.move_uids([999], "INBOX.Trash")
    assert client.moves == []


def test_uidvalidity_change_aborts_move_before_mutation() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True, allowed_destinations=("INBOX.Trash",), allow_delete=False) as mailbox:
        client.uidvalidity = 43
        with pytest.raises(UnsafeMailboxOperation, match="UIDVALIDITY changed"):
            mailbox.move_uids([10], "INBOX.Trash")
    assert client.moves == []


def test_disappeared_uid_aborts_move_before_mutation() -> None:
    client = FakeClient(uids=[10, 20])
    with make_mailbox(client, writable=True, allowed_destinations=("INBOX.Trash",), allow_delete=False) as mailbox:
        client.uids = [20]
        with pytest.raises(UnsafeMailboxOperation, match="no longer exist"):
            mailbox.move_uids([10], "INBOX.Trash")
    assert client.moves == []


def test_partial_move_reports_confirmed_and_pending_uids_safely() -> None:
    client = FakeClient(uids=[1, 2, 3, 4, 5])
    client.fail_move_on_call = 2
    with make_mailbox(
        client,
        writable=True,
        allowed_destinations=("INBOX.Trash",),
        allow_delete=False,
        mutation_batch_size=2,
    ) as mailbox:
        with pytest.raises(PartialMoveError) as raised:
            mailbox.move_uids([1, 2, 3, 4, 5], "INBOX.Trash")

    error = raised.value
    rendered = str(error)
    assert error.moved == (1, 2)
    assert error.pending == (3, 4, 5)
    assert error.destination == "INBOX.Trash"
    assert error.operation == "imap_uid_move"
    assert error.batch == 2 and error.batch_count == 3
    assert client.moves == [((1, 2), "INBOX.Trash")]
    assert "server_status=BAD" in rendered
    assert "password=secret" not in rendered
    assert RAW.decode() not in rendered


def test_destination_existence_is_allow_listed_and_read_only() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=False, allowed_destinations=("INBOX.Trash", "INBOX.Missing")) as mailbox:
        assert mailbox.destination_exists("INBOX.Trash")
        assert not mailbox.destination_exists("INBOX.Missing")
        with pytest.raises(UnsafeMailboxOperation, match="outside the configured allow-list"):
            mailbox.destination_exists("INBOX.Other")

    assert client.folder_queries == ["Spam", "INBOX.Trash", "INBOX.Missing"]
    assert client.moves == []
    assert client.expunged == []


def test_delete_requires_explicit_allow_delete() -> None:
    client = FakeClient()
    with make_mailbox(client, writable=True, allow_delete=False) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="not allowed"):
            mailbox.delete_uids([10])
    assert client.expunged == []


def test_delete_requires_uidplus_but_not_move() -> None:
    client = FakeClient(capabilities=(b"IMAP4rev1", b"UIDPLUS"))
    with make_mailbox(client, writable=True, allow_delete=True) as mailbox:
        result = mailbox.delete_uids([10])
    assert result.deleted == (10,)
    assert client.expunged == [(10,)]


class FakeFolderClient:
    def __init__(self, folders, statuses=None, *, status_failures=(), fail_login=False, fail_list=False):
        self.folders = folders
        self.statuses = statuses or {}
        self.status_failures = set(status_failures)
        self.fail_login = fail_login
        self.fail_list = fail_list
        self.calls = []
        self.status_calls = []
        self.failure_text = "command error: NO password=secret private@example.org RAW_SERVER_DATA"

    def login(self, username, password):
        self.calls.append("login")
        self.login_args = (username, password)
        if self.fail_login:
            raise RuntimeError(self.failure_text)

    def logout(self):
        self.calls.append("logout")

    def list_folders(self):
        self.calls.append("list_folders")
        if self.fail_list:
            raise RuntimeError(self.failure_text)
        return self.folders

    def folder_status(self, folder, what):
        self.status_calls.append((folder, what))
        if folder in self.status_failures:
            raise RuntimeError(self.failure_text)
        return self.statuses[folder]

    def select_folder(self, *args, **kwargs):
        raise AssertionError("folder discovery must not SELECT")

    def search(self, *args, **kwargs):
        raise AssertionError("folder discovery must not SEARCH")

    def fetch(self, *args, **kwargs):
        raise AssertionError("folder discovery must not FETCH")

    def move(self, *args, **kwargs):
        raise AssertionError("folder discovery must not MOVE")

    def add_flags(self, *args, **kwargs):
        raise AssertionError("folder discovery must not STORE flags")

    def remove_flags(self, *args, **kwargs):
        raise AssertionError("folder discovery must not STORE flags")

    def uid_expunge(self, *args, **kwargs):
        raise AssertionError("folder discovery must not EXPUNGE")

    def folder_exists(self, *args, **kwargs):
        raise AssertionError("folder discovery must not probe folders individually")

    def copy(self, *args, **kwargs):
        raise AssertionError("folder discovery must not COPY")

    def create_folder(self, *args, **kwargs):
        raise AssertionError("folder discovery must not CREATE folders")

    def rename_folder(self, *args, **kwargs):
        raise AssertionError("folder discovery must not RENAME folders")

    def delete_folder(self, *args, **kwargs):
        raise AssertionError("folder discovery must not DELETE folders")

    def subscribe_folder(self, *args, **kwargs):
        raise AssertionError("folder discovery must not change subscriptions")


def make_catalog(client, *, factory_options=None, event_callback=None):
    def factory(host, **kwargs):
        if factory_options is not None:
            factory_options.update(host=host, **kwargs)
        return client

    return FolderCatalog(
        host="imap.example.org",
        port=993,
        username="me@example.org",
        password="secret",
        client_factory=factory,
        event_callback=event_callback,
    )


def test_folder_catalog_no_counts_uses_only_list():
    client = FakeFolderClient([((b"\\HasChildren",), b".", "INBOX")])
    factory_options = {}

    with make_catalog(client, factory_options=factory_options) as catalog:
        rows = catalog.list_folders(include_counts=False)

    assert [row.name for row in rows] == ["INBOX"]
    assert rows[0].total is rows[0].unread is rows[0].read is None
    assert client.calls == ["login", "list_folders", "logout"]
    assert client.status_calls == []
    assert factory_options == {
        "host": "imap.example.org",
        "port": 993,
        "ssl": True,
        "timeout": 30.0,
        "use_uid": True,
    }


def test_folder_catalog_statuses_only_selectable_listed_names_and_preserves_names():
    folders = [
        ((b"\\HasChildren",), b".", "INBOX"),
        ((b"\\HasNoChildren", b"\\Junk"), b".", "INBOX.Junk"),
        ((b"\\Noselect", b"\\HasChildren"), b".", "Shared"),
        ((b"\\HasNoChildren",), b".", "Shared.Team"),
    ]
    statuses = {
        "INBOX": {b"MESSAGES": 100, b"UNSEEN": 7},
        "INBOX.Junk": {"MESSAGES": 0, "UNSEEN": 0},
        "Shared.Team": {b"MESSAGES": 10, b"UNSEEN": 10},
    }
    client = FakeFolderClient(folders, statuses)

    with make_catalog(client) as catalog:
        rows = catalog.list_folders()

    by_name = {row.name: row for row in rows}
    assert client.status_calls == [
        ("INBOX", ("MESSAGES", "UNSEEN")),
        ("INBOX.Junk", ("MESSAGES", "UNSEEN")),
        ("Shared.Team", ("MESSAGES", "UNSEEN")),
    ]
    assert by_name["INBOX"].read == 93
    assert by_name["INBOX.Junk"].total == by_name["INBOX.Junk"].unread == by_name["INBOX.Junk"].read == 0
    assert by_name["Shared.Team"].read == 0
    assert by_name["Shared"].selectable is False
    assert by_name["Shared"].total is by_name["Shared"].unread is by_name["Shared"].read is None
    assert by_name["INBOX.Junk"].flags == frozenset({b"\\HASNOCHILDREN", b"\\JUNK"})
    assert [(row.name, row.delimiter) for row in rows] == [
        ("INBOX", "."),
        ("INBOX.Junk", "."),
        ("Shared", "."),
        ("Shared.Team", "."),
    ]


@pytest.mark.parametrize(
    ("status", "expected_type"),
    [
        ({b"UNSEEN": 1}, "ValueError"),
        ({b"MESSAGES": 2}, "ValueError"),
        ({b"MESSAGES": -1, b"UNSEEN": 0}, "ValueError"),
        ({b"MESSAGES": 1, b"UNSEEN": -1}, "ValueError"),
        ({b"MESSAGES": 1, b"UNSEEN": 2}, "ValueError"),
        ({b"MESSAGES": "invalid", b"UNSEEN": 0}, "ValueError"),
    ],
)
def test_folder_catalog_malformed_status_counts_are_unavailable(status, expected_type):
    client = FakeFolderClient([((b"\\HasNoChildren",), ".", "Legacy")], {"Legacy": status})

    with make_catalog(client) as catalog:
        (row,) = catalog.list_folders()

    assert row.total is row.unread is row.read is None
    assert row.status_error is not None
    assert row.status_error.operation == "imap_folder_status"
    assert row.status_error.cause_type == expected_type


def test_folder_catalog_status_failure_keeps_other_rows_and_sanitizes_error():
    folders = [
        ((b"\\HasNoChildren",), ".", "First"),
        ((b"\\HasNoChildren",), ".", "Broken"),
        ((b"\\HasNoChildren",), ".", "Last"),
    ]
    statuses = {name: {b"MESSAGES": 4, b"UNSEEN": 1} for name in ("First", "Last")}
    client = FakeFolderClient(folders, statuses, status_failures={"Broken"})

    with make_catalog(client) as catalog:
        rows = catalog.list_folders()

    assert [row.name for row in rows] == ["Broken", "First", "Last"]
    assert rows[0].status_error is not None
    assert rows[0].total is rows[0].unread is rows[0].read is None
    assert rows[1].read == rows[2].read == 3
    assert [folder for folder, _ in client.status_calls] == ["First", "Broken", "Last"]
    rendered = str(rows[0].status_error)
    assert "password=secret" not in rendered
    assert "private@example.org" not in rendered
    assert "RAW_SERVER_DATA" not in rendered


def test_folder_catalog_list_failure_is_fatal_and_sanitized():
    client = FakeFolderClient([], fail_list=True)

    with pytest.raises(ImapOperationError) as raised:
        with make_catalog(client) as catalog:
            catalog.list_folders()

    assert raised.value.operation == "imap_list_folders"
    assert "password=secret" not in str(raised.value)
    assert "private@example.org" not in str(raised.value)
    assert "RAW_SERVER_DATA" not in str(raised.value)
    assert client.calls == ["login", "list_folders", "logout"]


def test_folder_catalog_clears_password_after_login_attempt():
    client = FakeFolderClient([], fail_login=True)
    catalog = make_catalog(client)

    with pytest.raises(ImapOperationError, match="imap_login"):
        catalog.__enter__()

    assert catalog._password == ""
    assert client.calls == ["login", "logout"]


def test_folder_catalog_never_calls_message_or_mutation_methods():
    client = FakeFolderClient(
        [((b"\\HasNoChildren",), ".", "INBOX")],
        {"INBOX": {b"MESSAGES": 2, b"UNSEEN": 1}},
    )

    with make_catalog(client) as catalog:
        catalog.list_folders()

    assert client.calls == ["login", "list_folders", "logout"]


def test_folder_info_is_immutable_and_derives_read_count():
    row = FolderInfo(name="Spam", delimiter=None, flags={b"\\noselect", b"\\junk"}, total=5, unread=2)

    assert row.flags == frozenset({b"\\NOSELECT", b"\\JUNK"})
    assert row.selectable is False
    assert row.read == 3


@pytest.mark.parametrize(("total", "unread"), [(None, 0), (-1, 0), (1, -1), (1, 2)])
def test_folder_info_rejects_invalid_counts(total, unread):
    with pytest.raises(ValueError):
        FolderInfo(name="Spam", delimiter=None, flags=frozenset(), total=total, unread=unread)


@pytest.mark.parametrize(
    ("permanent_flags", "expected"),
    [
        ((b"\\*",), True),
        (("imapledger-v1-review",), True),
        (None, False),
        (42, False),
    ],
)
def test_snapshot_normalizes_permanent_flags_and_detects_keyword_support(permanent_flags, expected) -> None:
    client = FakeClient(permanent_flags=permanent_flags)
    with make_mailbox(client, writable=False) as mailbox:
        snapshot = mailbox.snapshot()

    assert snapshot.supports_persistent_keyword("imapledger-v1-review") is expected
    if permanent_flags == ("imapledger-v1-review",):
        assert snapshot.permanent_flags == frozenset({b"IMAPLEDGER-V1-REVIEW"})


def test_apply_precheck_requires_persistent_support_for_every_state_keyword() -> None:
    supported_client = FakeClient(permanent_flags=(b"\\*",))
    with make_mailbox(supported_client, writable=True) as mailbox:
        mailbox.require_persistent_classification_state()

    unsupported_client = FakeClient(permanent_flags=(b"imapledger-v1-spam",))
    with make_mailbox(unsupported_client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.require_persistent_classification_state()

    assert raised.value.operation == "imap_keyword_unsupported"
    assert "imapledger-v1-notspam" in (raised.value.selector or "")
    assert supported_client.added == unsupported_client.added == []


def test_exact_permanent_keyword_support_does_not_require_wildcard() -> None:
    client = FakeClient(permanent_flags=(b"imapledger-v1-notspam",))
    with make_mailbox(client, writable=True) as mailbox:
        mailbox.add_keyword(10, "imapledger-v1-notspam")

    assert client.added == [((10,), ("imapledger-v1-notspam",), True)]


def test_unsupported_keyword_is_rejected_before_store() -> None:
    client = FakeClient(permanent_flags=(b"\\Seen",))
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.add_keyword(10, "imapledger-v1-spam")

    assert raised.value.operation == "imap_keyword_unsupported"
    assert client.added == []


def test_keyword_store_is_exact_uid_scoped_and_reselects_source_read_write() -> None:
    client = FakeClient(uids=[10, 20])
    with make_mailbox(client, writable=True) as mailbox:
        mailbox.add_keyword(10, "imapledger-v1-spam")

    assert client.selected[-1] == ("Spam", False)
    assert client.added == [((10,), ("imapledger-v1-spam",), True)]
    assert client.flags[10] == {b"imapledger-v1-spam"}
    assert client.flags.get(20, set()) == set()
    assert client.searches[-1] == ["UID", 10]


def test_keyword_mutation_rejects_uid_outside_initial_snapshot() -> None:
    client = FakeClient(uids=[10])
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(UnsafeMailboxOperation, match="outside initial"):
            mailbox.add_keyword(20, "imapledger-v1-spam")

    assert client.added == []


def test_keyword_mutation_rejects_disappeared_uid() -> None:
    client = FakeClient(uids=[10])
    with make_mailbox(client, writable=True) as mailbox:
        client.uids.clear()
        with pytest.raises(UnsafeMailboxOperation, match="no longer exists"):
            mailbox.add_keyword(10, "imapledger-v1-spam")

    assert client.added == []


def test_keyword_store_requires_verified_resulting_flags() -> None:
    client = FakeClient()
    client.ignore_flag_store = True
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.add_keyword(10, "imapledger-v1-review")

    assert raised.value.operation == "imap_verify_keyword"


def test_conflicting_existing_state_is_reported_without_store() -> None:
    client = FakeClient(
        flags={10: {b"imapledger-v1-review", b"imapledger-v1-notspam"}},
    )
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.add_keyword(10, "imapledger-v1-spam")

    assert raised.value.operation == "imap_state_conflict"
    assert client.added == []


def test_add_keyword_refuses_to_replace_a_single_existing_state() -> None:
    client = FakeClient(flags={10: {b"imapledger-v1-spam"}})
    with make_mailbox(client, writable=True) as mailbox:
        with pytest.raises(ImapOperationError) as raised:
            mailbox.add_keyword(10, "imapledger-v1-review")

    assert raised.value.operation == "imap_state_conflict"
    assert client.added == []


def test_set_classification_keyword_adds_before_removing_peer_states() -> None:
    client = FakeClient(flags={10: {b"imapledger-v1-spam"}})
    target = keyword_for_outcome(SpamOutcome.REVIEW)
    peers = tuple(keyword for keyword in all_state_keywords() if keyword != target)
    with make_mailbox(client, writable=True) as mailbox:
        mailbox.set_classification_keyword(10, keyword=target, peer_keywords=peers)

    assert client.added[0] == ((10,), (target,), True)
    assert client.removed == [((10,), (peers[0],), True), ((10,), (peers[1],), True)]
    assert client.flags[10] == {target.encode()}


def test_unclassified_search_filters_markers_before_candidate_pagination() -> None:
    uids = list(range(1, 16))
    client = FakeClient(
        uids=uids,
        flags={uid: {b"imapledger-v1-review"} for uid in range(11, 16)},
    )
    with make_mailbox(client, writable=False) as mailbox:
        candidates = mailbox.candidate_uids(excluded_keywords=all_state_keywords())

    selected = sorted(candidates, reverse=True)[:10]
    assert selected == list(range(10, 0, -1))
    assert client.searches[-1] == [
        "UNKEYWORD",
        "imapledger-v1-spam",
        "UNKEYWORD",
        "imapledger-v1-notspam",
        "UNKEYWORD",
        "imapledger-v1-review",
    ]


def test_excluded_keywords_are_applied_before_message_selection_and_fetch() -> None:
    client = FakeClient(
        uids=list(range(1, 16)),
        flags={uid: {b"imapledger-v1-review"} for uid in range(11, 16)},
    )
    selection = MessageSelection(limit=10, excluded_keywords=all_state_keywords())
    with make_mailbox(client, writable=False) as mailbox:
        assert mailbox.selected_count(selection) == 10
        items = list(mailbox.iter_messages(selection))

    assert [item.uid for item in items] == list(range(10, 0, -1))
    assert [messages for messages, selector in client.fetches if selector == ("RFC822.SIZE",)] == [
        tuple(range(10, 0, -1))
    ]


def test_flag_inspection_does_not_mutate_seen_and_headers_use_peek_subset() -> None:
    client = FakeClient(flags={10: {b"\\Seen"}})
    with make_mailbox(client, writable=False) as mailbox:
        flags = mailbox.get_flags(10)
        message = mailbox.fetch_headers(10)

    assert flags == frozenset({b"\\Seen"})
    assert message is not None
    assert message.subject == "Buy now"
    assert message.body == ""
    assert client.flags[10] == {b"\\Seen"}
    assert ((10,), ("FLAGS",)) in client.fetches
    assert client.fetches[-1] == ((10,), ("BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]",))


def test_state_store_never_touches_another_configured_folder() -> None:
    client = FolderAwareFakeClient(
        {
            "Spam": {10: _folder_raw_message("spam", "sender@example.org")},
            "Other": {20: _folder_raw_message("other", "other@example.org")},
        },
        flags={"Other": {20: {b"imapledger-v1-review"}}},
    )
    with make_mailbox(client, writable=True, folder="Spam") as mailbox:
        mailbox.add_keyword(10, "imapledger-v1-spam")

    assert client.flags["Spam"][10] == {b"imapledger-v1-spam"}
    assert client.flags["Other"][20] == {b"imapledger-v1-review"}
    assert all(folder == "Spam" for folder, _ in client.selected)


class SummaryFakeClient(FakeClient):
    def fetch(self, messages, data, modifiers=None):
        messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if data != (
            "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]",
            "FLAGS",
            "RFC822.SIZE",
        ):
            return super().fetch(messages, data, modifiers)
        headers = (
            b"From: Sender <sender@example.org>\r\nSubject: Page row\r\nDate: Today\r\n"
            b"Message-ID: <row@example.org>\r\n\r\n"
        )
        return {
            uid: {
                b"BODY[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]": headers,
                b"FLAGS": tuple(self.flags.get(uid, set())),
                b"RFC822.SIZE": uid * 10,
            }
            for uid in messages
            if uid in self.uids and uid not in getattr(self, "missing_summary_uids", set())
        }


def test_fetch_summaries_batches_preserves_requested_order_and_reads_state() -> None:
    client = SummaryFakeClient(uids=[10, 20], flags={20: {b"imapledger-v1-review"}})
    with make_mailbox(client, writable=False, fetch_batch_size=1) as mailbox:
        summaries = mailbox.fetch_summaries((20, 10))

    assert [summary.uid for summary in summaries] == [20, 10]
    assert summaries[0].sender == "Sender <sender@example.org>"
    assert summaries[0].subject == "Page row"
    assert summaries[0].size_bytes == 200
    assert summaries[0].persisted_state is SpamOutcome.REVIEW
    assert summaries[1].persisted_state is None
    assert [call[0] for call in client.fetches] == [(20,), (10,)]
    assert all("BODY.PEEK[HEADER.FIELDS" in call[1][0] for call in client.fetches)
    assert client.selected[0] == ("Spam", True)


def test_fetch_summaries_marks_vanished_uid_and_rejects_uid_outside_snapshot() -> None:
    client = SummaryFakeClient(uids=[10, 20])
    client.missing_summary_uids = {20}
    with make_mailbox(client, writable=False) as mailbox:
        summaries = mailbox.fetch_summaries((20, 10))
        with pytest.raises(UnsafeMailboxOperation, match="initial mailbox snapshot"):
            mailbox.fetch_summaries((99,))

    assert summaries[0].skip_reason == "message disappeared before header fetch"
    assert summaries[1].subject == "Page row"
    assert len(client.fetches) == 1


def test_read_only_facade_exposes_browsing_but_no_mutation_methods() -> None:
    client = FakeClient(uids=[10, 20])
    scoped = make_mailbox(client, writable=False)
    mailbox = ReadOnlyMailbox(scoped)

    assert not hasattr(mailbox, "move_uid")
    with mailbox:
        assert mailbox.page_uids(limit=1) == (20,)
        assert mailbox.page_uids(limit=2, sort=MessageSort.OLDEST) == (10, 20)

    with pytest.raises(ValueError, match="read-only ScopedMailbox"):
        ReadOnlyMailbox(make_mailbox(FakeClient(), writable=True))
