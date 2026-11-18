import pytest

from imapledger.mailbox import (
    DeleteResult,
    ImapOperationError,
    MessageSelection,
    MessageSort,
    MoveResult,
    PartialDeleteError,
    PartialMoveError,
    ScopedMailbox,
    UnsafeMailboxOperation,
)

RAW = b"From: spammer@example.org\r\nTo: me@example.org\r\nSubject: Buy now\r\n\r\nCheap pills"


class FakeClient:
    def __init__(self, *, capabilities=(b"IMAP4rev1", b"UIDPLUS", b"MOVE"), uidvalidity=42, size=None, uids=None):
        self._capabilities = capabilities
        self.uidvalidity = uidvalidity
        self.size = len(RAW) if size is None else size
        self.uids = [10] if uids is None else list(uids)
        self.selected = []
        self.fetches = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.moves = []
        self.existing_folders = {"INBOX.Trash"}
        self.folder_queries = []
        self.logged_out = False
        self.fail_on = None
        self.fail_move_on_call = None
        self.failure_text = "FETCH command error: BAD password=secret raw_message=" + RAW.decode()

    def _maybe_fail(self, operation):
        if self.fail_on == operation or (isinstance(self.fail_on, set) and operation in self.fail_on):
            raise RuntimeError(self.failure_text)

    def login(self, username, password):
        self._maybe_fail("login")
        self.login_args = (username, password)

    def logout(self):
        self.logged_out = True

    def capabilities(self):
        self._maybe_fail("capabilities")
        return self._capabilities

    def select_folder(self, folder, readonly=False):
        self._maybe_fail("select")
        self.selected.append((folder, readonly))
        return {b"UIDVALIDITY": self.uidvalidity, b"EXISTS": len(self.uids), b"FLAGS": (), b"RECENT": 0}

    def folder_exists(self, folder):
        self._maybe_fail("folder_exists")
        self.folder_queries.append(folder)
        return folder in self.existing_folders

    def search(self, criteria="ALL", charset=None):
        self._maybe_fail("search")
        return self.uids

    def fetch(self, messages, data, modifiers=None):
        messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if data == ("RFC822.SIZE",):
            self._maybe_fail("fetch_size")
            return {uid: {b"RFC822.SIZE": self.size} for uid in messages}
        self._maybe_fail("fetch_body")
        return {uid: {b"BODY[]": RAW} for uid in messages}

    def move(self, messages, folder):
        if self.fail_move_on_call == len(self.moves) + 1:
            raise RuntimeError(self.failure_text)
        self._maybe_fail("move")
        self.moves.append((tuple(messages), folder))

    def add_flags(self, messages, flags, silent=False):
        self._maybe_fail("add_flags")
        self.added.append((tuple(messages), tuple(flags), silent))

    def remove_flags(self, messages, flags, silent=False):
        self._maybe_fail("remove_flags")
        self.removed.append((tuple(messages), tuple(flags), silent))

    def uid_expunge(self, messages):
        self._maybe_fail("uid_expunge")
        self.expunged.append(tuple(messages))


def factory_for(client):
    return lambda *args, **kwargs: client


def make_mailbox(
    client,
    *,
    writable,
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
        folder="Spam",
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

    assert client.folder_queries == ["INBOX.Trash", "INBOX.Missing"]
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
