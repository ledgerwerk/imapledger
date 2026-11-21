from __future__ import annotations

import inspect

import pytest

from imapledger.config_errors import ConfigSnapshotIntegrityError, ConfigStoreFolderMissingError
from imapledger.config_mailbox import ConfigStoreMailbox, ConfigStoreOperationError
from imapledger.config_snapshot import create_snapshot, serialize_snapshot
from tests.fakes import ConfigStoreFakeClient, raw_message

STORE_FOLDER = "INBOX.imapledger.Config"


def _snapshot(tool: str = "xyz", content: bytes = b"value = 1\n"):
    return create_snapshot(tool=tool, content=content, default_path=f"~/.config/{tool}/config.toml")


def _mailbox(fake: ConfigStoreFakeClient, *, writable: bool = False, password: str = "secret") -> ConfigStoreMailbox:
    return ConfigStoreMailbox(
        host="imap.example.org",
        port=993,
        username="user@example.org",
        password=password,
        folder=STORE_FOLDER,
        max_file_bytes=1_048_576,
        writable=writable,
        client_factory=lambda *args, **kwargs: fake,
    )


def _message(tool: str = "xyz", content: bytes = b"value = 1\n") -> bytes:
    return serialize_snapshot(_snapshot(tool, content), username="user@example.org")


def test_connect_login_logout_and_readonly_selection() -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})
    mailbox = _mailbox(fake)

    with mailbox:
        assert fake.login_args == ("user@example.org", "secret")
        assert fake.readonly_selections == [True]
        assert mailbox._password == ""

    assert fake.logged_out
    assert mailbox._password == ""


def test_password_is_cleared_after_login_failure() -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})
    fake.fail_on = "login"
    mailbox = _mailbox(fake, password="sensitive")

    with pytest.raises(ConfigStoreOperationError, match="login failed"):
        mailbox.__enter__()

    assert mailbox._password == ""
    assert fake.logged_out


def test_missing_config_store_folder_fails_without_creating_it() -> None:
    fake = ConfigStoreFakeClient({"INBOX": {}})

    with pytest.raises(ConfigStoreFolderMissingError, match=STORE_FOLDER):
        with _mailbox(fake):
            pass

    assert fake.folder_queries == [STORE_FOLDER]
    assert STORE_FOLDER not in fake.folders
    assert fake.logged_out


def test_metadata_search_is_header_only_and_filters_kind_and_tool() -> None:
    fake = ConfigStoreFakeClient(
        {
            STORE_FOLDER: {
                1: _message("xyz"),
                2: _message("pyjev"),
                3: raw_message("ordinary mail", "other@example.org"),
            }
        }
    )

    with _mailbox(fake) as mailbox:
        all_metadata = mailbox.list_snapshot_metadata()
        xyz_metadata = mailbox.list_snapshot_metadata("XYZ")

    assert [item.tool for item in all_metadata] == ["xyz", "pyjev"]
    assert [item.tool for item in xyz_metadata] == ["xyz"]
    assert fake.searches[0] == ["HEADER", "X-Imapledger-Kind", "config-snapshot"]
    assert fake.searches[1][-3:] == ["HEADER", "X-Imapledger-Tool", "xyz"]
    assert all("BODY.PEEK[]" not in selector[0] for selector in fake.fetch_selectors)
    assert all(item.uidvalidity == 42 for item in all_metadata)


def test_metadata_scan_reports_malformed_snapshots_with_tool_identity() -> None:
    valid = _message()
    malformed = valid.replace(b"X-Imapledger-Schema: 1", b"X-Imapledger-Schema: 9", 1)
    fake = ConfigStoreFakeClient({STORE_FOLDER: {1: malformed, 2: valid}})

    with _mailbox(fake) as mailbox:
        scan = mailbox.scan_snapshot_metadata()

    assert [item.uid for item in scan.metadata] == [2]
    assert [(item.uid, item.tool) for item in scan.issues] == [(1, "xyz")]
    assert "unsupported config snapshot schema" in scan.issues[0].reason


def test_full_snapshot_fetch_is_lazy_and_verified() -> None:
    raw = _message()
    fake = ConfigStoreFakeClient({STORE_FOLDER: {7: raw}})

    with _mailbox(fake) as mailbox:
        meta = mailbox.list_snapshot_metadata("xyz")[0]
        snapshot = mailbox.fetch_snapshot(meta)

    assert snapshot.content == b"value = 1\n"
    assert snapshot.meta.uid == 7
    assert fake.fetch_selectors[-1] == ("BODY.PEEK[]",)


def test_writable_selection_append_and_appended_snapshot_verification() -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})
    snapshot = _snapshot()

    with _mailbox(fake, writable=True) as mailbox:
        appended = mailbox.append_snapshot(snapshot)

    assert fake.readonly_selections == [False]
    assert len(fake.appends) == 1
    assert fake.appends[0][0] == STORE_FOLDER
    assert appended.content == snapshot.content
    assert appended.meta.uid == 1
    assert fake.selected_folders == [STORE_FOLDER]


def test_readonly_transport_refuses_append() -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})

    with _mailbox(fake) as mailbox:
        with pytest.raises(Exception, match="read-only"):
            mailbox.append_snapshot(_snapshot())

    assert fake.appends == []


@pytest.mark.parametrize("operation", ["select", "search", "fetch", "append"])
def test_imap_failures_are_translated_without_raw_server_text(operation: str) -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {1: _message()}})
    fake.fail_on = operation
    mailbox = _mailbox(fake, writable=operation == "append")

    if operation == "select":
        with pytest.raises(ConfigStoreOperationError, match="select"):
            mailbox.__enter__()
        return

    with mailbox:
        with pytest.raises(ConfigStoreOperationError):
            if operation == "search":
                mailbox.list_snapshot_metadata()
            elif operation == "fetch":
                mailbox.list_snapshot_metadata()
            else:
                mailbox.append_snapshot(_snapshot())


def test_config_transport_has_no_arbitrary_folder_or_raw_client_api() -> None:
    public_methods = {
        name: value
        for name, value in inspect.getmembers(ConfigStoreMailbox, predicate=inspect.isfunction)
        if not name.startswith("_")
    }

    assert set(public_methods) == {
        "list_snapshot_metadata",
        "scan_snapshot_metadata",
        "fetch_snapshot",
        "append_snapshot",
    }
    assert all("folder" not in inspect.signature(method).parameters for method in public_methods.values())
    assert not hasattr(ConfigStoreMailbox, "client")


def test_snapshot_with_stale_uidvalidity_is_rejected() -> None:
    fake = ConfigStoreFakeClient({STORE_FOLDER: {1: _message()}}, uidvalidities={STORE_FOLDER: 99})

    with _mailbox(fake) as mailbox:
        meta = mailbox.list_snapshot_metadata("xyz")[0]
        stale = type(meta)(
            tool=meta.tool,
            version_id=meta.version_id,
            parent_version_ids=meta.parent_version_ids,
            created_at=meta.created_at,
            default_path=meta.default_path,
            filename=meta.filename,
            content_sha256=meta.content_sha256,
            size_bytes=meta.size_bytes,
            schema=meta.schema,
            uid=meta.uid,
            uidvalidity=98,
            message_id=meta.message_id,
        )
        with pytest.raises(ConfigSnapshotIntegrityError, match="stale"):
            mailbox.fetch_snapshot(stale)
