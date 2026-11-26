from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import pytest

from imapledger.config import ConfigStoreSettings
from imapledger.config_diff import DiffDirection
from imapledger.config_errors import (
    ConfigHistoryConflictError,
    ConfigLedgerError,
    ConfigSnapshotIntegrityError,
    SensitiveConfigError,
)
from imapledger.config_ledger import (
    ConfigLedger,
    ConfigOverwriteConfirmationRequired,
    ConfigToolStatus,
)
from imapledger.config_mailbox import ConfigStoreMailbox
from imapledger.config_snapshot import create_snapshot, serialize_snapshot
from tests.fakes import ConfigStoreFakeClient

STORE_FOLDER = "INBOX.imapledger.Config"
HOME = Path("/tmp/imapledger-test-home")


@contextmanager
def _service(
    tmp_path: Path,
    messages: dict[int, bytes] | None = None,
    *,
    writable: bool = False,
    home: Path | None = None,
):
    store = ConfigStoreSettings(STORE_FOLDER)
    fake = ConfigStoreFakeClient({STORE_FOLDER: messages or {}})
    mailbox = ConfigStoreMailbox(
        host="imap.example.org",
        port=993,
        username="user@example.org",
        password="secret",
        folder=store.folder,
        max_file_bytes=store.max_file_bytes,
        writable=writable,
        client_factory=lambda *args, **kwargs: fake,
    )
    mailbox.__enter__()
    service = ConfigLedger(mailbox, store, home=home or (tmp_path / "home"))
    try:
        yield service, fake, mailbox
    finally:
        mailbox.__exit__(None, None, None)


def _snapshot(
    content: bytes,
    *,
    tool: str = "xyz",
    parents: tuple[str, ...] = (),
    default_path: str = "~/.config/xyz/config.toml",
    created_at: datetime | None = None,
):
    return create_snapshot(
        tool=tool,
        content=content,
        default_path=default_path,
        parent_version_ids=parents,
        created_at=created_at,
    )


def _stored(uid: int, snapshot) -> tuple[int, bytes]:
    return uid, serialize_snapshot(snapshot, username="user@example.org")


def _write_local(home: Path, relative: str, content: bytes) -> Path:
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_list_and_versions_use_metadata_and_show_parent_derived_current(tmp_path: Path) -> None:
    home = tmp_path / "home"
    first = _snapshot(b"first\n", created_at=datetime(2026, 11, 21, tzinfo=timezone.utc))
    second = _snapshot(
        b"second\n",
        parents=(first.meta.version_id,),
        created_at=datetime(2026, 11, 21, tzinfo=timezone.utc) + timedelta(seconds=1),
    )
    messages = dict((_stored(1, first), _stored(2, second)))

    with _service(tmp_path, messages, home=home) as (service, fake, _):
        tools = service.list_tools()
        versions = service.list_versions("xyz")

    assert len(tools) == 1
    assert tools[0].status is ConfigToolStatus.OK
    assert tools[0].current == second.meta.version_id
    assert tools[0].versions == 2
    assert [record.current for record in versions] == [False, True]
    assert not any(selector == ("BODY.PEEK[]",) for selector in fake.fetch_selectors)


def test_list_reports_conflicts_and_corrupt_metadata(tmp_path: Path) -> None:
    root = _snapshot(b"root\n")
    branch_a = _snapshot(b"a\n", parents=(root.meta.version_id,))
    branch_b = _snapshot(b"b\n", parents=(root.meta.version_id,))
    conflicted = dict((_stored(1, root), _stored(2, branch_a), _stored(3, branch_b)))
    with _service(tmp_path, conflicted) as (service, _, _):
        summary = service.list_tools()[0]
    assert summary.status is ConfigToolStatus.CONFLICT
    assert summary.current == "2 heads"

    malformed = _stored(4, root)[1].replace(b"X-Imapledger-Schema: 1", b"X-Imapledger-Schema: 8", 1)
    with _service(tmp_path, {4: malformed}) as (service, _, _):
        corrupt = service.list_tools()[0]
    assert corrupt.status is ConfigToolStatus.CORRUPT
    assert corrupt.tool == "xyz"


def test_first_push_next_push_duplicate_suppression_and_path_revision(tmp_path: Path) -> None:
    home = tmp_path / "home"
    source = _write_local(home, ".config/xyz/config.toml", b"value = 1\n")

    with _service(tmp_path, writable=True, home=home) as (service, fake, _):
        first = service.push("XYZ", source)
        duplicate = service.push("xyz", source)
        other_path = _write_local(home, "backup/xyz-copy.toml", b"value = 1\n")
        moved_default = service.push("xyz", other_path)

    assert first.created
    assert not duplicate.created
    assert len(fake.appends) == 2
    assert moved_default.snapshot.parent_version_ids == (first.snapshot.version_id,)
    assert moved_default.snapshot.default_path == "~/backup/xyz-copy.toml"
    assert moved_default.snapshot.filename == "xyz-copy.toml"


def test_push_rejects_conflict_unless_explicitly_resolved(tmp_path: Path) -> None:
    root = _snapshot(b"root\n")
    branch_a = _snapshot(b"a\n", parents=(root.meta.version_id,))
    branch_b = _snapshot(b"b\n", parents=(root.meta.version_id,))
    messages = dict((_stored(1, root), _stored(2, branch_a), _stored(3, branch_b)))
    path = _write_local(tmp_path / "home", ".config/xyz/config.toml", b"chosen\n")

    with _service(tmp_path, messages, writable=True) as (service, fake, _):
        with pytest.raises(ConfigHistoryConflictError, match="2 current heads"):
            service.push("xyz", path)
        resolved = service.push("xyz", path, resolve_conflict=True)

    assert len(fake.appends) == 1
    assert set(resolved.snapshot.parent_version_ids) == {branch_a.meta.version_id, branch_b.meta.version_id}


def test_secret_scan_blocks_without_values_and_override_allows_append(tmp_path: Path) -> None:
    path = _write_local(tmp_path / "home", ".config/xyz/config.toml", b'api_key = "private-value"\n')

    with _service(tmp_path, writable=True) as (service, fake, _):
        with pytest.raises(SensitiveConfigError) as raised:
            service.push("xyz", path)
        result = service.push("xyz", path, allow_sensitive_plaintext=True)

    assert "api_key" in str(raised.value)
    assert "private-value" not in str(raised.value)
    assert result.created
    assert len(fake.appends) == 1


def test_cat_returns_exact_remote_text_and_diff_uses_explicit_direction(tmp_path: Path) -> None:
    home = tmp_path / "home"
    remote = _snapshot(b"remote\n", created_at=datetime(2026, 11, 21, tzinfo=timezone.utc))
    local = _write_local(home, ".config/xyz/config.toml", b"local\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        cat = service.cat("xyz")
        local_to_imap = service.diff("xyz", path=local, direction=DiffDirection.LOCAL_TO_IMAP)
        imap_to_local = service.diff("xyz", path=local, direction=DiffDirection.IMAP_TO_LOCAL)

    assert cat == "remote\n"
    assert local_to_imap.startswith(f"--- local:{local}\n+++ imap:xyz@{remote.meta.version_id}\n")
    assert "-local\n+remote\n" in local_to_imap
    assert imap_to_local.startswith(f"--- imap:xyz@{remote.meta.version_id}\n+++ local:{local}\n")
    assert "-remote\n+local\n" in imap_to_local


def test_pull_creates_default_target_atomically_and_identical_target_is_noop(tmp_path: Path) -> None:
    home = tmp_path / "home"
    remote = _snapshot(b"remote\r\n")
    messages = dict((_stored(1, remote),))

    with _service(tmp_path, messages, home=home) as (service, _, _):
        pulled = service.pull("xyz")
        again = service.pull("xyz")

    target = home / ".config/xyz/config.toml"
    assert pulled.written
    assert target.read_bytes() == b"remote\r\n"
    assert again.already_up_to_date
    assert not again.written


def test_pull_diff_prompt_rejection_leaves_target_untouched(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    remote = _snapshot(b"remote\n")
    prompts = []

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        result = service.pull(
            "xyz",
            confirm_overwrite=lambda path, diff: prompts.append((path, diff)) or False,
        )

    assert result.cancelled
    assert not result.written
    assert target.read_bytes() == b"local\n"
    assert prompts[0][0] == target
    assert "-local\n+remote\n" in prompts[0][1]


def test_force_skips_prompt_and_force_show_diff_returns_diff(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    remote = _snapshot(b"remote\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        forced = service.pull("xyz", force=True, confirm_overwrite=lambda *_: pytest.fail("prompt was called"))
        target.write_bytes(b"local\n")
        shown_diffs = []
        shown = service.pull(
            "xyz",
            force=True,
            show_diff=True,
            show_diff_callback=lambda path, diff: shown_diffs.append((path, diff, target.read_bytes())),
        )

    assert forced.written
    assert forced.diff == ""
    assert shown.written
    assert "-local\n+remote\n" in shown.diff
    assert shown_diffs == [(target, shown.diff, b"local\n")]
    assert target.read_bytes() == b"remote\n"


def test_pull_requires_callback_for_differing_existing_target(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    remote = _snapshot(b"remote\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        with pytest.raises(ConfigOverwriteConfirmationRequired) as raised:
            service.pull("xyz")

    assert raised.value.target == target
    assert "-local\n+remote\n" in raised.value.diff
    assert target.read_bytes() == b"local\n"


def test_pull_preview_requires_consent_and_rejects_stale_local_content(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    remote = _snapshot(b"remote\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        preview = service.preview_pull("xyz")
        assert preview.target == target
        assert preview.target_exists
        assert preview.target_sha256 is not None
        assert "-local\n+remote\n" in preview.diff
        with pytest.raises(ConfigOverwriteConfirmationRequired):
            service.apply_pull(preview, confirm_overwrite=False)

        target.write_bytes(b"changed after preview\n")
        with pytest.raises(ConfigLedgerError, match="changed since preview"):
            service.apply_pull(preview, confirm_overwrite=True)

    assert target.read_bytes() == b"changed after preview\n"


def test_pull_preview_apply_writes_only_after_explicit_confirmation(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    remote = _snapshot(b"remote\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        preview = service.preview_pull("xyz")
        result = service.apply_pull(preview, confirm_overwrite=True)

    assert result.written
    assert result.version_id == preview.version_id
    assert target.read_bytes() == b"remote\n"


def test_pull_preview_rejects_a_target_created_after_preview(tmp_path: Path) -> None:
    home = tmp_path / "home"
    remote = _snapshot(b"remote\n")

    with _service(tmp_path, dict((_stored(1, remote),)), home=home) as (service, _, _):
        preview = service.preview_pull("xyz")
        preview.target.parent.mkdir(parents=True)
        preview.target.write_bytes(b"new local content\n")
        with pytest.raises(ConfigLedgerError, match="changed since preview"):
            service.apply_pull(preview, confirm_overwrite=True)

    assert preview.target.read_bytes() == b"new local content\n"


def test_pull_to_override_and_outside_home_default_safety(tmp_path: Path) -> None:
    outside = Path("/etc/xyz/config.toml")
    remote = _snapshot(b"remote\n", default_path=str(outside))
    explicit_target = tmp_path / "explicit" / "xyz.toml"

    with _service(tmp_path, dict((_stored(1, remote),)), home=tmp_path / "home") as (service, _, _):
        with pytest.raises(ConfigLedgerError, match="outside the current home directory"):
            service.pull("xyz")
        result = service.pull("xyz", to=explicit_target)

    assert result.written
    assert explicit_target.read_bytes() == b"remote\n"


def test_remote_integrity_failure_occurs_before_any_local_write(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target = _write_local(home, ".config/xyz/config.toml", b"local\n")
    original = serialize_snapshot(_snapshot(b"remote\n"), username="user@example.org")
    message = BytesParser(policy=default).parsebytes(original)
    message.clear_content()
    message.set_content("readable mirror")
    message.add_attachment(b"tamper\n", maintype="application", subtype="octet-stream", filename="config.toml")
    fake_messages = {1: message.as_bytes()}

    with _service(tmp_path, fake_messages, home=home) as (service, _, _):
        with pytest.raises(ConfigSnapshotIntegrityError, match="SHA-256"):
            service.pull("xyz", force=True)

    assert target.read_bytes() == b"local\n"


def test_stored_path_expands_on_current_home_and_versions_can_be_selected(tmp_path: Path) -> None:
    home = tmp_path / "home"
    first = _snapshot(b"first\n", created_at=datetime(2026, 11, 21, tzinfo=timezone.utc))
    second = _snapshot(
        b"second\n",
        parents=(first.meta.version_id,),
        created_at=datetime(2026, 11, 21, tzinfo=timezone.utc) + timedelta(seconds=1),
    )

    with _service(tmp_path, dict((_stored(1, first), _stored(2, second))), home=home) as (service, _, _):
        result = service.pull("xyz", version=first.meta.version_id[:20])

    assert result.target == home / ".config/xyz/config.toml"
    assert result.target.read_bytes() == b"first\n"
