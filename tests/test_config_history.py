from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from imapledger.config_errors import (
    ConfigHistoryConflictError,
    ConfigHistoryError,
    ConfigVersionNotFoundError,
)
from imapledger.config_history import build_history, group_histories
from imapledger.config_snapshot import ConfigSnapshotMeta, create_snapshot

START = datetime(2026, 11, 21, 16, 0, tzinfo=timezone.utc)


def _meta(
    content: bytes,
    *,
    tool: str = "xyz",
    parents: tuple[str, ...] = (),
    offset: int = 0,
) -> ConfigSnapshotMeta:
    return create_snapshot(
        tool=tool,
        content=content,
        default_path=f"~/.config/{tool}/config.toml",
        parent_version_ids=parents,
        created_at=START + timedelta(seconds=offset),
    ).meta


def test_empty_history_has_no_heads_and_no_current_version() -> None:
    history = build_history([], tool="xyz")

    assert history.versions == ()
    assert history.heads == ()
    with pytest.raises(ConfigVersionNotFoundError):
        _ = history.current


def test_one_first_snapshot_is_the_only_head() -> None:
    first = _meta(b"first")
    history = build_history([first], tool="xyz")

    assert history.current == first
    assert history.heads == (first,)


def test_linear_history_selects_head_from_parent_links() -> None:
    first = _meta(b"A")
    second = _meta(b"B", parents=(first.version_id,), offset=1)
    third = _meta(b"C", parents=(second.version_id,), offset=2)
    history = build_history([third, first, second], tool="xyz")

    assert [item.version_id for item in history.versions] == [
        first.version_id,
        second.version_id,
        third.version_id,
    ]
    assert history.current == third


def test_divergent_branches_are_a_conflict_not_timestamp_selected() -> None:
    first = _meta(b"A")
    branch_b = _meta(b"B", parents=(first.version_id,), offset=1)
    branch_c = _meta(b"C", parents=(first.version_id,), offset=2)
    history = build_history([first, branch_b, branch_c], tool="xyz")

    assert {item.version_id for item in history.heads} == {branch_b.version_id, branch_c.version_id}
    with pytest.raises(ConfigHistoryConflictError, match="2 current heads"):
        _ = history.current
    with pytest.raises(ConfigHistoryConflictError):
        history.select()


def test_multi_parent_resolution_snapshot_becomes_unique_head() -> None:
    first = _meta(b"A")
    branch_b = _meta(b"B", parents=(first.version_id,), offset=1)
    branch_c = _meta(b"C", parents=(first.version_id,), offset=2)
    resolution = _meta(b"resolved", parents=(branch_b.version_id, branch_c.version_id), offset=3)
    history = build_history([first, branch_b, branch_c, resolution], tool="xyz")

    assert history.current == resolution
    assert history.heads == (resolution,)


def test_missing_parent_is_reported_as_history_corruption() -> None:
    child = _meta(b"child", parents=("20261121T150000.000000Z-0123456789ab",))

    with pytest.raises(ConfigHistoryError, match="missing parent"):
        build_history([child], tool="xyz")


def test_identical_transport_copies_are_deduplicated() -> None:
    original = _meta(b"same")
    duplicate = replace(original, uid=42, uidvalidity=9, message_id="<copy@example.org>")
    history = build_history([original, duplicate], tool="xyz")

    assert history.versions == (original,)
    assert history.current == original


def test_same_version_id_with_different_metadata_is_corruption() -> None:
    original = _meta(b"same")
    changed = replace(original, default_path="~/other.toml")

    with pytest.raises(ConfigHistoryError, match="conflicting metadata"):
        build_history([original, changed], tool="xyz")


def test_explicit_full_or_unambiguous_prefix_version_selection() -> None:
    first = _meta(b"A")
    second = _meta(b"B", parents=(first.version_id,), offset=1)
    history = build_history([first, second], tool="xyz")

    assert history.select(first.version_id) == first
    assert history.select(first.version_id[:20]) == first
    with pytest.raises(ConfigVersionNotFoundError):
        history.select("missing")


def test_histories_are_separated_by_tool_name() -> None:
    xyz = _meta(b"xyz")
    pyjev = _meta(b"pyjev", tool="pyjev")

    histories = group_histories([xyz, pyjev])

    assert [history.tool for history in histories] == ["pyjev", "xyz"]
    assert histories[0].current == pyjev
    assert histories[1].current == xyz
