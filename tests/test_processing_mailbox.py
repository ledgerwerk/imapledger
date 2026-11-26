from __future__ import annotations

import pytest

from imapledger.mailbox import PartialMoveError, ProcessingMailbox, UnsafeMailboxOperation
from tests.fakes import FolderAwareFakeClient, raw_message


def _mailbox(
    client: FolderAwareFakeClient,
    *,
    writable: bool = False,
    destinations: tuple[str, ...] = (),
    max_message_bytes: int = 100_000,
    fetch_batch_size: int = 100,
) -> ProcessingMailbox:
    return ProcessingMailbox(
        host="imap.example.org",
        port=993,
        username="user@example.org",
        password="secret",
        folder="INBOX",
        writable=writable,
        max_message_bytes=max_message_bytes,
        max_body_chars=1000,
        fetch_batch_size=fetch_batch_size,
        allowed_destinations=destinations,
        client_factory=lambda *args, **kwargs: client,
    )


def _client(uids: tuple[int, ...]) -> FolderAwareFakeClient:
    return FolderAwareFakeClient(
        {
            "INBOX": {uid: raw_message(f"Message {uid}", "sender@example.org") for uid in uids},
            "Archive": {},
        }
    )


def test_processing_mailbox_captures_uidnext_and_scans_sparse_bounded_oldest_windows() -> None:
    client = _client((2, 4000, 5000))
    mailbox = _mailbox(client)

    with mailbox:
        metadata = mailbox.metadata()
        assert metadata.uidvalidity == 42
        assert metadata.uidnext == 5001
        assert metadata.high_watermark_uid == 5000
        client.folders["INBOX"][5001] = raw_message("New mail", "sender@example.org")

        uids = mailbox.find_next_uids(
            cursor_uid=None,
            high_watermark_uid=metadata.high_watermark_uid,
            limit=10,
            direction="oldest",
        )

    assert uids == (2, 4000, 5000)
    assert client.searches == [["UID", "1:4096"], ["UID", "4097:5000"]]
    assert client.fetches == []


def test_processing_mailbox_scans_newest_uid_windows_without_a_full_snapshot() -> None:
    high_uid = 10_000_000
    client = _client((1, high_uid - 1, high_uid))

    with _mailbox(client) as mailbox:
        metadata = mailbox.metadata()
        uids = mailbox.find_next_uids(
            cursor_uid=None,
            high_watermark_uid=metadata.high_watermark_uid,
            limit=2,
            direction="newest",
        )

    assert uids == (high_uid, high_uid - 1)
    assert client.searches == [["UID", f"{high_uid - 4095}:{high_uid}"]]
    assert client.fetches == []
    assert not any(messages == ("1:*",) and data == ("UID",) for messages, data in client.fetches)


def test_processing_mailbox_respects_stable_lower_uid_bound() -> None:
    high_uid = 10_000
    client = _client((2, 4000, 5000, high_uid))

    with _mailbox(client) as mailbox:
        metadata = mailbox.metadata()
        newest = mailbox.find_next_uids(
            cursor_uid=None,
            high_watermark_uid=metadata.high_watermark_uid,
            lower_bound_uid=4000,
            limit=10,
            direction="newest",
        )
        oldest = mailbox.find_next_uids(
            cursor_uid=None,
            high_watermark_uid=metadata.high_watermark_uid,
            lower_bound_uid=1,
            limit=10,
            direction="oldest",
        )

    assert newest == (high_uid, 5000)
    assert oldest == (2, 4000, 5000, high_uid)


def test_processing_mailbox_fetches_only_eligible_bodies_in_batches() -> None:
    client = _client((1, 2, 3))

    with _mailbox(client, fetch_batch_size=10) as mailbox:
        items = mailbox.fetch_items((1, 2, 3), high_watermark_uid=3)

    assert all(item.message is not None for item in items)
    assert [item.uid for item in items] == [1, 2, 3]
    assert client.fetches == [
        ((1, 2, 3), ("RFC822.SIZE",)),
        ((1, 2, 3), ("BODY.PEEK[]",)),
    ]


def test_processing_mailbox_skips_oversized_and_disappeared_messages() -> None:
    client = _client((1, 2))

    with _mailbox(client, max_message_bytes=1) as mailbox:
        oversized = mailbox.fetch_items((1, 2), high_watermark_uid=2)

    assert all(item.message is None and "exceeds limit" in item.skip_reason for item in oversized)
    assert all(data == ("RFC822.SIZE",) for _, data in client.fetches)

    client = _client((1,))
    with _mailbox(client) as mailbox:
        client.folders["INBOX"].pop(1)
        disappeared = mailbox.fetch_items((1,), high_watermark_uid=1)
    assert disappeared[0].message is None
    assert disappeared[0].skip_reason == "message disappeared before size fetch"


def test_processing_mailbox_fails_closed_on_uidvalidity_change_and_checks_destinations() -> None:
    client = _client((1,))
    with _mailbox(client, destinations=("Archive", "Missing")) as mailbox:
        mailbox.validate_destination("Archive")
        with pytest.raises(UnsafeMailboxOperation, match="does not exist"):
            mailbox.validate_destination("Missing")

        client.uidvalidities["INBOX"] = 43
        with pytest.raises(UnsafeMailboxOperation, match="UIDVALIDITY changed"):
            mailbox.find_next_uids(
                cursor_uid=None,
                high_watermark_uid=1,
                limit=10,
                direction="oldest",
            )


def test_processing_mailbox_moves_exact_uid_and_preserves_partial_move_failure() -> None:
    client = _client((9, 10))
    with _mailbox(client, writable=True, destinations=("Archive",)) as mailbox:
        mailbox.validate_destination("Archive")
        moved = mailbox.move_uid(9, "Archive")
        assert moved.moved == (9,)
        assert client.moves == [((9,), "Archive")]
        assert [criteria for criteria in client.searches if criteria == ["UID", 9]] == [["UID", 9]]

    client = _client((9,))
    client.fail_on = "move"
    with _mailbox(client, writable=True, destinations=("Archive",)) as mailbox:
        with pytest.raises(PartialMoveError) as error:
            mailbox.move_uid(9, "Archive")
    assert error.value.moved == ()
    assert error.value.pending == (9,)
    assert client.moves == []


def test_processing_mailbox_refuses_uid_outside_captured_uidnext() -> None:
    client = _client((9,))
    with _mailbox(client, writable=True, destinations=("Archive",)) as mailbox:
        client.folders["INBOX"][10] = raw_message("Arrived late", "sender@example.org")
        with pytest.raises(UnsafeMailboxOperation, match="outside initial mailbox snapshot"):
            mailbox.move_uid(10, "Archive")
