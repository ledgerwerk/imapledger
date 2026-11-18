from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .message import MailMessage, parse_message

DELETED_FLAG = "\\Deleted"


class MailboxError(RuntimeError):
    pass


class UnsafeMailboxOperation(MailboxError):
    pass


class _Client(Protocol):
    def login(self, username: str, password: str) -> Any: ...
    def logout(self) -> Any: ...
    def capabilities(self) -> Any: ...
    def select_folder(self, folder: str, readonly: bool = False) -> dict[bytes, Any]: ...
    def search(self, criteria: Any = "ALL", charset: str | None = None) -> list[int]: ...
    def fetch(self, messages: Any, data: Any, modifiers: Any = None) -> dict[int, dict[bytes, Any]]: ...
    def add_flags(self, messages: Any, flags: Any, silent: bool = False) -> Any: ...
    def remove_flags(self, messages: Any, flags: Any, silent: bool = False) -> Any: ...
    def uid_expunge(self, messages: Any) -> Any: ...


ClientFactory = Callable[..., _Client]


@dataclass(frozen=True, slots=True)
class MailboxSnapshot:
    uidvalidity: int
    uids: frozenset[int]


@dataclass(frozen=True, slots=True)
class MailboxItem:
    uid: int
    message: MailMessage | None = None
    skip_reason: str | None = None


class ScopedMailbox:
    """An IMAP session permanently scoped to one configured folder.

    No public method accepts a folder name. The semantic layer never receives
    the underlying IMAP client.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        folder: str,
        writable: bool,
        max_message_bytes: int,
        max_body_chars: int,
        timeout: float = 30.0,
        client_factory: ClientFactory | None = None,
    ) -> None:
        if not folder.strip():
            raise ValueError("folder must not be empty")
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._folder = folder
        self._writable = writable
        self._max_message_bytes = max_message_bytes
        self._max_body_chars = max_body_chars
        self._timeout = timeout
        self._client_factory = client_factory or _default_client_factory
        self._client: _Client | None = None
        self._snapshot: MailboxSnapshot | None = None

    @property
    def folder(self) -> str:
        return self._folder

    @property
    def writable(self) -> bool:
        return self._writable

    def __enter__(self) -> ScopedMailbox:
        client = self._client_factory(self._host, port=self._port, ssl=True, timeout=self._timeout)
        try:
            client.login(self._username, self._password)
            if self._writable and not _has_capability(client, b"UIDPLUS"):
                raise UnsafeMailboxOperation(
                    "destructive mode requires IMAP UIDPLUS so only approved UIDs can be expunged"
                )
            selected = client.select_folder(self._folder, readonly=not self._writable)
            uidvalidity = _uidvalidity(selected)
            uids = frozenset(int(uid) for uid in client.search("ALL"))
        except Exception:
            try:
                client.logout()
            except Exception:
                pass
            raise
        self._client = client
        self._snapshot = MailboxSnapshot(uidvalidity=uidvalidity, uids=uids)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        client = self._client
        self._client = None
        self._snapshot = None
        self._password = ""
        if client is not None:
            try:
                client.logout()
            except Exception:
                if exc is None:
                    raise

    def snapshot(self) -> MailboxSnapshot:
        if self._snapshot is None:
            raise MailboxError("mailbox is not open")
        return self._snapshot

    def iter_messages(self) -> Iterator[MailboxItem]:
        client = self._require_client()
        snapshot = self.snapshot()
        if not snapshot.uids:
            return

        ordered_uids = sorted(snapshot.uids)
        sizes = client.fetch(ordered_uids, ["RFC822.SIZE"])
        for uid in ordered_uids:
            size_data = sizes.get(uid)
            if not size_data:
                yield MailboxItem(uid=uid, skip_reason="message disappeared before size fetch")
                continue
            size = int(size_data.get(b"RFC822.SIZE", 0) or 0)
            if size > self._max_message_bytes:
                yield MailboxItem(
                    uid=uid,
                    skip_reason=f"message size {size} exceeds limit {self._max_message_bytes}",
                )
                continue

            response = client.fetch([uid], ["BODY.PEEK[]"])
            data = response.get(uid)
            if not data:
                yield MailboxItem(uid=uid, skip_reason="message disappeared before body fetch")
                continue
            raw = data.get(b"BODY[]")
            if not isinstance(raw, bytes):
                yield MailboxItem(uid=uid, skip_reason="server did not return BODY[] bytes")
                continue
            yield MailboxItem(
                uid=uid,
                message=parse_message(uid, raw, max_body_chars=self._max_body_chars),
            )

    def delete_uids(self, uids: Sequence[int]) -> None:
        if not self._writable:
            raise UnsafeMailboxOperation("mailbox is read-only")
        client = self._require_client()
        snapshot = self.snapshot()
        requested = tuple(dict.fromkeys(int(uid) for uid in uids))
        if not requested:
            return
        outside = set(requested) - snapshot.uids
        if outside:
            raise UnsafeMailboxOperation(f"refusing UIDs outside initial mailbox snapshot: {sorted(outside)}")
        if not _has_capability(client, b"UIDPLUS"):
            raise UnsafeMailboxOperation("UIDPLUS disappeared; refusing deletion")

        selected = client.select_folder(self._folder, readonly=False)
        current_uidvalidity = _uidvalidity(selected)
        if current_uidvalidity != snapshot.uidvalidity:
            raise UnsafeMailboxOperation(
                f"UIDVALIDITY changed from {snapshot.uidvalidity} to {current_uidvalidity}; refusing deletion"
            )

        current_uids = {int(uid) for uid in client.search("ALL")}
        missing = set(requested) - current_uids
        if missing:
            raise UnsafeMailboxOperation(f"approved UIDs no longer exist in scoped mailbox: {sorted(missing)}")

        try:
            client.add_flags(requested, [DELETED_FLAG], silent=True)
            client.uid_expunge(requested)
        except Exception:
            # If STORE succeeded but UID EXPUNGE did not, best-effort removal
            # avoids leaving our approved messages marked for a later broad EXPUNGE.
            try:
                client.remove_flags(requested, [DELETED_FLAG], silent=True)
            except Exception:
                pass
            raise

    def _require_client(self) -> _Client:
        if self._client is None:
            raise MailboxError("mailbox is not open")
        return self._client


def _default_client_factory(host: str, **kwargs: Any) -> _Client:
    from imapclient import IMAPClient

    return IMAPClient(host, **kwargs)


def _has_capability(client: _Client, capability: bytes) -> bool:
    values = client.capabilities()
    normalized = {item.upper() if isinstance(item, bytes) else str(item).upper().encode() for item in values}
    return capability.upper() in normalized


def _uidvalidity(selected: dict[bytes, Any]) -> int:
    value = selected.get(b"UIDVALIDITY")
    if value is None:
        raise UnsafeMailboxOperation("server did not provide UIDVALIDITY; refusing scoped operation")
    return int(value)
