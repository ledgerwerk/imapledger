from __future__ import annotations

import imaplib
import re
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .message import MailMessage, MailSummary, parse_message, parse_summary

DELETED_FLAG = "\\Deleted"


DEFAULT_FETCH_BATCH_SIZE = 100
DEFAULT_MUTATION_BATCH_SIZE = 100
DEFAULT_DELETE_BATCH_SIZE = DEFAULT_MUTATION_BATCH_SIZE
UID_SEARCH_WINDOW_SIZE = 4096


class MailboxError(RuntimeError):
    pass


class ImapOperationError(MailboxError):
    def __init__(
        self,
        *,
        operation: str,
        message: str,
        folder: str | None = None,
        selector: str | None = None,
        uids: Sequence[int] = (),
        batch: int | None = None,
        batch_count: int | None = None,
        cause_type: str | None = None,
        cause_code: str | None = None,
        server_status: str | None = None,
    ) -> None:
        super().__init__(message)
        normalized = tuple(int(uid) for uid in uids)
        self.operation = operation
        self.message = message
        self.folder = folder
        self.selector = selector
        self.uid_count = len(normalized) or None
        self.uid_min = min(normalized) if normalized else None
        self.uid_max = max(normalized) if normalized else None
        self.batch = batch
        self.batch_count = batch_count
        self.cause_type = cause_type
        self.cause_code = cause_code
        self.server_status = server_status
        self.rollback_error_type: str | None = None

    def __str__(self) -> str:
        lines = [f"error [{self.operation}]: {self.message}"]
        details = []
        if self.folder is not None:
            details.append(f"folder={self.folder!r}")
        if self.selector is not None:
            details.append(f"selector={self.selector}")
        if self.batch is not None:
            batch = f"batch={self.batch}"
            if self.batch_count is not None:
                batch += f"/{self.batch_count}"
            details.append(batch)
        if self.uid_count is not None:
            details.append(f"uid_count={self.uid_count}")
            if self.uid_min == self.uid_max:
                details.append(f"uid={self.uid_min}")
            else:
                details.extend((f"uid_min={self.uid_min}", f"uid_max={self.uid_max}"))
        if self.rollback_error_type is not None:
            details.append(f"rollback_error_type={self.rollback_error_type}")
        if self.server_status is not None:
            details.append(f"server_status={self.server_status}")
        if self.cause_code is not None:
            details.append(f"cause={self.cause_code}")
        if self.cause_type is not None:
            details.append(f"server_error_type={self.cause_type}")
        if details:
            lines.append(" ".join(details))
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class FolderInfo:
    name: str
    delimiter: str | None
    flags: frozenset[bytes]
    total: int | None
    unread: int | None
    status_error: ImapOperationError | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "flags", _normalize_folder_flags(self.flags))
        if (self.total is None) != (self.unread is None):
            raise ValueError("total and unread counts must both be available or unavailable")
        if self.total is not None and self.total < 0:
            raise ValueError("total must be non-negative")
        if self.unread is not None and self.unread < 0:
            raise ValueError("unread must be non-negative")
        if self.total is not None and self.unread is not None and self.unread > self.total:
            raise ValueError("unread must not exceed total")

    @property
    def selectable(self) -> bool:
        return b"\\NOSELECT" not in self.flags

    @property
    def read(self) -> int | None:
        if self.total is None or self.unread is None:
            return None
        return self.total - self.unread


@dataclass(frozen=True, slots=True)
class DeleteResult:
    deleted: tuple[int, ...]


class PartialDeleteError(ImapOperationError):
    def __init__(
        self,
        *,
        deleted: Sequence[int],
        pending: Sequence[int],
        failure: ImapOperationError,
    ) -> None:
        self.deleted = tuple(int(uid) for uid in deleted)
        self.pending = tuple(int(uid) for uid in pending)
        self.cause = failure
        super().__init__(
            operation=failure.operation,
            message="deletion stopped after a failed UID batch",
            folder=failure.folder,
            selector=failure.selector,
            uids=self.pending,
            batch=failure.batch,
            batch_count=failure.batch_count,
            cause_type=failure.cause_type,
            cause_code=failure.cause_code,
            server_status=failure.server_status,
        )
        self.rollback_error_type = failure.rollback_error_type

    def __str__(self) -> str:
        return f"{super().__str__()}\nconfirmed_deleted_count={len(self.deleted)} pending_count={len(self.pending)}"


@dataclass(frozen=True, slots=True)
class MoveResult:
    moved: tuple[int, ...]
    destination: str


class PartialMoveError(ImapOperationError):
    def __init__(
        self,
        *,
        moved: Sequence[int],
        pending: Sequence[int],
        destination: str,
        failure: ImapOperationError,
    ) -> None:
        self.moved = tuple(int(uid) for uid in moved)
        self.pending = tuple(int(uid) for uid in pending)
        self.destination = destination
        self.cause = failure
        super().__init__(
            operation=failure.operation,
            message="move stopped after a failed UID batch",
            folder=failure.folder,
            selector=failure.selector,
            uids=self.pending,
            batch=failure.batch,
            batch_count=failure.batch_count,
            cause_type=failure.cause_type,
            cause_code=failure.cause_code,
            server_status=failure.server_status,
        )

    def __str__(self) -> str:
        return (
            f"{super().__str__()} destination={self.destination!r}\n"
            f"confirmed_moved_count={len(self.moved)} pending_count={len(self.pending)}"
        )


class UnsafeMailboxOperation(MailboxError):
    pass


class _Client(Protocol):
    use_uid: bool

    def login(self, username: str, password: str) -> Any: ...
    def logout(self) -> Any: ...
    def capabilities(self) -> Any: ...
    def select_folder(self, folder: str, readonly: bool = False) -> dict[bytes, Any]: ...
    def folder_exists(self, folder: str) -> bool: ...
    def search(self, criteria: Any = "ALL", charset: str | None = None) -> list[int]: ...
    def fetch(self, messages: Any, data: Any, modifiers: Any = None) -> dict[int, dict[bytes, Any]]: ...
    def move(self, messages: Any, folder: str) -> Any: ...
    def add_flags(self, messages: Any, flags: Any, silent: bool = False) -> Any: ...
    def uid_expunge(self, messages: Any) -> Any: ...


class _FolderClient(Protocol):
    def login(self, username: str, password: str) -> Any: ...
    def logout(self) -> Any: ...
    def list_folders(self, directory: str = "", pattern: str = "*") -> Any: ...
    def folder_status(self, folder: str, what: Any = None) -> Mapping[Any, Any]: ...


FolderClientFactory = Callable[..., _FolderClient]

ClientFactory = Callable[..., _Client]


@dataclass(frozen=True, slots=True)
class MailboxSnapshot:
    uidvalidity: int
    uids: frozenset[int]
    uidnext: int | None = None


@dataclass(frozen=True, slots=True)
class MailboxRunMetadata:
    uidvalidity: int
    uidnext: int

    @property
    def high_watermark_uid(self) -> int:
        return self.uidnext - 1


class MessageSort(str, Enum):
    NEWEST = "newest"
    OLDEST = "oldest"


@dataclass(frozen=True, slots=True)
class MessageSelection:
    limit: int | None = None
    offset: int = 0
    sort: MessageSort = MessageSort.NEWEST


    def __post_init__(self) -> None:
        if self.limit is not None and self.limit < 1:
            raise ValueError("limit must be positive")
        if self.offset < 0:
            raise ValueError("offset must be non-negative")
        if not isinstance(self.sort, MessageSort):
            raise ValueError("sort must be a MessageSort")


@dataclass(frozen=True, slots=True)
class MailboxProbe:
    uidvalidity: int
    message_count: int
    uid_min: int | None
    uid_max: int | None
    size_fetch_uid: int | None
    body_fetch_uid: int | None
    body_skip_reason: str | None


@dataclass(frozen=True, slots=True)
class MailboxItem:
    uid: int
    message: MailMessage | None = None
    skip_reason: str | None = None


class FolderCatalog:
    """A read-only account-wide view of IMAP folder metadata."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = 30.0,
        client_factory: FolderClientFactory | None = None,
        event_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._client_factory = client_factory or _default_folder_client_factory
        self._event_callback = event_callback
        self._client: _FolderClient | None = None

    def __enter__(self) -> FolderCatalog:
        self._emit(f"connect host={self._host} port={self._port} tls=true")
        try:
            client = self._client_factory(
                self._host,
                port=self._port,
                ssl=True,
                timeout=self._timeout,
                use_uid=True,
            )
        except Exception as exc:
            raise _operation_error(
                operation="imap_connect",
                message="could not establish IMAP connection",
                exc=exc,
            ) from exc
        self._emit("TLS connect: OK")

        try:
            try:
                client.login(self._username, self._password)
            except Exception as exc:
                raise _operation_error(
                    operation="imap_login",
                    message="IMAP login failed",
                    exc=exc,
                ) from exc
            finally:
                self._password = ""
            self._client = client
            self._emit("login ok")
        except Exception:
            try:
                client.logout()
            except Exception:
                pass
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        client = self._client
        self._client = None
        self._password = ""
        if client is None:
            return
        try:
            client.logout()
        except Exception as logout_exc:
            if exc is None:
                raise _operation_error(
                    operation="imap_logout",
                    message="IMAP logout failed",
                    exc=logout_exc,
                ) from logout_exc
        else:
            self._emit("logout: OK")

    def list_folders(self, include_counts: bool = True) -> tuple[FolderInfo, ...]:
        client = self._require_client()
        try:
            folders = client.list_folders()
        except Exception as exc:
            raise _operation_error(
                operation="imap_list_folders",
                message="could not list IMAP folders",
                exc=exc,
            ) from exc

        self._emit(f"LIST folders: {len(folders)}")
        rows = []
        for raw_flags, raw_delimiter, raw_name in folders:
            flags = _normalize_folder_flags(raw_flags)
            delimiter = _normalize_folder_delimiter(raw_delimiter)
            name = raw_name.decode("utf-8") if isinstance(raw_name, bytes) else str(raw_name)
            total = None
            unread = None
            status_error = None
            if include_counts and b"\\NOSELECT" not in flags:
                try:
                    status = client.folder_status(name, ("MESSAGES", "UNSEEN"))
                    total = _status_int(status, "MESSAGES")
                    unread = _status_int(status, "UNSEEN")
                    if unread > total:
                        raise ValueError("UNSEEN exceeds MESSAGES")
                except Exception as exc:
                    total = None
                    unread = None
                    status_error = _operation_error(
                        operation="imap_folder_status",
                        message="could not read mailbox counts",
                        exc=exc,
                        folder=name,
                    )
                    self._emit(f"STATUS folder={name!r}: FAILED")
                else:
                    self._emit(f"STATUS folder={name!r}: OK messages={total} unseen={unread}")
            elif include_counts:
                self._emit(f"STATUS folder={name!r}: SKIPPED (\\Noselect)")
            rows.append(
                FolderInfo(
                    name=name,
                    delimiter=delimiter,
                    flags=flags,
                    total=total,
                    unread=unread,
                    status_error=status_error,
                )
            )
        return tuple(sorted(rows, key=lambda row: (row.name.casefold(), row.name)))

    def folder_counts(self, folders: Sequence[str]) -> dict[str, tuple[int, int]]:
        client = self._require_client()
        counts = {}
        for folder in folders:
            try:
                status = client.folder_status(folder, ("MESSAGES", "UNSEEN"))
                total = _status_int(status, "MESSAGES")
                unread = _status_int(status, "UNSEEN")
                if unread > total:
                    raise ValueError("UNSEEN exceeds MESSAGES")
            except Exception as exc:
                raise _operation_error(
                    operation="imap_folder_status",
                    message="could not read mailbox counts",
                    exc=exc,
                    folder=folder,
                ) from exc
            counts[folder] = (total, unread)
        return counts

    def _emit(self, event: str) -> None:
        if self._event_callback is not None:
            self._event_callback(event)

    def _require_client(self) -> _FolderClient:
        if self._client is None:
            raise MailboxError("folder catalog is not open")
        return self._client


def _normalize_uid_scope(values: Collection[int] | None) -> tuple[int, ...] | None:
    if values is None:
        return None
    normalized: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("uid_scope must contain positive integer UIDs")
        normalized.add(value)
    return tuple(sorted(normalized))


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
        fetch_batch_size: int = DEFAULT_FETCH_BATCH_SIZE,
        mutation_batch_size: int = DEFAULT_MUTATION_BATCH_SIZE,
        delete_batch_size: int | None = None,
        allowed_destinations: Collection[str] = (),
        allow_delete: bool = False,
        uid_scope: Collection[int] | None = None,
        cursor_oriented: bool = False,
        client_factory: ClientFactory | None = None,
        event_callback: Callable[[str], None] | None = None,
    ) -> None:
        if not folder.strip() or folder != folder.strip():
            raise ValueError("folder must be non-empty and have no surrounding whitespace")
        destinations = tuple(allowed_destinations)
        if any(not isinstance(destination, str) or not destination.strip() for destination in destinations):
            raise ValueError("allowed destinations must be non-empty strings")
        if any(destination != destination.strip() for destination in destinations):
            raise ValueError("allowed destinations must not have surrounding whitespace")
        self._allowed_destinations = frozenset(destinations)
        self._allow_delete = allow_delete
        self._host = host
        self._uid_scope = _normalize_uid_scope(uid_scope)
        self._cursor_oriented = cursor_oriented
        self._port = port
        self._username = username
        self._password = password
        self._folder = folder
        self._writable = writable
        self._max_message_bytes = max_message_bytes
        self._max_body_chars = max_body_chars
        if fetch_batch_size <= 0:
            raise ValueError("fetch_batch_size must be positive")
        if delete_batch_size is not None:
            mutation_batch_size = delete_batch_size
        if mutation_batch_size <= 0:
            raise ValueError("mutation_batch_size must be positive")
        self._timeout = timeout
        self._fetch_batch_size = fetch_batch_size
        self._mutation_batch_size = mutation_batch_size
        self._client_factory = client_factory or _default_client_factory
        self._event_callback = event_callback
        self._client: _Client | None = None
        self._snapshot: MailboxSnapshot | None = None
        self._capabilities: frozenset[bytes] | None = None

    @property
    def folder(self) -> str:
        return self._folder

    @property
    def writable(self) -> bool:
        return self._writable

    @property
    def capabilities(self) -> frozenset[bytes]:
        if self._capabilities is None:
            raise MailboxError("mailbox is not open")
        return self._capabilities

    def destination_exists(self, destination: str) -> bool:
        if destination not in self._allowed_destinations:
            raise UnsafeMailboxOperation("refusing to inspect a destination outside the configured allow-list")
        client = self._require_client()
        try:
            exists = bool(client.folder_exists(destination))
        except Exception as exc:
            failure = _operation_error(
                operation="imap_folder_exists",
                message="could not verify configured move destination",
                exc=exc,
                folder=self._folder,
                selector=destination,
            )
            try:
                self._reselect_source(operation="imap_post_destination_select")
            except Exception as restore_exc:
                self._emit(f"source restore after destination probe failed error_type={type(restore_exc).__name__}")
            raise failure from exc
        self._reselect_source(operation="imap_post_destination_select")
        return exists

    def validate_destination(self, destination: str) -> None:
        if not self.destination_exists(destination):
            raise UnsafeMailboxOperation(f"configured destination does not exist: {destination}")

    def __enter__(self) -> ScopedMailbox:
        self._emit(f"connect host={self._host} port={self._port} tls=true")
        try:
            client = self._client_factory(self._host, port=self._port, ssl=True, timeout=self._timeout, use_uid=True)
        except Exception as exc:
            raise _operation_error(
                operation="imap_connect",
                message="could not establish IMAP connection",
                exc=exc,
            ) from exc
        self._emit("TLS connect: OK")

        try:
            try:
                client.login(self._username, self._password)
            except Exception as exc:
                raise _operation_error(
                    operation="imap_login",
                    message="IMAP login failed",
                    exc=exc,
                ) from exc
            finally:
                self._password = ""
            self._emit("login ok")

            try:
                capabilities = client.capabilities()
            except Exception as exc:
                raise _operation_error(
                    operation="imap_capabilities",
                    message="could not read IMAP capabilities",
                    exc=exc,
                ) from exc
            self._emit(f"capabilities count={len(capabilities)}")
            normalized_capabilities = frozenset(_normalize_capabilities(capabilities))
            if self._writable and self._allowed_destinations and b"MOVE" not in normalized_capabilities:
                raise UnsafeMailboxOperation("configured move action requires IMAP MOVE")
            if self._writable and self._allow_delete and b"UIDPLUS" not in normalized_capabilities:
                raise UnsafeMailboxOperation("configured delete action requires IMAP UIDPLUS")

            try:
                source_exists = bool(client.folder_exists(self._folder))
            except Exception as exc:
                raise _operation_error(
                    operation="imap_source_folder_exists",
                    message="could not verify configured source folder",
                    exc=exc,
                    folder=self._folder,
                ) from exc
            if not source_exists:
                raise ImapOperationError(
                    operation="imap_source_folder_missing",
                    message="configured source folder does not exist",
                    folder=self._folder,
                )
            self._emit(f"source folder exists: {self._folder!r}")

            try:
                selected = client.select_folder(self._folder, readonly=not self._writable)
            except Exception as exc:
                raise _operation_error(
                    operation="imap_select_folder",
                    message="configured source folder exists but could not be selected",
                    exc=exc,
                    folder=self._folder,
                ) from exc
            self._emit(f"select folder={self._folder!r} readonly={not self._writable}")
            uidvalidity = _uidvalidity(selected)
            uidnext = _uidnext(selected) if self._cursor_oriented else None


            self._emit(f"uidvalidity={uidvalidity}")

            uids = self._initial_uid_snapshot(client, selected)
            self._emit(f"snapshot messages={len(uids)}")
        except Exception:
            try:
                client.logout()
            except Exception:
                pass
            raise
        self._client = client
        self._snapshot = MailboxSnapshot(
            uidvalidity=uidvalidity,
            uids=uids,


            uidnext=uidnext,
        )
        self._capabilities = normalized_capabilities
        return self

    def _initial_uid_snapshot(
        self,
        client: _Client,
        selected: Mapping[bytes, Any],
    ) -> frozenset[int]:
        if self._cursor_oriented:
            return frozenset()
        if self._uid_scope is None:
            return self._fetch_full_uid_snapshot(client, selected)
        if not self._uid_scope:
            return frozenset()
        return frozenset(
            uid for uid in self._uid_scope if self._search_exact_uid(client, uid, operation="imap_initial_scope_search")
        )

    def _fetch_full_uid_snapshot(
        self,
        client: _Client,
        selected: Mapping[bytes, Any],
    ) -> frozenset[int]:
        exists = selected.get(b"EXISTS", selected.get("EXISTS", 0))
        try:
            exists_count = int(exists)
        except (TypeError, ValueError) as exc:
            raise _operation_error(
                operation="imap_uid_snapshot",
                message="selected mailbox returned malformed EXISTS metadata",
                exc=exc,
                folder=self._folder,
            ) from exc
        if exists_count < 0:
            raise ImapOperationError(
                operation="imap_uid_snapshot",
                message="selected mailbox returned malformed EXISTS metadata",
                folder=self._folder,
            )
        if exists_count == 0:
            return frozenset()

        try:
            response = client.fetch("1:*", ["UID"])
        except Exception as exc:
            raise _operation_error(
                operation="imap_uid_snapshot",
                message="UID FETCH failed while building mailbox snapshot",
                exc=exc,
                folder=self._folder,
                selector="1:* UID",
            ) from exc

        uids: set[int] = set()
        try:
            if not isinstance(response, Mapping):
                raise TypeError("FETCH response is not a mapping")
            for key, data in response.items():
                if isinstance(key, bool) or not isinstance(key, int) or key < 1:
                    raise ValueError("FETCH response has an invalid message key")
                if not isinstance(data, Mapping):
                    raise TypeError("FETCH response data is not a mapping")
                uid = data.get(b"UID", data.get("UID", key if client.use_uid else None))
                if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
                    raise ValueError("FETCH response has an invalid UID")
                if client.use_uid and uid != key:
                    raise ValueError("FETCH response UID does not match its UID key")
                uids.add(uid)
        except (TypeError, ValueError) as exc:
            raise _operation_error(
                operation="imap_uid_snapshot",
                message="UID FETCH returned malformed UID data",
                exc=exc,
                folder=self._folder,
                selector="1:* UID",
            ) from exc
        return frozenset(uids)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        client = self._client
        self._client = None
        self._snapshot = None
        self._capabilities = None
        self._password = ""
        if client is not None:
            try:
                client.logout()
            except Exception as logout_exc:
                if exc is None:
                    raise _operation_error(
                        operation="imap_logout",
                        message="IMAP logout failed",
                        exc=logout_exc,
                        folder=self._folder,
                    ) from logout_exc

    def snapshot(self) -> MailboxSnapshot:
        if self._snapshot is None:
            raise MailboxError("mailbox is not open")
        return self._snapshot

    def metadata(self) -> MailboxRunMetadata:
        if not self._cursor_oriented:
            raise MailboxError("mailbox was not opened in cursor-oriented mode")
        snapshot = self.snapshot()
        if snapshot.uidnext is None:
            raise MailboxError("selected mailbox has no UIDNEXT metadata")
        return MailboxRunMetadata(snapshot.uidvalidity, snapshot.uidnext)

    def find_next_uids(
        self,
        *,
        cursor_uid: int | None,
        high_watermark_uid: int,
        limit: int,
        direction: str,
        lower_bound_uid: int = 0,
    ) -> tuple[int, ...]:
        if not self._cursor_oriented:
            raise MailboxError("mailbox was not opened in cursor-oriented mode")
        metadata = self.metadata()
        if isinstance(high_watermark_uid, bool) or not isinstance(high_watermark_uid, int):
            raise ValueError("high-watermark UID must be an integer")
        if not 0 <= high_watermark_uid <= metadata.high_watermark_uid:
            raise ValueError("high-watermark UID is outside the selected mailbox snapshot")
        if isinstance(lower_bound_uid, bool) or not isinstance(lower_bound_uid, int):
            raise ValueError("lower-bound UID must be an integer")
        if not 0 <= lower_bound_uid <= high_watermark_uid:
            raise ValueError("lower-bound UID is outside the stable run range")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("UID window limit must be a positive integer")
        if direction not in {"oldest", "newest"}:
            raise ValueError("UID scan direction must be oldest or newest")
        if cursor_uid is not None and (
            isinstance(cursor_uid, bool) or not isinstance(cursor_uid, int) or cursor_uid < 0
        ):
            raise ValueError("UID cursor must be a non-negative integer")

        found: list[int] = []
        if direction == "oldest":
            start = max(cursor_uid or lower_bound_uid, lower_bound_uid) + 1
            while start <= high_watermark_uid and len(found) < limit:
                end = min(start + UID_SEARCH_WINDOW_SIZE - 1, high_watermark_uid)
                found.extend(self._search_uid_window(start, end))
                start = end + 1
            return tuple(found[:limit])

        cursor = high_watermark_uid + 1 if cursor_uid is None else cursor_uid
        end = min(cursor - 1, high_watermark_uid)
        while end > lower_bound_uid and len(found) < limit:
            start = max(lower_bound_uid + 1, end - UID_SEARCH_WINDOW_SIZE + 1)
            found.extend(reversed(self._search_uid_window(start, end)))
            end = start - 1
        return tuple(found[:limit])

    def _search_uid_window(self, start: int, end: int) -> tuple[int, ...]:
        client = self._reselect_source(operation="imap_uid_window_select")
        selector = f"UID {start}:{end}"
        try:
            response = client.search(["UID", f"{start}:{end}"])
            uids = tuple(int(uid) for uid in response)
            if any(uid < start or uid > end for uid in uids):
                raise ValueError("UID SEARCH returned a UID outside its requested range")
        except Exception as exc:
            raise _operation_error(
                operation="imap_uid_window_search",
                message="bounded UID SEARCH failed",
                exc=exc,
                folder=self._folder,
                selector=selector,
            ) from exc
        return tuple(sorted(set(uids)))

    def fetch_items(self, uids: Sequence[int], *, high_watermark_uid: int) -> tuple[MailboxItem, ...]:
        if not self._cursor_oriented:
            raise MailboxError("mailbox was not opened in cursor-oriented mode")
        metadata = self.metadata()
        requested = tuple(uids)
        if len(set(requested)) != len(requested):
            raise ValueError("UID fetch request must not contain duplicates")
        if isinstance(high_watermark_uid, bool) or not isinstance(high_watermark_uid, int):
            raise ValueError("high-watermark UID must be an integer")
        if not 0 <= high_watermark_uid <= metadata.high_watermark_uid:
            raise ValueError("high-watermark UID is outside the selected mailbox snapshot")
        if any(
            isinstance(uid, bool) or not isinstance(uid, int) or uid < 1 or uid > high_watermark_uid
            for uid in requested
        ):
            raise ValueError("fetch UID is outside the stable run high-watermark")
        if not requested:
            return ()

        items: dict[int, MailboxItem] = {}
        for batch in _iter_chunks(requested, self._fetch_batch_size):
            client = self._reselect_source(operation="imap_processing_size_select")
            try:
                sizes = client.fetch(batch, ["RFC822.SIZE"])
            except Exception as exc:
                raise _operation_error(
                    operation="imap_processing_size_fetch",
                    message="batched RFC822.SIZE FETCH failed",
                    exc=exc,
                    folder=self._folder,
                    selector="RFC822.SIZE",
                    uids=batch,
                ) from exc
            eligible: list[int] = []
            message_sizes: dict[int, int] = {}
            for uid in batch:
                data = sizes.get(uid)
                if data is None:
                    items[uid] = MailboxItem(uid=uid, skip_reason="message disappeared before size fetch")
                    continue
                size = _fetch_size_value(data) if isinstance(data, Mapping) else None
                if size is None:
                    raise ImapOperationError(
                        operation="imap_processing_size_fetch",
                        message="server returned invalid RFC822.SIZE",
                        folder=self._folder,
                        selector="RFC822.SIZE",
                        uids=(uid,),
                    )
                if size > self._max_message_bytes:
                    items[uid] = MailboxItem(
                        uid=uid,
                        skip_reason=f"message size {size} exceeds limit {self._max_message_bytes}",
                    )
                    continue
                eligible.append(uid)
                message_sizes[uid] = size

            for body_batch in _iter_chunks(tuple(eligible), self._fetch_batch_size):
                client = self._reselect_source(operation="imap_processing_body_select")
                try:
                    bodies = client.fetch(body_batch, ["BODY.PEEK[]"])
                except Exception as exc:
                    raise _operation_error(
                        operation="imap_processing_body_fetch",
                        message="batched BODY.PEEK[] FETCH failed",
                        exc=exc,
                        folder=self._folder,
                        selector="BODY.PEEK[]",
                        uids=body_batch,
                    ) from exc
                for uid in body_batch:
                    data = bodies.get(uid)
                    if not isinstance(data, Mapping):
                        items[uid] = MailboxItem(uid=uid, skip_reason="message disappeared before body fetch")
                        continue
                    raw = data.get(b"BODY[]", data.get("BODY[]"))
                    if not isinstance(raw, bytes):
                        items[uid] = MailboxItem(uid=uid, skip_reason="server did not return BODY[] bytes")
                        continue
                    items[uid] = MailboxItem(
                        uid=uid,
                        message=parse_message(
                            uid,
                            raw,
                            max_body_chars=self._max_body_chars,
                            size_bytes=message_sizes[uid],
                        ),
                    )
        return tuple(items[uid] for uid in requested)


    def fetch_headers(self, uid: int) -> MailMessage | None:
        self._validate_snapshot_uid(uid)
        client = self._reselect_source(operation="imap_fetch_headers_select")
        if not self._search_exact_uid(client, uid, operation="imap_fetch_headers_search"):
            return None
        selector = "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]"
        try:
            response = client.fetch((uid,), [selector])
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_headers",
                message="FETCH of message headers failed",
                exc=exc,
                folder=self._folder,
                selector=selector,
                uids=(uid,),
            ) from exc
        data = response.get(uid)
        if not data:
            return None
        raw = next(
            (
                value
                for key, value in data.items()
                if isinstance(key, bytes) and key.upper().startswith(b"BODY[HEADER.FIELDS")
            ),
            None,
        )
        if not isinstance(raw, bytes):
            raise ImapOperationError(
                operation="imap_fetch_headers",
                message="server did not return the requested message headers",
                folder=self._folder,
                selector=selector,
                uids=(uid,),
            )
        return parse_message(uid, raw, max_body_chars=0)

    def fetch_summaries(self, uids: Sequence[int]) -> tuple[MailSummary, ...]:
        requested = tuple(uids)
        for uid in requested:
            self._validate_snapshot_uid(uid)
        if not requested:
            return ()

        selector = "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]"
        fetch_data = [selector, "FLAGS", "RFC822.SIZE"]
        summaries: dict[int, MailSummary] = {}
        for offset in range(0, len(requested), self._fetch_batch_size):
            batch = requested[offset : offset + self._fetch_batch_size]
            client = self._reselect_source(operation="imap_fetch_summaries_select")
            try:
                response = client.fetch(batch, fetch_data)
            except Exception as exc:
                raise _operation_error(
                    operation="imap_fetch_summaries",
                    message="FETCH of message summaries failed",
                    exc=exc,
                    folder=self._folder,
                    selector=f"{selector} FLAGS RFC822.SIZE",
                    uids=batch,
                ) from exc
            for uid in batch:
                data = response.get(uid)
                if not isinstance(data, Mapping):
                    summaries[uid] = _skipped_summary(uid, "message disappeared before header fetch")
                    continue
                raw_headers = _fetch_header_bytes(data)
                if raw_headers is None:
                    summaries[uid] = _skipped_summary(uid, "server did not return message headers")
                    continue
                flags = _fetch_flags_value(data)
                size = _fetch_size_value(data)
                if flags is None:
                    summaries[uid] = _skipped_summary(uid, "server did not return message flags")
                    continue
                summaries[uid] = parse_summary(uid, raw_headers, flags=flags, size_bytes=size)
        return tuple(summaries[uid] for uid in requested)


    def _validate_snapshot_uid(self, uid: int) -> None:
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            raise ValueError("uid must be a positive integer")
        if uid not in self.snapshot().uids:
            raise UnsafeMailboxOperation(f"refusing UID outside initial mailbox snapshot: {uid}")

    def _search_exact_uid(self, client: _Client, uid: int, *, operation: str) -> bool:
        try:
            found = client.search(["UID", uid])
        except Exception as exc:
            raise _operation_error(
                operation=operation,
                message="exact UID SEARCH failed in scoped mailbox",
                exc=exc,
                folder=self._folder,
                selector=f"UID {uid}",
                uids=(uid,),
            ) from exc
        return uid in {int(found_uid) for found_uid in found}



    def _reselect_source(self, *, readonly: bool | None = None, operation: str) -> _Client:
        client, _ = self._reselect_source_with_response(readonly=readonly, operation=operation)
        return client

    def _reselect_source_with_response(
        self,
        *,
        readonly: bool | None = None,
        operation: str,
    ) -> tuple[_Client, Mapping[bytes, Any]]:
        client = self._require_client()
        if readonly is None:
            readonly = not self._writable
        try:
            selected = client.select_folder(self._folder, readonly=readonly)
        except Exception as exc:
            raise _operation_error(
                operation=operation,
                message="could not reselect configured source folder",
                exc=exc,
                folder=self._folder,
            ) from exc

        snapshot = self._snapshot
        if snapshot is not None:
            current_uidvalidity = _uidvalidity(selected)
            if current_uidvalidity != snapshot.uidvalidity:
                raise UnsafeMailboxOperation(
                    f"UIDVALIDITY changed from {snapshot.uidvalidity} to {current_uidvalidity}; "
                    "refusing source operation"
                )
        self._emit(f"reselect folder={self._folder!r} readonly={readonly}")
        return client, selected

    def probe(self) -> MailboxProbe:
        client = self._require_client()
        snapshot = self.snapshot()
        ordered_uids = sorted(snapshot.uids)
        if not ordered_uids:
            return MailboxProbe(
                uidvalidity=snapshot.uidvalidity,
                message_count=0,
                uid_min=None,
                uid_max=None,
                size_fetch_uid=None,
                body_fetch_uid=None,
                body_skip_reason="mailbox is empty",
            )

        uid = ordered_uids[0]
        self._emit(f"doctor-size-fetch uid={uid}")
        client = self._reselect_source(operation="imap_preprobe_select")
        try:
            sizes = client.fetch([uid], ["RFC822.SIZE"])
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_size",
                message="FETCH failed while reading RFC822.SIZE",
                exc=exc,
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            ) from exc
        size_data = sizes.get(uid)
        if not size_data:
            raise ImapOperationError(
                operation="imap_fetch_size",
                message="server did not return RFC822.SIZE for probe UID",
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            )
        try:
            size = int(size_data.get(b"RFC822.SIZE", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise _operation_error(
                operation="imap_fetch_size",
                message="server returned invalid RFC822.SIZE for probe UID",
                exc=exc,
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            ) from exc

        body_fetch_uid = None
        body_skip_reason = None
        if size > self._max_message_bytes:
            body_skip_reason = f"probe message size {size} exceeds limit {self._max_message_bytes}"
        else:
            self._emit(f"doctor-body-fetch uid={uid}")
            client = self._reselect_source(operation="imap_prebody_select")
            try:
                response = client.fetch([uid], ["BODY.PEEK[]"])
            except Exception as exc:
                raise _operation_error(
                    operation="imap_fetch_body",
                    message="FETCH failed while reading BODY.PEEK[]",
                    exc=exc,
                    folder=self._folder,
                    selector="BODY.PEEK[]",
                    uids=(uid,),
                ) from exc
            body_data = response.get(uid)
            raw = body_data.get(b"BODY[]") if body_data else None
            if not isinstance(raw, bytes):
                raise ImapOperationError(
                    operation="imap_fetch_body",
                    message="server did not return BODY[] bytes for probe UID",
                    folder=self._folder,
                    selector="BODY.PEEK[]",
                    uids=(uid,),
                )
            body_fetch_uid = uid

        return MailboxProbe(
            uidvalidity=snapshot.uidvalidity,
            message_count=len(ordered_uids),
            uid_min=ordered_uids[0],
            uid_max=ordered_uids[-1],
            size_fetch_uid=uid,
            body_fetch_uid=body_fetch_uid,
            body_skip_reason=body_skip_reason,
        )

    def fetch_uid(self, uid: int) -> MailboxItem:
        client = self._require_client()
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            raise ValueError("uid must be a positive integer")
        if uid not in self.snapshot().uids:
            raise UnsafeMailboxOperation(f"refusing UID outside initial mailbox snapshot: {uid}")

        self._emit(f"size-fetch uid={uid}")
        client = self._reselect_source(operation="imap_prefetch_select")
        try:
            sizes = client.fetch((uid,), ["RFC822.SIZE"])
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_size",
                message="FETCH failed while reading RFC822.SIZE",
                exc=exc,
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            ) from exc
        size_data = sizes.get(uid)
        if not size_data:
            return MailboxItem(uid=uid, skip_reason="message disappeared before size fetch")
        try:
            size_value = size_data.get(b"RFC822.SIZE")
            if size_value is None:
                raise ValueError("missing RFC822.SIZE")
            size = int(size_value)
            if size < 0:
                raise ValueError("negative RFC822.SIZE")
        except (TypeError, ValueError) as exc:
            raise _operation_error(
                operation="imap_fetch_size",
                message="server returned invalid RFC822.SIZE",
                exc=exc,
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            ) from exc
        if size > self._max_message_bytes:
            return MailboxItem(
                uid=uid,
                skip_reason=f"message size {size} exceeds limit {self._max_message_bytes}",
            )

        self._emit(f"body-fetch uid={uid}")
        client = self._reselect_source(operation="imap_prebody_select")
        try:
            response = client.fetch((uid,), ["BODY.PEEK[]"])
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_body",
                message="FETCH failed while reading BODY.PEEK[]",
                exc=exc,
                folder=self._folder,
                selector="BODY.PEEK[]",
                uids=(uid,),
            ) from exc
        body_data = response.get(uid)
        if not body_data:
            return MailboxItem(uid=uid, skip_reason="message disappeared before body fetch")
        raw = body_data.get(b"BODY[]")
        if not isinstance(raw, bytes):
            return MailboxItem(uid=uid, skip_reason="server did not return BODY[] bytes")
        return MailboxItem(
            uid=uid,
            message=parse_message(uid, raw, max_body_chars=self._max_body_chars, size_bytes=size),
        )

    def selected_count(self, selection: MessageSelection) -> int:
        return len(self._selected_uids(selection))

    def _selected_uids(self, selection: MessageSelection) -> tuple[int, ...]:
        uids = self.snapshot().uids
        ordered_uids = sorted(
            uids,
            reverse=selection.sort is MessageSort.NEWEST,
        )
        selected_uids = ordered_uids[selection.offset :]
        if selection.limit is not None:
            selected_uids = selected_uids[: selection.limit]
        return tuple(selected_uids)

    def iter_messages(
        self,
        selection: MessageSelection | None = None,
    ) -> Iterator[MailboxItem]:
        client = self._require_client()
        selected_uids = self._selected_uids(selection or MessageSelection())
        if not selected_uids:
            return

        batch_count = (len(selected_uids) + self._fetch_batch_size - 1) // self._fetch_batch_size
        for batch_number, uid_batch in enumerate(
            _iter_chunks(selected_uids, self._fetch_batch_size),
            start=1,
        ):
            self._emit(
                f"size-fetch batch={batch_number}/{batch_count} uid_count={len(uid_batch)} "
                f"uid_min={min(uid_batch)} uid_max={max(uid_batch)}"
            )
            client = self._reselect_source(operation="imap_prefetch_select")
            try:
                sizes = client.fetch(uid_batch, ["RFC822.SIZE"])
            except Exception as exc:
                raise _operation_error(
                    operation="imap_fetch_size",
                    message="FETCH failed while reading RFC822.SIZE",
                    exc=exc,
                    folder=self._folder,
                    selector="RFC822.SIZE",
                    uids=uid_batch,
                    batch=batch_number,
                    batch_count=batch_count,
                ) from exc

            for uid in uid_batch:
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

                self._emit(f"body-fetch uid={uid}")
                client = self._reselect_source(operation="imap_prebody_select")
                try:
                    response = client.fetch([uid], ["BODY.PEEK[]"])
                except Exception as exc:
                    raise _operation_error(
                        operation="imap_fetch_body",
                        message="FETCH failed while reading BODY.PEEK[]",
                        exc=exc,
                        folder=self._folder,
                        selector="BODY.PEEK[]",
                        uids=(uid,),
                    ) from exc
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
                    message=parse_message(uid, raw, max_body_chars=self._max_body_chars, size_bytes=size),
                )

    def move_uid(self, uid: int, destination: str) -> MoveResult:
        if destination not in self._allowed_destinations:
            raise UnsafeMailboxOperation("refusing to move to a destination outside the configured allow-list")
        if destination == self._folder:
            raise UnsafeMailboxOperation("refusing to move messages to their source folder")
        client, uid = self._validate_streaming_mutation_uid(
            uid,
            required_capability=b"MOVE",
            operation_prefix="move",
        )
        self._emit(f"streaming move destination={destination!r} uid={uid}")
        try:
            client.move((uid,), destination)
        except Exception as exc:
            failure = _operation_error(
                operation="imap_uid_move",
                message="UID MOVE failed",
                exc=exc,
                folder=self._folder,
                selector=f"destination={destination}",
                uids=(uid,),
            )
            raise PartialMoveError(
                moved=(),
                pending=(uid,),
                destination=destination,
                failure=failure,
            ) from exc
        return MoveResult(moved=(uid,), destination=destination)

    def move_uids(self, uids: Sequence[int], destination: str) -> MoveResult:
        if destination not in self._allowed_destinations:
            raise UnsafeMailboxOperation("refusing to move to a destination outside the configured allow-list")
        if destination == self._folder:
            raise UnsafeMailboxOperation("refusing to move messages to their source folder")
        client, requested = self._validate_mutation_uids(
            uids,
            required_capability=b"MOVE",
            operation_prefix="move",
        )
        if not requested:
            return MoveResult(moved=(), destination=destination)
        batch_count = (len(requested) + self._mutation_batch_size - 1) // self._mutation_batch_size
        completed: list[int] = []
        for batch_number, uid_batch in enumerate(_iter_chunks(requested, self._mutation_batch_size), start=1):
            if batch_number > 1:
                client = self._reselect_source(readonly=False, operation="imap_premove_select")
            self._emit(
                f"move batch={batch_number}/{batch_count} destination={destination!r} "
                f"uid_count={len(uid_batch)} uid_min={min(uid_batch)} uid_max={max(uid_batch)}"
            )
            try:
                client.move(uid_batch, destination)
            except Exception as exc:
                failure = _operation_error(
                    operation="imap_uid_move",
                    message="UID MOVE failed",
                    exc=exc,
                    folder=self._folder,
                    selector=f"destination={destination}",
                    uids=uid_batch,
                    batch=batch_number,
                    batch_count=batch_count,
                )
                raise PartialMoveError(
                    moved=completed,
                    pending=requested[len(completed) :],
                    destination=destination,
                    failure=failure,
                ) from exc
            completed.extend(uid_batch)
        return MoveResult(moved=tuple(completed), destination=destination)

    def delete_uid(self, uid: int) -> DeleteResult:
        if not self._allow_delete:
            raise UnsafeMailboxOperation("deletion requires explicit authorization")
        client, uid = self._validate_streaming_mutation_uid(
            uid,
            required_capability=b"UIDPLUS",
            operation_prefix="delete",
        )
        self._emit(f"streaming delete uid={uid}")
        try:
            self._delete_batch(client, (uid,))
        except ImapOperationError as failure:
            failure.batch = 1
            failure.batch_count = 1
            raise PartialDeleteError(deleted=(), pending=(uid,), failure=failure) from failure
        return DeleteResult(deleted=(uid,))

    def delete_uids(self, uids: Sequence[int]) -> DeleteResult:
        if not self._allow_delete:
            raise UnsafeMailboxOperation("deletion requires explicit authorization")
        client, requested = self._validate_mutation_uids(
            uids,
            required_capability=b"UIDPLUS",
            operation_prefix="delete",
        )
        if not requested:
            return DeleteResult(deleted=())
        batch_count = (len(requested) + self._mutation_batch_size - 1) // self._mutation_batch_size
        completed: list[int] = []
        for batch_number, uid_batch in enumerate(_iter_chunks(requested, self._mutation_batch_size), start=1):
            if batch_number > 1:
                self._reselect_source(readonly=False, operation="imap_predelete_select")
            self._emit(
                f"delete batch={batch_number}/{batch_count} uid_count={len(uid_batch)} "
                f"uid_min={min(uid_batch)} uid_max={max(uid_batch)}"
            )
            try:
                self._delete_batch(client, uid_batch)
            except ImapOperationError as failure:
                failure.batch = batch_number
                failure.batch_count = batch_count
                raise PartialDeleteError(
                    deleted=completed,
                    pending=requested[len(completed) :],
                    failure=failure,
                ) from failure
            completed.extend(uid_batch)
        return DeleteResult(deleted=tuple(completed))

    def _validate_mutation_uids(
        self,
        uids: Sequence[int],
        *,
        required_capability: bytes,
        operation_prefix: str,
    ) -> tuple[_Client, tuple[int, ...]]:
        if not self._writable:
            raise UnsafeMailboxOperation("mailbox is read-only")
        client = self._require_client()
        requested = tuple(sorted({int(uid) for uid in uids}))
        if not requested:
            return client, ()
        snapshot = self.snapshot()
        outside = set(requested) - snapshot.uids
        if outside:
            raise UnsafeMailboxOperation(f"refusing UIDs outside initial mailbox snapshot: {sorted(outside)}")
        capability_name = required_capability.decode("ascii")
        try:
            has_capability = _has_capability(client, required_capability)
        except Exception as exc:
            raise _operation_error(
                operation="imap_capabilities",
                message=f"could not verify {capability_name} before mutation",
                exc=exc,
                folder=self._folder,
                uids=requested,
            ) from exc
        if not has_capability:
            raise UnsafeMailboxOperation(f"{capability_name} disappeared; refusing {operation_prefix}")

        client = self._reselect_source(
            readonly=False,
            operation=f"imap_pre{operation_prefix}_select",
        )
        try:
            current_uids = {int(uid) for uid in client.search("ALL")}
        except Exception as exc:
            raise _operation_error(
                operation=f"imap_pre{operation_prefix}_search",
                message="UID SEARCH ALL failed before mutation",
                exc=exc,
                folder=self._folder,
                uids=requested,
            ) from exc
        missing = set(requested) - current_uids
        if missing:
            raise UnsafeMailboxOperation(f"approved UIDs no longer exist in scoped mailbox: {sorted(missing)}")
        return client, requested

    def _validate_streaming_mutation_uid(
        self,
        uid: int,
        *,
        required_capability: bytes,
        operation_prefix: str,
    ) -> tuple[_Client, int]:
        if not self._writable:
            raise UnsafeMailboxOperation("mailbox is read-only")
        client = self._require_client()
        uid = int(uid)
        snapshot = self.snapshot()
        if uid not in snapshot.uids and (
            not self._cursor_oriented or snapshot.uidnext is None or uid >= snapshot.uidnext
        ):
            raise UnsafeMailboxOperation(f"refusing UID outside initial mailbox snapshot: {uid}")
        capability_name = required_capability.decode("ascii")
        if required_capability not in self.capabilities:
            raise UnsafeMailboxOperation(f"{capability_name} disappeared; refusing {operation_prefix}")

        client = self._reselect_source(
            readonly=False,
            operation=f"imap_pre{operation_prefix}_select",
        )
        try:
            current_uids = client.search(["UID", uid])
        except Exception as exc:
            raise _operation_error(
                operation=f"imap_pre{operation_prefix}_search",
                message="exact UID SEARCH failed before mutation",
                exc=exc,
                folder=self._folder,
                selector=f"UID {uid}",
                uids=(uid,),
            ) from exc
        if uid not in {int(current_uid) for current_uid in current_uids}:
            raise UnsafeMailboxOperation(f"approved UID no longer exists in scoped mailbox: {uid}")
        return client, uid

    def _delete_batch(self, client: _Client, uids: Sequence[int]) -> None:
        try:
            client.add_flags(uids, [DELETED_FLAG], silent=True)
        except Exception as exc:
            rollback_error_type = self._remove_deleted_flags(client, uids)
            error = _operation_error(
                operation="imap_add_deleted_flag",
                message="STORE \\Deleted failed",
                exc=exc,
                folder=self._folder,
                selector="\\Deleted",
                uids=uids,
            )
            error.rollback_error_type = rollback_error_type
            raise error from exc
        try:
            client.uid_expunge(uids)
        except Exception as exc:
            rollback_error_type = self._remove_deleted_flags(client, uids)
            error = _operation_error(
                operation="imap_uid_expunge",
                message="UID EXPUNGE failed",
                exc=exc,
                folder=self._folder,
                uids=uids,
            )
            error.rollback_error_type = rollback_error_type
            raise error from exc

    def _remove_deleted_flags(self, client: _Client, uids: Sequence[int]) -> str | None:
        try:
            client.remove_flags(uids, [DELETED_FLAG], silent=True)
        except Exception as exc:
            self._emit(f"rollback remove-deleted-flag failed error_type={type(exc).__name__}")
            return type(exc).__name__
        return None

    def _emit(self, event: str) -> None:
        if self._event_callback is not None:
            self._event_callback(event)

    def _require_client(self) -> _Client:
        if self._client is None:
            raise MailboxError("mailbox is not open")
        return self._client


def _default_folder_client_factory(host: str, **kwargs: Any) -> _FolderClient:
    from imapclient import IMAPClient

    return IMAPClient(host, **kwargs)


def _default_client_factory(host: str, **kwargs: Any) -> _Client:
    from imapclient import IMAPClient

    return IMAPClient(host, **kwargs)


def _iter_chunks(values: Sequence[int], size: int) -> Iterator[tuple[int, ...]]:
    for start in range(0, len(values), size):
        yield tuple(values[start : start + size])


def _normalize_folder_flags(flags: object) -> frozenset[bytes]:
    if flags is None:
        return frozenset()
    values = (flags,) if isinstance(flags, (bytes, str)) else flags
    return frozenset(
        value.upper() if isinstance(value, bytes) else str(value).upper().encode("utf-8") for value in values
    )


def _normalize_folder_delimiter(delimiter: object) -> str | None:
    if delimiter is None or delimiter == "" or delimiter == b"":
        return None
    return delimiter.decode("utf-8") if isinstance(delimiter, bytes) else str(delimiter)


def _status_int(status: Mapping[object, object], key: str) -> int:
    for candidate in (key, key.encode("ascii")):
        if candidate in status:
            value = int(status[candidate])
            if value < 0:
                raise ValueError(f"{key} must be non-negative")
            return value
    raise ValueError(f"{key} is missing")


def _normalize_capabilities(values: Any) -> set[bytes]:
    return {item.upper() if isinstance(item, bytes) else str(item).upper().encode() for item in values}


def _contains_capability(values: Any, capability: bytes) -> bool:
    return capability.upper() in _normalize_capabilities(values)


def _has_capability(client: _Client, capability: bytes) -> bool:
    return _contains_capability(client.capabilities(), capability)


def _safe_server_status(exc: Exception) -> str | None:
    match = re.search(r"\bcommand error:\s*(BAD|NO|BYE)\b", str(exc), flags=re.IGNORECASE)
    return match.group(1).upper() if match is not None else None


def _safe_cause_code(exc: Exception) -> str | None:
    text = str(exc).casefold()
    if "got more than" in text and "bytes" in text:
        return "response-line-too-long"

    status = _safe_server_status(exc)
    if status == "BAD":
        return "command-bad"
    if status == "NO":
        return "command-no"

    exception_name = type(exc).__name__.casefold()
    if isinstance(exc, TimeoutError) or "timeout" in exception_name:
        return "timeout"
    if isinstance(exc, (ConnectionError, imaplib.IMAP4.abort)):
        return "connection-abort"
    if isinstance(exc, imaplib.IMAP4.error):
        return "protocol-error"
    return None


def _operation_error(
    *,
    operation: str,
    message: str,
    exc: Exception,
    folder: str | None = None,
    selector: str | None = None,
    uids: Sequence[int] = (),
    batch: int | None = None,
    batch_count: int | None = None,
) -> ImapOperationError:
    return ImapOperationError(
        operation=operation,
        message=message,
        folder=folder,
        selector=selector,
        uids=uids,
        batch=batch,
        batch_count=batch_count,
        cause_code=_safe_cause_code(exc),
        cause_type=type(exc).__name__,
        server_status=_safe_server_status(exc),
    )




def _uidvalidity(selected: dict[bytes, Any]) -> int:
    value = selected.get(b"UIDVALIDITY")
    if value is None:
        raise UnsafeMailboxOperation("server did not provide UIDVALIDITY; refusing scoped operation")
    return int(value)


def _uidnext(selected: Mapping[Any, Any]) -> int:
    value = selected.get(b"UIDNEXT", selected.get("UIDNEXT"))
    try:
        uidnext = int(value)
    except (TypeError, ValueError) as exc:
        raise UnsafeMailboxOperation("server did not provide valid UIDNEXT; refusing resumable scan") from exc
    if isinstance(value, bool) or uidnext < 1:
        raise UnsafeMailboxOperation("server did not provide valid UIDNEXT; refusing resumable scan")
    return uidnext


def _fetch_header_bytes(data: Mapping[Any, Any]) -> bytes | None:
    for key, value in data.items():
        normalized = key.decode("ascii", errors="replace") if isinstance(key, bytes) else str(key)
        if normalized.upper().startswith("BODY[HEADER.FIELDS") and isinstance(value, bytes):
            return value
    return None


def _fetch_flags_value(data: Mapping[Any, Any]) -> frozenset[bytes | str] | None:
    values = data.get(b"FLAGS", data.get("FLAGS"))
    if values is None:
        return None
    if isinstance(values, (bytes, str)):
        values = (values,)
    try:
        flags = frozenset(values)
    except TypeError:
        return None
    return flags if all(isinstance(flag, (bytes, str)) for flag in flags) else None


def _fetch_size_value(data: Mapping[Any, Any]) -> int | None:
    value = data.get(b"RFC822.SIZE", data.get("RFC822.SIZE"))
    try:
        size = int(value)
    except (TypeError, ValueError):
        return None
    return size if size >= 0 else None


def _fetch_uid_value(data: Mapping[Any, Any]) -> int | None:
    value = data.get(b"UID", data.get("UID"))
    try:
        uid = int(value)
    except (TypeError, ValueError):
        return None
    return uid if uid > 0 else None


def _skipped_summary(uid: int, reason: str) -> MailSummary:
    return MailSummary(
        uid=uid,
        sender="",
        subject="",
        date="",
        message_id="",
        size_bytes=None,
        flags=frozenset(),

        skip_reason=reason,
    )


class ProcessingMailbox(ScopedMailbox):
    """Bounded UID-window mailbox that does not build a full UID snapshot."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["uid_scope"] = ()
        kwargs["cursor_oriented"] = True
        super().__init__(**kwargs)


class BrowserMailbox:
    """Read-only mailbox pinned to one folder, optimized for interactive browsing."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        folder: str,
        max_message_bytes: int,
        max_body_chars: int,
        client_factory: ClientFactory | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._host, self._port, self._username = host, port, username
        self._password, self._folder = password, folder
        self._max_message_bytes, self._max_body_chars = max_message_bytes, max_body_chars
        self._client_factory = client_factory or _default_client_factory
        self._timeout = timeout
        self._client: _Client | None = None
        self.uidvalidity = 0
        self.message_count = 0

    def __enter__(self) -> BrowserMailbox:
        try:
            client = self._client_factory(self._host, port=self._port, ssl=True, timeout=self._timeout, use_uid=True)
            client.login(self._username, self._password)
        except Exception as exc:
            self._password = ""
            raise _operation_error(
                operation="imap_connect",
                message="could not open read-only browser session",
                exc=exc,
            ) from exc
        self._password = ""
        self._client = client
        try:
            selected = client.select_folder(self._folder, readonly=True)
            self.uidvalidity = _uidvalidity(selected)
            exists = selected.get(b"EXISTS", selected.get("EXISTS", 0))
            self.message_count = int(exists or 0)
        except Exception as exc:
            self.__exit__(type(exc), exc, exc.__traceback__)
            raise _operation_error(
                operation="imap_select_folder",
                message="could not select read-only folder",
                exc=exc,
                folder=self._folder,
            ) from exc
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        client, self._client = self._client, None
        self._password = ""
        if client is not None:
            try:
                client.logout()
            except Exception:
                if exc is None:
                    raise

    def fetch_summary_page(
        self,
        *,
        offset: int,
        limit: int,
        sort: MessageSort = MessageSort.NEWEST,
    ) -> tuple[MailSummary, ...]:
        if offset < 0 or limit < 1:
            raise ValueError("offset must be non-negative and limit must be positive")
        if not isinstance(sort, MessageSort):
            raise ValueError("sort must be a MessageSort")

        count = self.message_count
        if sort is MessageSort.NEWEST:
            high = count - offset
            if high < 1:
                return ()
            low = max(1, high - limit + 1)
            sequence_numbers = tuple(range(low, high + 1))
            ordered_sequences = reversed(sequence_numbers)
        else:
            low = offset + 1
            if low > count:
                return ()
            high = min(count, low + limit - 1)
            sequence_numbers = tuple(range(low, high + 1))
            ordered_sequences = iter(sequence_numbers)

        client = self._require_client()
        previous_use_uid = client.use_uid
        selector = "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]"
        try:
            client.use_uid = False
            response = client.fetch(
                sequence_numbers,
                ["UID", selector, "FLAGS", "RFC822.SIZE"],
            )
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_summaries",
                message="FETCH of message summaries failed",
                exc=exc,
                folder=self._folder,
                selector="sequence page headers UID FLAGS RFC822.SIZE",
            ) from exc
        finally:
            client.use_uid = previous_use_uid

        response_by_sequence = {int(sequence): data for sequence, data in response.items()}
        summaries = []
        for sequence in ordered_sequences:
            data = response_by_sequence.get(sequence)
            if not isinstance(data, Mapping):
                continue
            uid = _fetch_uid_value(data)
            if uid is None:
                continue
            raw = _fetch_header_bytes(data)
            flags = _fetch_flags_value(data)
            size = _fetch_size_value(data)
            if raw is not None and flags is not None:
                summaries.append(parse_summary(uid, raw, flags=flags, size_bytes=size))
            else:
                summaries.append(_skipped_summary(uid, "message summary unavailable"))
        return tuple(summaries)


    def fetch_summaries(self, uids: Sequence[int]) -> tuple[MailSummary, ...]:
        if not uids:
            return ()
        selector = "BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]"
        try:
            response = self._require_client().fetch(tuple(uids), [selector, "FLAGS", "RFC822.SIZE"])
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_summaries",
                message="FETCH of message summaries failed",
                exc=exc,
                folder=self._folder,
                selector="headers FLAGS RFC822.SIZE",
                uids=uids,
            ) from exc
        summaries = []
        for uid in uids:
            data = response.get(uid)
            raw = _fetch_header_bytes(data) if isinstance(data, Mapping) else None
            flags = _fetch_flags_value(data) if isinstance(data, Mapping) else None
            size = _fetch_size_value(data) if isinstance(data, Mapping) else None
            if raw is not None and flags is not None:
                summaries.append(parse_summary(uid, raw, flags=flags, size_bytes=size))
            else:
                summaries.append(_skipped_summary(uid, "message summary unavailable"))
        return tuple(summaries)

    def fetch_uid(self, uid: int) -> MailboxItem:
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            raise ValueError("uid must be a positive integer")
        client = self._require_client()
        try:
            exists = {int(found) for found in client.search(["UID", uid])}
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_uid_search",
                message="exact UID SEARCH failed",
                exc=exc,
                folder=self._folder,
                selector=f"UID {uid}",
                uids=(uid,),
            ) from exc
        if uid not in exists:
            return MailboxItem(uid, skip_reason="message does not exist in selected folder")
        try:
            sized = client.fetch((uid,), ["RFC822.SIZE"]).get(uid)
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_size",
                message="FETCH of message size failed",
                exc=exc,
                folder=self._folder,
                selector="RFC822.SIZE",
                uids=(uid,),
            ) from exc
        size = _fetch_size_value(sized) if isinstance(sized, Mapping) else None
        if size is None:
            return MailboxItem(uid, skip_reason="message size unavailable")
        if size > self._max_message_bytes:
            return MailboxItem(uid, skip_reason=f"message size {size} exceeds limit {self._max_message_bytes}")
        try:
            body_data = client.fetch((uid,), ["BODY.PEEK[]"]).get(uid)
        except Exception as exc:
            raise _operation_error(
                operation="imap_fetch_body",
                message="FETCH of BODY.PEEK[] failed",
                exc=exc,
                folder=self._folder,
                selector="BODY.PEEK[]",
                uids=(uid,),
            ) from exc
        raw = body_data.get(b"BODY[]") if isinstance(body_data, Mapping) else None
        if not isinstance(raw, bytes):
            return MailboxItem(uid, skip_reason="message body unavailable")
        message = parse_message(uid, raw, max_body_chars=self._max_body_chars, size_bytes=size)
        return MailboxItem(uid, message=message)
    def _require_client(self) -> _Client:
        if self._client is None:
            raise MailboxError("browser mailbox is not open")
        return self._client


class ReadOnlyMailbox:
    """Narrow read-only facade over one read-only scoped mailbox."""

    def __init__(self, mailbox: ScopedMailbox) -> None:
        if mailbox.writable:
            raise ValueError("ReadOnlyMailbox requires a read-only ScopedMailbox")
        self.__mailbox = mailbox

    def __enter__(self) -> ReadOnlyMailbox:
        self.__mailbox.__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.__mailbox.__exit__(exc_type, exc, tb)

    def snapshot(self) -> MailboxSnapshot:
        return self.__mailbox.snapshot()

    def page_uids(self, *, offset: int = 0, limit: int = 50, sort: MessageSort = MessageSort.NEWEST) -> tuple[int, ...]:
        if offset < 0 or limit < 1:
            raise ValueError("offset must be non-negative and limit must be positive")
        if not isinstance(sort, MessageSort):
            raise ValueError("sort must be a MessageSort")
        uids = sorted(self.snapshot().uids, reverse=sort is MessageSort.NEWEST)
        return tuple(uids[offset : offset + limit])

    def fetch_summaries(self, uids: Sequence[int]) -> tuple[MailSummary, ...]:
        return self.__mailbox.fetch_summaries(uids)


    def fetch_uid(self, uid: int) -> MailboxItem:
        return self.__mailbox.fetch_uid(uid)

