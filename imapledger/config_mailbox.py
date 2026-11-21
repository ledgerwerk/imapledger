from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.parser import BytesHeaderParser
from email.policy import default
from typing import Any, Protocol

from imapclient import IMAPClient

from .config_errors import ConfigLedgerError, ConfigSnapshotIntegrityError, ConfigStoreFolderMissingError
from .config_snapshot import (
    ConfigSnapshot,
    ConfigSnapshotMeta,
    normalize_tool_name,
    parse_snapshot_message,
    parse_snapshot_metadata,
    serialize_snapshot,
)


class _ConfigStoreClient(Protocol):
    def login(self, username: str, password: str) -> Any: ...
    def logout(self) -> Any: ...
    def capabilities(self) -> Any: ...
    def folder_exists(self, folder: str) -> bool: ...
    def select_folder(self, folder: str, readonly: bool = False) -> Mapping[bytes, Any]: ...
    def search(self, criteria: Any = "ALL", charset: str | None = None) -> list[int]: ...
    def fetch(self, messages: Any, data: Any, modifiers: Any = None) -> Mapping[int, Mapping[bytes, Any]]: ...
    def append(self, folder: str, message: bytes, flags: Any = None, msg_time: Any = None) -> Any: ...


ConfigStoreClientFactory = Callable[..., _ConfigStoreClient]


@dataclass(frozen=True, slots=True)
class ConfigSnapshotMetadataIssue:
    uid: int
    tool: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ConfigSnapshotMetadataScan:
    metadata: tuple[ConfigSnapshotMeta, ...]
    issues: tuple[ConfigSnapshotMetadataIssue, ...]


class ConfigStoreOperationError(ConfigLedgerError):
    def __init__(self, operation: str, message: str, *, folder: str, cause_type: str | None = None) -> None:
        super().__init__(message)
        self.operation = operation
        self.message = message
        self.folder = folder
        self.cause_type = cause_type

    def __str__(self) -> str:
        result = f"error [{self.operation}]: {self.message} folder={self.folder!r}"
        if self.cause_type is not None:
            result += f" server_error_type={self.cause_type}"
        return result


class ConfigStoreMailbox:
    """IMAP transport permanently scoped to one configured config-store folder."""

    _METADATA_FIELDS = (
        "X-Imapledger-Kind X-Imapledger-Schema X-Imapledger-Tool X-Imapledger-Version "
        "X-Imapledger-Parents X-Imapledger-Content-SHA256 X-Imapledger-Size "
        "X-Imapledger-Default-Path X-Imapledger-Filename Date Message-ID"
    )

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        folder: str,
        max_file_bytes: int,
        writable: bool,
        timeout: float = 30.0,
        client_factory: ConfigStoreClientFactory | None = None,
        event_callback: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(folder, str) or not folder or folder != folder.strip():
            raise ValueError("config-store folder must be non-empty and have no surrounding whitespace")
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._folder = folder
        self._max_file_bytes = max_file_bytes
        self._writable = writable
        self._timeout = timeout
        self._client_factory = client_factory or _default_client_factory
        self._event_callback = event_callback
        self._client: _ConfigStoreClient | None = None
        self._uidvalidity: int | None = None

    def __enter__(self) -> ConfigStoreMailbox:
        client: _ConfigStoreClient | None = None
        try:
            client = self._client_factory(
                self._host,
                port=self._port,
                ssl=True,
                timeout=self._timeout,
                use_uid=True,
            )
            try:
                client.login(self._username, self._password)
            except Exception as exc:
                raise self._operation_error("imap_login", "IMAP login failed", exc) from exc
            finally:
                self._password = ""
            try:
                client.capabilities()
            except Exception as exc:
                raise self._operation_error("imap_capabilities", "could not read IMAP capabilities", exc) from exc
            try:
                exists = bool(client.folder_exists(self._folder))
            except Exception as exc:
                raise self._operation_error("imap_folder_exists", "could not verify config-store folder", exc) from exc
            if not exists:
                raise ConfigStoreFolderMissingError(f"Configuration store folder does not exist: {self._folder}")
            try:
                selected = client.select_folder(self._folder, readonly=not self._writable)
            except Exception as exc:
                raise self._operation_error("imap_select_folder", "could not select config-store folder", exc) from exc
            uidvalidity = _uidvalidity(selected)
            self._uidvalidity = uidvalidity
            self._client = client
            self._emit(f"config store selected readonly={not self._writable} uidvalidity={uidvalidity}")
            return self
        except Exception:
            self._password = ""
            self._uidvalidity = None
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass
            raise

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        client = self._client
        self._client = None
        self._uidvalidity = None
        self._password = ""
        if client is not None:
            try:
                client.logout()
            except Exception as logout_error:
                if exc is None:
                    raise self._operation_error("imap_logout", "IMAP logout failed", logout_error) from logout_error

    def list_snapshot_metadata(self, tool: str | None = None) -> tuple[ConfigSnapshotMeta, ...]:
        scan = self.scan_snapshot_metadata(tool)
        if scan.issues:
            issue = scan.issues[0]
            raise ConfigSnapshotIntegrityError(f"invalid config snapshot metadata at UID {issue.uid}: {issue.reason}")
        return scan.metadata

    def scan_snapshot_metadata(self, tool: str | None = None) -> ConfigSnapshotMetadataScan:
        client = self._require_client()
        criteria: list[str] = ["HEADER", "X-Imapledger-Kind", "config-snapshot"]
        normalized_tool = normalize_tool_name(tool) if tool is not None else None
        if normalized_tool is not None:
            criteria.extend(("HEADER", "X-Imapledger-Tool", normalized_tool))
        try:
            uids = tuple(sorted(int(uid) for uid in client.search(criteria)))
        except Exception as exc:
            raise self._operation_error("imap_search", "config snapshot search failed", exc) from exc
        if not uids:
            return ConfigSnapshotMetadataScan((), ())
        selector = f"BODY.PEEK[HEADER.FIELDS ({self._METADATA_FIELDS})]"
        try:
            response = client.fetch(uids, [selector])
        except Exception as exc:
            raise self._operation_error("imap_fetch_metadata", "config snapshot metadata fetch failed", exc) from exc
        metadata = []
        issues = []
        for uid in uids:
            raw_headers = None
            try:
                raw_headers = _header_fetch_value(response.get(uid))
                meta = parse_snapshot_metadata(raw_headers, uid=uid, uidvalidity=self._require_uidvalidity())
            except ConfigLedgerError as exc:
                issue_tool = _header_tool(raw_headers) if raw_headers is not None else None
                if normalized_tool is None or issue_tool == normalized_tool:
                    issues.append(ConfigSnapshotMetadataIssue(uid=uid, tool=issue_tool, reason=str(exc)))
                continue
            if meta.tool == normalized_tool or normalized_tool is None:
                metadata.append(meta)
        return ConfigSnapshotMetadataScan(tuple(metadata), tuple(issues))

    def fetch_snapshot(self, meta: ConfigSnapshotMeta) -> ConfigSnapshot:
        client = self._require_client()
        if meta.uid is None or meta.uidvalidity != self._require_uidvalidity():
            raise ConfigSnapshotIntegrityError("snapshot transport identity is missing or stale")
        try:
            response = client.fetch((meta.uid,), ["BODY.PEEK[]"])
        except Exception as exc:
            raise self._operation_error("imap_fetch_snapshot", "config snapshot fetch failed", exc) from exc
        fields = response.get(meta.uid)
        raw_message = _body_fetch_value(fields)
        snapshot = parse_snapshot_message(
            raw_message,
            max_file_bytes=self._max_file_bytes,
            uid=meta.uid,
            uidvalidity=meta.uidvalidity,
        )
        if _without_transport(snapshot.meta) != _without_transport(meta):
            raise ConfigSnapshotIntegrityError("fetched snapshot metadata changed since discovery")
        return snapshot

    def append_snapshot(self, snapshot: ConfigSnapshot) -> ConfigSnapshot:
        if not self._writable:
            raise ConfigLedgerError("config store mailbox was opened read-only")
        client = self._require_client()
        raw_message = serialize_snapshot(snapshot, username=self._username)
        try:
            client.append(self._folder, raw_message)
        except Exception as exc:
            raise self._operation_error("imap_append", "config snapshot append failed", exc) from exc
        matches = [
            meta
            for meta in self.list_snapshot_metadata(snapshot.meta.tool)
            if meta.version_id == snapshot.meta.version_id
        ]
        if len(matches) != 1:
            raise ConfigSnapshotIntegrityError("appended snapshot could not be uniquely verified")
        appended = self.fetch_snapshot(matches[0])
        if appended.content != snapshot.content or _without_transport(appended.meta) != _without_transport(
            snapshot.meta
        ):
            raise ConfigSnapshotIntegrityError("appended snapshot does not match the requested snapshot")
        return appended

    def _require_client(self) -> _ConfigStoreClient:
        if self._client is None:
            raise ConfigLedgerError("config store mailbox is not open")
        return self._client

    def _require_uidvalidity(self) -> int:
        if self._uidvalidity is None:
            raise ConfigLedgerError("config store mailbox is not open")
        return self._uidvalidity

    def _operation_error(self, operation: str, message: str, exc: Exception) -> ConfigStoreOperationError:
        return ConfigStoreOperationError(operation, message, folder=self._folder, cause_type=type(exc).__name__)

    def _emit(self, message: str) -> None:
        if self._event_callback is not None:
            self._event_callback(message)


def _default_client_factory(host: str, **kwargs: Any) -> _ConfigStoreClient:
    return IMAPClient(host, **kwargs)


def _uidvalidity(selected: Mapping[bytes, Any]) -> int:
    value = selected.get(b"UIDVALIDITY", selected.get("UIDVALIDITY"))
    if value is None:
        raise ConfigLedgerError("IMAP did not return UIDVALIDITY for config store")
    return int(value)


def _header_tool(raw_headers: bytes) -> str | None:
    headers = BytesHeaderParser(policy=default).parsebytes(raw_headers)
    value = headers.get("X-Imapledger-Tool")
    if value is None:
        return None
    try:
        return normalize_tool_name(str(value))
    except ConfigLedgerError:
        return None


def _header_fetch_value(fields: Mapping[bytes, Any] | None) -> bytes:
    if fields is None:
        raise ConfigSnapshotIntegrityError("snapshot disappeared during metadata fetch")
    for key, value in fields.items():
        if bytes(key).upper().startswith(b"BODY[HEADER.FIELDS"):
            if isinstance(value, bytes):
                return value
    raise ConfigSnapshotIntegrityError("IMAP metadata response did not contain requested headers")


def _body_fetch_value(fields: Mapping[bytes, Any] | None) -> bytes:
    if fields is None:
        raise ConfigSnapshotIntegrityError("snapshot disappeared during fetch")
    value = fields.get(b"BODY[]", fields.get("BODY[]"))
    if isinstance(value, bytes):
        return value
    raise ConfigSnapshotIntegrityError("IMAP response did not contain the requested snapshot body")


def _without_transport(meta: ConfigSnapshotMeta) -> ConfigSnapshotMeta:
    return ConfigSnapshotMeta(
        tool=meta.tool,
        version_id=meta.version_id,
        parent_version_ids=meta.parent_version_ids,
        created_at=meta.created_at,
        default_path=meta.default_path,
        filename=meta.filename,
        content_sha256=meta.content_sha256,
        size_bytes=meta.size_bytes,
        schema=meta.schema,
    )
