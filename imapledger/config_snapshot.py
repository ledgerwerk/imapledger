from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.policy import default
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path

from .config_errors import ConfigSnapshotError, ConfigSnapshotIntegrityError

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 10 * 1024 * 1024
_TOOL_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.ASCII)
_VERSION_PATTERN = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z)-([0-9a-f]{12})$", re.ASCII)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SECRET_ASSIGNMENT = re.compile(
    r"^\s*(password|passwd|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret)\s*[:=]\s*(.*?)\s*$",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\bAuthorization\s*:\s*Bearer\s+(\S+)", re.IGNORECASE)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PLACEHOLDER = re.compile(r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|env:[A-Za-z_][A-Za-z0-9_]*)$")


@dataclass(frozen=True, slots=True)
class ConfigSnapshotMeta:
    tool: str
    version_id: str
    parent_version_ids: tuple[str, ...]
    created_at: datetime
    default_path: str
    filename: str
    content_sha256: str
    size_bytes: int
    schema: int = SCHEMA_VERSION
    uid: int | None = None
    uidvalidity: int | None = None
    message_id: str | None = None


@dataclass(frozen=True, slots=True)
class ConfigSnapshot:
    meta: ConfigSnapshotMeta
    content: bytes


@dataclass(frozen=True, slots=True)
class SensitiveField:
    line_number: int
    field: str


def normalize_tool_name(tool: str) -> str:
    if not isinstance(tool, str):
        raise ConfigSnapshotError("tool name must be a string")
    normalized = tool.lower()
    if not _TOOL_PATTERN.fullmatch(normalized) or ".." in normalized:
        raise ConfigSnapshotError("tool name must match [a-z0-9][a-z0-9._-]{0,63} and must not contain '..'")
    return normalized


def portable_default_path(path: str | Path, *, home: Path | None = None) -> str:
    source = Path(path).expanduser()
    absolute = source.resolve()
    home_path = (home or Path.home()).expanduser().resolve()
    try:
        relative = absolute.relative_to(home_path)
    except ValueError:
        return str(absolute)
    return "~" if str(relative) == "." else f"~/{relative.as_posix()}"


def expand_default_path(path: str, *, home: Path | None = None) -> Path:
    _validate_default_path(path)
    if path == "~":
        return (home or Path.home()).expanduser()
    if path.startswith("~/"):
        return (home or Path.home()).expanduser() / path[2:]
    return Path(path)


def _validate_default_path(path: str) -> None:
    if not isinstance(path, str) or not path or "\x00" in path or "\r" in path or "\n" in path:
        raise ConfigSnapshotError("snapshot default path is invalid")
    if path != "~" and not path.startswith("~/") and not Path(path).is_absolute():
        raise ConfigSnapshotError("snapshot default path must be portable-home or absolute")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).strftime("%Y%m%dT%H%M%S.%fZ")


def _canonical_metadata(
    *,
    tool: str,
    created_at: datetime,
    default_path: str,
    content_sha256: str,
    parent_version_ids: tuple[str, ...],
    schema: int,
) -> bytes:
    payload = {
        "schema": schema,
        "tool": tool,
        "created_at": _timestamp(created_at),
        "default_path": default_path,
        "content_sha256": content_sha256,
        "parent_version_ids": list(parent_version_ids),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_version_id(
    *,
    tool: str,
    created_at: datetime,
    default_path: str,
    content_sha256: str,
    parent_version_ids: tuple[str, ...] = (),
    schema: int = SCHEMA_VERSION,
) -> str:
    normalized = normalize_tool_name(tool)
    _validate_default_path(default_path)
    parents = tuple(sorted(parent_version_ids))
    digest = hashlib.sha256(
        _canonical_metadata(
            tool=normalized,
            created_at=created_at,
            default_path=default_path,
            content_sha256=content_sha256,
            parent_version_ids=parents,
            schema=schema,
        )
    ).hexdigest()[:12]
    return f"{_timestamp(created_at)}-{digest}"


def create_snapshot(
    *,
    tool: str,
    content: bytes,
    default_path: str,
    parent_version_ids: tuple[str, ...] = (),
    created_at: datetime | None = None,
    filename: str | None = None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> ConfigSnapshot:
    normalized = normalize_tool_name(tool)
    _validate_default_path(default_path)
    if len(content) > max_file_bytes:
        raise ConfigSnapshotError(f"configuration exceeds the {max_file_bytes}-byte limit")
    _validate_content(content)
    created = _utc(created_at or datetime.now(timezone.utc))
    parents = tuple(sorted(parent_version_ids))
    for parent in parents:
        if not _VERSION_PATTERN.fullmatch(parent):
            raise ConfigSnapshotError("parent version ID is invalid")
    if len(set(parents)) != len(parents):
        raise ConfigSnapshotError("parent version IDs must not contain duplicates")
    file_name = filename or Path(default_path).name
    _validate_filename(file_name)
    digest = sha256_bytes(content)
    version_id = build_version_id(
        tool=normalized,
        created_at=created,
        default_path=default_path,
        content_sha256=digest,
        parent_version_ids=parents,
    )
    return ConfigSnapshot(
        meta=ConfigSnapshotMeta(
            tool=normalized,
            version_id=version_id,
            parent_version_ids=parents,
            created_at=created,
            default_path=default_path,
            filename=file_name,
            content_sha256=digest,
            size_bytes=len(content),
        ),
        content=content,
    )


def serialize_snapshot(snapshot: ConfigSnapshot, *, username: str) -> bytes:
    meta = snapshot.meta
    if not isinstance(username, str) or not username or any(char in username for char in ("\x00", "\r", "\n")):
        raise ConfigSnapshotError("header value is invalid")
    _validate_metadata(meta)
    _validate_content(snapshot.content)
    if len(snapshot.content) != meta.size_bytes or sha256_bytes(snapshot.content) != meta.content_sha256:
        raise ConfigSnapshotIntegrityError("snapshot content does not match its metadata")
    message = EmailMessage(policy=default)
    message["From"] = f"imapledger <{username}>"
    message["To"] = username
    message["Subject"] = f"[imapledger config] {meta.tool} @ {meta.version_id}"
    message["Date"] = format_datetime(_utc(meta.created_at))
    message["Message-ID"] = meta.message_id or f"<{meta.version_id}@imapledger>"
    message["X-Imapledger-Kind"] = "config-snapshot"
    message["X-Imapledger-Schema"] = str(meta.schema)
    message["X-Imapledger-Tool"] = meta.tool
    message["X-Imapledger-Version"] = meta.version_id
    message["X-Imapledger-Parents"] = ",".join(meta.parent_version_ids)
    message["X-Imapledger-Content-SHA256"] = meta.content_sha256
    message["X-Imapledger-Size"] = str(meta.size_bytes)
    message["X-Imapledger-Default-Path"] = meta.default_path
    message["X-Imapledger-Filename"] = meta.filename
    readable = (
        "imapledger configuration snapshot\n"
        f"Tool: {meta.tool}\nVersion: {meta.version_id}\n"
        f"SHA-256: {meta.content_sha256}\n\n" + snapshot.content.decode("utf-8")
    )
    message.set_content(readable, charset="utf-8")
    message.add_attachment(
        snapshot.content,
        maintype="application",
        subtype="octet-stream",
        filename=meta.filename,
    )
    return message.as_bytes()


def parse_snapshot_metadata(
    source: bytes | Message,
    *,
    uid: int | None = None,
    uidvalidity: int | None = None,
) -> ConfigSnapshotMeta:
    message = BytesParser(policy=default).parsebytes(source) if isinstance(source, bytes) else source

    def required(name: str) -> str:
        values = message.get_all(name, [])
        if len(values) != 1:
            raise ConfigSnapshotIntegrityError(f"snapshot must contain exactly one {name} header")
        return str(values[0])

    if required("X-Imapledger-Kind") != "config-snapshot":
        raise ConfigSnapshotIntegrityError("message is not an imapledger config snapshot")
    try:
        schema = int(required("X-Imapledger-Schema"))
    except ValueError as exc:
        raise ConfigSnapshotIntegrityError("snapshot schema is invalid") from exc
    if schema != SCHEMA_VERSION:
        raise ConfigSnapshotIntegrityError(f"unsupported config snapshot schema: {schema}")
    tool_header = required("X-Imapledger-Tool")
    tool = normalize_tool_name(tool_header)
    if tool != tool_header:
        raise ConfigSnapshotIntegrityError("snapshot tool header is not normalized")
    version_id = required("X-Imapledger-Version")
    version_match = _VERSION_PATTERN.fullmatch(version_id)
    if version_match is None:
        raise ConfigSnapshotIntegrityError("snapshot version ID is invalid")
    try:
        created_at = datetime.strptime(version_match.group(1), "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ConfigSnapshotIntegrityError("snapshot timestamp is invalid") from exc
    parents_header = required("X-Imapledger-Parents")
    parents = tuple(parent.strip() for parent in parents_header.split(",") if parent.strip())
    if any(_VERSION_PATTERN.fullmatch(parent) is None for parent in parents):
        raise ConfigSnapshotIntegrityError("snapshot parent version ID is invalid")
    if len(set(parents)) != len(parents):
        raise ConfigSnapshotIntegrityError("snapshot parent version IDs contain duplicates")
    digest = required("X-Imapledger-Content-SHA256")
    if not _SHA256_PATTERN.fullmatch(digest):
        raise ConfigSnapshotIntegrityError("snapshot content SHA-256 is invalid")
    try:
        size_bytes = int(required("X-Imapledger-Size"))
    except ValueError as exc:
        raise ConfigSnapshotIntegrityError("snapshot size is invalid") from exc
    if size_bytes < 0:
        raise ConfigSnapshotIntegrityError("snapshot size is invalid")
    default_path = required("X-Imapledger-Default-Path")
    _validate_default_path(default_path)
    filename = required("X-Imapledger-Filename")
    _validate_filename(filename)
    meta = ConfigSnapshotMeta(
        tool=tool,
        version_id=version_id,
        parent_version_ids=parents,
        created_at=created_at,
        default_path=default_path,
        filename=filename,
        content_sha256=digest,
        size_bytes=size_bytes,
        schema=schema,
        uid=uid,
        uidvalidity=uidvalidity,
        message_id=str(message.get("Message-ID")) if message.get("Message-ID") else None,
    )
    _validate_metadata(meta)
    date_value = required("Date")
    try:
        if parsedate_to_datetime(date_value) is None:
            raise ValueError("invalid date")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConfigSnapshotIntegrityError("snapshot Date header is invalid") from exc
    return meta


def parse_snapshot_message(
    raw_message: bytes,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    uid: int | None = None,
    uidvalidity: int | None = None,
) -> ConfigSnapshot:
    message = BytesParser(policy=default).parsebytes(raw_message)
    meta = parse_snapshot_metadata(message, uid=uid, uidvalidity=uidvalidity)
    if meta.size_bytes > max_file_bytes:
        raise ConfigSnapshotIntegrityError("snapshot exceeds the configured size limit")
    attachments = [
        part
        for part in message.walk()
        if part.get_content_disposition() == "attachment" and part.get_content_type() == "application/octet-stream"
    ]
    if len(attachments) != 1:
        raise ConfigSnapshotIntegrityError("snapshot must contain exactly one authoritative attachment")
    attachment = attachments[0]
    if attachment.get_filename() != meta.filename:
        raise ConfigSnapshotIntegrityError("snapshot attachment filename does not match its metadata")
    content = attachment.get_payload(decode=True)
    if content is None:
        raise ConfigSnapshotIntegrityError("snapshot authoritative attachment is unreadable")
    if len(content) != meta.size_bytes:
        raise ConfigSnapshotIntegrityError("snapshot attachment size does not match its metadata")
    if sha256_bytes(content) != meta.content_sha256:
        raise ConfigSnapshotIntegrityError("snapshot attachment SHA-256 does not match its metadata")
    _validate_content(content)
    return ConfigSnapshot(meta=meta, content=content)


def sensitive_fields(text: str) -> tuple[SensitiveField, ...]:
    findings: list[SensitiveField] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if _PRIVATE_KEY.search(line):
            findings.append(SensitiveField(line_number, "private key"))
            continue
        assignment = _SECRET_ASSIGNMENT.match(line)
        if assignment is not None:
            field = assignment.group(1).lower().replace("-", "_")
            value = assignment.group(2).strip().strip("\"'").strip()
            if value and not _PLACEHOLDER.fullmatch(value):
                findings.append(SensitiveField(line_number, field))
            continue
        bearer = _BEARER.search(line)
        if bearer is not None and not _PLACEHOLDER.fullmatch(bearer.group(1)):
            findings.append(SensitiveField(line_number, "authorization bearer token"))
    return tuple(findings)


def _validate_filename(filename: str) -> None:
    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or Path(filename).name != filename
        or any(character in filename for character in ("/", "\\", "\x00", "\r", "\n"))
    ):
        raise ConfigSnapshotError("snapshot filename is invalid")


def _validate_content(content: bytes) -> None:
    if not isinstance(content, bytes):
        raise ConfigSnapshotError("configuration content must be bytes")
    if b"\x00" in content:
        raise ConfigSnapshotError("configuration text must not contain NUL")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigSnapshotError("configuration content must be UTF-8 text") from exc


def _validate_metadata(meta: ConfigSnapshotMeta) -> None:
    if normalize_tool_name(meta.tool) != meta.tool:
        raise ConfigSnapshotIntegrityError("snapshot tool name is not normalized")
    _validate_default_path(meta.default_path)
    _validate_filename(meta.filename)
    if meta.filename != Path(meta.default_path).name:
        raise ConfigSnapshotIntegrityError("snapshot filename does not match its default path")
    if meta.schema != SCHEMA_VERSION:
        raise ConfigSnapshotIntegrityError(f"unsupported config snapshot schema: {meta.schema}")
    if not _SHA256_PATTERN.fullmatch(meta.content_sha256):
        raise ConfigSnapshotIntegrityError("snapshot content SHA-256 is invalid")
    expected = build_version_id(
        tool=meta.tool,
        created_at=meta.created_at,
        default_path=meta.default_path,
        content_sha256=meta.content_sha256,
        parent_version_ids=meta.parent_version_ids,
        schema=meta.schema,
    )
    if meta.version_id != expected:
        raise ConfigSnapshotIntegrityError("snapshot version ID does not match its canonical metadata")
    if meta.size_bytes < 0:
        raise ConfigSnapshotIntegrityError("snapshot size is invalid")
