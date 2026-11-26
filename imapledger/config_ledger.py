from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text

from .config import ConfigStoreSettings
from .config_diff import DiffDirection, render_config_diff
from .config_errors import (
    ConfigHistoryConflictError,
    ConfigHistoryError,
    ConfigLedgerError,
    ConfigSnapshotError,
    ConfigSnapshotIntegrityError,
    SensitiveConfigError,
)
from .config_history import ConfigHistory, build_history
from .config_mailbox import ConfigSnapshotMetadataIssue, ConfigStoreMailbox
from .config_snapshot import (
    ConfigSnapshot,
    ConfigSnapshotMeta,
    create_snapshot,
    expand_default_path,
    normalize_tool_name,
    portable_default_path,
    sensitive_fields,
)


class ConfigToolStatus(str, Enum):
    OK = "OK"
    CONFLICT = "CONFLICT"
    CORRUPT = "CORRUPT"


@dataclass(frozen=True, slots=True)
class ConfigToolSummary:
    tool: str
    versions: int
    status: ConfigToolStatus
    current: str | None
    default_path: str | None
    heads: int
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConfigVersionRecord:
    meta: ConfigSnapshotMeta
    current: bool
    head: bool


@dataclass(frozen=True, slots=True)
class ConfigPushResult:
    snapshot: ConfigSnapshotMeta
    created: bool


@dataclass(frozen=True, slots=True)
class ConfigPullResult:
    target: Path
    version_id: str
    written: bool
    already_up_to_date: bool
    cancelled: bool
    diff: str = ""


@dataclass(frozen=True, slots=True)
class ConfigPullPreview:
    tool: str
    version_id: str
    target: Path
    content_sha256: str
    target_exists: bool
    target_sha256: str | None
    already_up_to_date: bool
    diff: str


class ConfigOverwriteConfirmationRequired(ConfigLedgerError):
    def __init__(self, target: Path, diff: str) -> None:
        super().__init__(f"confirmation is required before overwriting {target}")
        self.target = target
        self.diff = diff


OverwriteConfirmation = Callable[[Path, str], bool]

DiffDisplay = Callable[[Path, str], None]


class ConfigLedger:
    """CLI-independent workflows for a configured IMAP configuration ledger."""

    def __init__(
        self,
        mailbox: ConfigStoreMailbox,
        settings: ConfigStoreSettings,
        *,
        home: Path | None = None,
    ) -> None:
        self._mailbox = mailbox
        self._settings = settings
        self._home = (home or Path.home()).expanduser().resolve()

    def list_tools(self) -> tuple[ConfigToolSummary, ...]:
        scan = self._mailbox.scan_snapshot_metadata()
        grouped: dict[str, list[ConfigSnapshotMeta]] = defaultdict(list)
        issues: dict[str, list[ConfigSnapshotMetadataIssue]] = defaultdict(list)
        for meta in scan.metadata:
            grouped[meta.tool].append(meta)
        for issue in scan.issues:
            issues[issue.tool or "<unknown>"].append(issue)
        summaries = []
        for tool in sorted(grouped.keys() | issues.keys()):
            metadata = grouped.get(tool, [])
            tool_issues = issues.get(tool, [])
            if tool_issues:
                summaries.append(
                    ConfigToolSummary(
                        tool=tool,
                        versions=len(metadata) + len(tool_issues),
                        status=ConfigToolStatus.CORRUPT,
                        current=None,
                        default_path=metadata[0].default_path if metadata else None,
                        heads=0,
                        details=tuple(issue.reason for issue in tool_issues),
                    )
                )
                continue
            try:
                history = build_history(metadata, tool=tool)
            except ConfigHistoryError as exc:
                summaries.append(
                    ConfigToolSummary(
                        tool=tool,
                        versions=len(metadata),
                        status=ConfigToolStatus.CORRUPT,
                        current=None,
                        default_path=metadata[0].default_path if metadata else None,
                        heads=0,
                        details=(str(exc),),
                    )
                )
                continue
            summaries.append(_summarize_history(history))
        return tuple(summaries)

    def list_versions(self, tool: str) -> tuple[ConfigVersionRecord, ...]:
        history = self._history(tool)
        current_id = history.heads[0].version_id if len(history.heads) == 1 else None
        head_ids = {meta.version_id for meta in history.heads}
        return tuple(
            ConfigVersionRecord(
                meta=meta,
                current=meta.version_id == current_id,
                head=meta.version_id in head_ids,
            )
            for meta in history.versions
        )

    def push(
        self,
        tool: str,
        path: str | Path,
        *,
        allow_sensitive_plaintext: bool = False,
        resolve_conflict: bool = False,
    ) -> ConfigPushResult:
        normalized_tool = normalize_tool_name(tool)
        source = Path(path).expanduser()
        content = _read_local_config(source, self._settings.max_file_bytes)
        text = content.decode("utf-8")
        findings = sensitive_fields(text)
        if findings and not allow_sensitive_plaintext:
            fields = ", ".join(f"line {item.line_number}: {item.field}" for item in findings)
            raise SensitiveConfigError(
                "Refusing to store possible secret material as plaintext email.\n"
                f"Possible sensitive fields:\n    {fields}\n"
                "Review the file or explicitly accept plaintext exposure with --allow-sensitive-plaintext."
            )
        default_path = portable_default_path(source, home=self._home)
        filename = source.name
        if not filename:
            raise ConfigLedgerError("configuration path must name a file")
        history = self._history(normalized_tool)
        if len(history.heads) > 1:
            if not resolve_conflict:
                raise ConfigHistoryConflictError(
                    f"Config history conflict for tool '{normalized_tool}': {len(history.heads)} current heads"
                )
            parents = tuple(meta.version_id for meta in history.heads)
        elif history.heads:
            current = history.current
            if (
                current.content_sha256 == _sha256(content)
                and current.default_path == default_path
                and current.filename == filename
            ):
                return ConfigPushResult(snapshot=current, created=False)
            parents = (current.version_id,)
        else:
            parents = ()
        snapshot = create_snapshot(
            tool=normalized_tool,
            content=content,
            default_path=default_path,
            filename=filename,
            parent_version_ids=parents,
            max_file_bytes=self._settings.max_file_bytes,
        )
        appended = self._mailbox.append_snapshot(snapshot)
        return ConfigPushResult(snapshot=appended.meta, created=True)

    def cat(self, tool: str, *, version: str | None = None) -> str:
        snapshot = self._fetch_selected(tool, version)
        return snapshot.content.decode("utf-8")

    def diff(
        self,
        tool: str,
        *,
        version: str | None = None,
        path: str | Path | None = None,
        direction: DiffDirection = DiffDirection.LOCAL_TO_IMAP,
    ) -> str:
        snapshot = self._fetch_selected(tool, version)
        local_path = self._resolve_target(snapshot.meta, path)
        local_text = _read_local_config(local_path, self._settings.max_file_bytes).decode("utf-8")
        remote_text = snapshot.content.decode("utf-8")
        return render_config_diff(
            local_text=local_text,
            remote_text=remote_text,
            local_label=f"local:{local_path}",
            remote_label=f"imap:{snapshot.meta.tool}@{snapshot.meta.version_id}",
            direction=DiffDirection(direction),
        )

    def preview_pull(
        self,
        tool: str,
        *,
        version: str | None = None,
        to: str | Path | None = None,
    ) -> ConfigPullPreview:
        snapshot = self._fetch_selected(tool, version)
        target = self._resolve_target(snapshot.meta, to)
        if target.exists() and not target.is_file():
            raise ConfigLedgerError(f"pull target is not a regular file: {target}")
        existing_text = _read_existing(target, self._settings.max_file_bytes) if target.exists() else None
        remote_text = snapshot.content.decode("utf-8")
        diff = ""
        if existing_text is not None and existing_text != remote_text:
            diff = render_config_diff(
                local_text=existing_text,
                remote_text=remote_text,
                local_label=f"local:{target}",
                remote_label=f"imap:{snapshot.meta.tool}@{snapshot.meta.version_id}",
                direction=DiffDirection.LOCAL_TO_IMAP,
            )
        return ConfigPullPreview(
            tool=snapshot.meta.tool,
            version_id=snapshot.meta.version_id,
            target=target,
            content_sha256=snapshot.meta.content_sha256,
            target_exists=existing_text is not None,
            target_sha256=_sha256(existing_text.encode("utf-8")) if existing_text is not None else None,
            already_up_to_date=existing_text == remote_text,
            diff=diff,
        )

    def pull(
        self,
        tool: str,
        *,
        version: str | None = None,
        to: str | Path | None = None,
        force: bool = False,
        show_diff: bool = False,
        confirm_overwrite: OverwriteConfirmation | None = None,
        show_diff_callback: DiffDisplay | None = None,
    ) -> ConfigPullResult:
        snapshot = self._fetch_selected(tool, version)
        target = self._resolve_target(snapshot.meta, to)
        remote_text = snapshot.content.decode("utf-8")
        if target.exists() and not target.is_file():
            raise ConfigLedgerError(f"pull target is not a regular file: {target}")
        existing_text = _read_existing(target, self._settings.max_file_bytes) if target.exists() else None
        if existing_text == remote_text:
            return ConfigPullResult(
                target=target,
                version_id=snapshot.meta.version_id,
                written=False,
                already_up_to_date=True,
                cancelled=False,
            )

        diff = ""
        if existing_text is not None and (not force or show_diff):
            diff = render_config_diff(
                local_text=existing_text,
                remote_text=remote_text,
                local_label=f"local:{target}",
                remote_label=f"imap:{snapshot.meta.tool}@{snapshot.meta.version_id}",
                direction=DiffDirection.LOCAL_TO_IMAP,
            )
        if force and show_diff and diff and show_diff_callback is not None:
            show_diff_callback(target, diff)
        if existing_text is not None and not force:
            if confirm_overwrite is None:
                raise ConfigOverwriteConfirmationRequired(target, diff)
            if not confirm_overwrite(target, diff):
                return ConfigPullResult(
                    target=target,
                    version_id=snapshot.meta.version_id,
                    written=False,
                    already_up_to_date=False,
                    cancelled=True,
                    diff=diff,
                )
        _atomic_write(target, remote_text)
        return ConfigPullResult(
            target=target,
            version_id=snapshot.meta.version_id,
            written=True,
            already_up_to_date=False,
            cancelled=False,
            diff=diff,
        )

    def apply_pull(self, preview: ConfigPullPreview, *, confirm_overwrite: bool) -> ConfigPullResult:
        snapshot = self._fetch_selected(preview.tool, preview.version_id)
        if snapshot.meta.content_sha256 != preview.content_sha256:
            raise ConfigLedgerError("stored snapshot changed since preview; preview again")
        target = self._resolve_target(snapshot.meta, preview.target)
        if target != preview.target:
            raise ConfigLedgerError("pull target changed since preview; preview again")
        if target.exists() and not target.is_file():
            raise ConfigLedgerError(f"pull target is not a regular file: {target}")
        existing_text = _read_existing(target, self._settings.max_file_bytes) if target.exists() else None
        existing_sha256 = _sha256(existing_text.encode("utf-8")) if existing_text is not None else None
        if (existing_text is not None) != preview.target_exists or existing_sha256 != preview.target_sha256:
            raise ConfigLedgerError("local target changed since preview; preview again")
        if preview.already_up_to_date:
            return ConfigPullResult(
                target=target,
                version_id=preview.version_id,
                written=False,
                already_up_to_date=True,
                cancelled=False,
            )
        if preview.target_exists and not confirm_overwrite:
            raise ConfigOverwriteConfirmationRequired(target, preview.diff)

        def confirm(current_target: Path, diff: str) -> bool:
            if current_target != preview.target or not preview.target_exists or diff != preview.diff:
                raise ConfigLedgerError("local target changed since preview; preview again")
            latest_text = _read_existing(current_target, self._settings.max_file_bytes)
            if _sha256(latest_text.encode("utf-8")) != preview.target_sha256:
                raise ConfigLedgerError("local target changed since preview; preview again")
            return True

        return self.pull(
            preview.tool,
            version=preview.version_id,
            to=preview.target,
            confirm_overwrite=confirm if preview.target_exists else None,
        )

    def _history(self, tool: str) -> ConfigHistory:
        normalized_tool = normalize_tool_name(tool)
        scan = self._mailbox.scan_snapshot_metadata(normalized_tool)
        if scan.issues:
            issue = scan.issues[0]
            raise ConfigSnapshotIntegrityError(
                f"invalid config snapshot metadata for '{normalized_tool}' at UID {issue.uid}: {issue.reason}"
            )
        return build_history(scan.metadata, tool=normalized_tool)

    def _fetch_selected(self, tool: str, version: str | None) -> ConfigSnapshot:
        history = self._history(tool)
        meta = history.select(version)
        return self._mailbox.fetch_snapshot(meta)

    def _resolve_target(self, meta: ConfigSnapshotMeta, explicit: str | Path | None) -> Path:
        if explicit is not None:
            raw_path = str(explicit)
            if "\x00" in raw_path:
                raise ConfigLedgerError("target path contains NUL")
            return Path(explicit).expanduser()
        target = expand_default_path(meta.default_path, home=self._home)
        if not meta.default_path.startswith("~"):
            try:
                target.resolve().relative_to(self._home)
            except ValueError as exc:
                raise ConfigLedgerError(
                    "Stored default path is outside the current home directory:\n"
                    f"    {target}\n\n"
                    "Specify the destination explicitly:\n"
                    f"    imapledger config pull {meta.tool} --to {target}"
                ) from exc
        return target


def _summarize_history(history: ConfigHistory) -> ConfigToolSummary:
    if len(history.heads) > 1:
        paths = {meta.default_path for meta in history.heads}
        return ConfigToolSummary(
            tool=history.tool,
            versions=len(history.versions),
            status=ConfigToolStatus.CONFLICT,
            current=f"{len(history.heads)} heads",
            default_path=next(iter(paths)) if len(paths) == 1 else None,
            heads=len(history.heads),
        )
    current = history.current
    return ConfigToolSummary(
        tool=history.tool,
        versions=len(history.versions),
        status=ConfigToolStatus.OK,
        current=current.version_id,
        default_path=current.default_path,
        heads=1,
    )


def _read_local_config(path: Path, max_file_bytes: int) -> bytes:
    if not path.is_file():
        raise ConfigLedgerError(f"configuration file does not exist or is not a regular file: {path}")
    try:
        size = path.stat().st_size
        if size > max_file_bytes:
            raise ConfigLedgerError(f"configuration exceeds the {max_file_bytes}-byte limit")
        content = path.read_bytes()
    except ConfigLedgerError:
        raise
    except OSError as exc:
        raise ConfigLedgerError(f"could not read configuration file: {path}") from exc
    if len(content) > max_file_bytes:
        raise ConfigLedgerError(f"configuration exceeds the {max_file_bytes}-byte limit")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigSnapshotError("configuration content must be UTF-8 text") from exc
    if b"\x00" in content:
        raise ConfigSnapshotError("configuration text must not contain NUL")
    return content


def _read_existing(path: Path, max_file_bytes: int) -> str:
    content = _read_local_config(path, max_file_bytes)
    return content.decode("utf-8")


def _atomic_write(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, content)
    except (AtomicWriteError, OSError) as exc:
        raise ConfigLedgerError(f"could not atomically write configuration file: {path}") from exc


def _sha256(content: bytes) -> str:

    return hashlib.sha256(content).hexdigest()
