from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .config_errors import ConfigHistoryConflictError, ConfigHistoryError, ConfigVersionNotFoundError
from .config_snapshot import ConfigSnapshotMeta, normalize_tool_name


@dataclass(frozen=True, slots=True)
class ConfigHistory:
    tool: str
    versions: tuple[ConfigSnapshotMeta, ...]
    heads: tuple[ConfigSnapshotMeta, ...]

    @property
    def current(self) -> ConfigSnapshotMeta:
        if not self.heads:
            raise ConfigVersionNotFoundError(f"config history for '{self.tool}' has no snapshots")
        if len(self.heads) > 1:
            raise ConfigHistoryConflictError(
                f"Config history conflict for tool '{self.tool}': {len(self.heads)} current heads"
            )
        return self.heads[0]

    def select(self, version: str | None = None) -> ConfigSnapshotMeta:
        if version is None:
            return self.current
        matches = [item for item in self.versions if item.version_id.startswith(version)]
        if not matches:
            raise ConfigVersionNotFoundError(f"version '{version}' not found for tool '{self.tool}'")
        if len(matches) > 1:
            raise ConfigHistoryError(f"version prefix '{version}' is ambiguous for tool '{self.tool}'")
        return matches[0]


def build_history(snapshots: Iterable[ConfigSnapshotMeta], *, tool: str) -> ConfigHistory:
    normalized_tool = normalize_tool_name(tool)
    by_version: dict[str, ConfigSnapshotMeta] = {}
    for snapshot in snapshots:
        if snapshot.tool != normalized_tool:
            continue
        existing = by_version.get(snapshot.version_id)
        if existing is None:
            by_version[snapshot.version_id] = snapshot
        elif _semantic_metadata(existing) != _semantic_metadata(snapshot):
            raise ConfigHistoryError(f"duplicate version ID has conflicting metadata: {snapshot.version_id}")

    versions = tuple(sorted(by_version.values(), key=lambda item: (item.created_at, item.version_id)))
    version_ids = set(by_version)
    referenced: set[str] = set()
    for snapshot in versions:
        for parent in snapshot.parent_version_ids:
            if parent not in version_ids:
                raise ConfigHistoryError(
                    f"snapshot {snapshot.version_id} references missing parent {parent} for tool '{normalized_tool}'"
                )
            if parent == snapshot.version_id:
                raise ConfigHistoryError(f"snapshot {snapshot.version_id} cannot be its own parent")
            referenced.add(parent)

    _reject_cycles(by_version)
    heads = tuple(item for item in versions if item.version_id not in referenced)
    return ConfigHistory(tool=normalized_tool, versions=versions, heads=heads)


def group_histories(snapshots: Iterable[ConfigSnapshotMeta]) -> tuple[ConfigHistory, ...]:
    grouped: dict[str, list[ConfigSnapshotMeta]] = {}
    for snapshot in snapshots:
        grouped.setdefault(snapshot.tool, []).append(snapshot)
    return tuple(build_history(group, tool=tool) for tool, group in sorted(grouped.items()))


def _semantic_metadata(meta: ConfigSnapshotMeta) -> tuple[object, ...]:
    return (
        meta.tool,
        meta.version_id,
        meta.parent_version_ids,
        meta.created_at,
        meta.default_path,
        meta.filename,
        meta.content_sha256,
        meta.size_bytes,
        meta.schema,
    )


def _reject_cycles(snapshots: dict[str, ConfigSnapshotMeta]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(version_id: str) -> None:
        if version_id in visiting:
            raise ConfigHistoryError(f"cycle detected in config history at {version_id}")
        if version_id in visited:
            return
        visiting.add(version_id)
        for parent in snapshots[version_id].parent_version_ids:
            if parent in snapshots:
                visit(parent)
        visiting.remove(version_id)
        visited.add(version_id)

    for version_id in snapshots:
        visit(version_id)
