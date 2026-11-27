from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .config import ImapSettings, Settings
from .routing_actions import RuleAction

RunMode = Literal["full", "single-rule"]
SortDirection = Literal["oldest", "newest"]
_RESULT_OUTCOMES = {
    "match",
    "no_match",
    "kept",
    "moved",
    "deleted",
    "already_there",
    "blocked",
    "error",
    "reconciled_missing",
}
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


class ProgressStoreError(RuntimeError):
    """Invalid or unavailable durable progress state."""


class ProgressResumeError(ProgressStoreError):
    """A prior run cannot be resumed safely."""


@dataclass(frozen=True, slots=True)
class ProgressRun:
    id: str
    account_key: str
    source_folder: str
    uidvalidity: int
    high_watermark_uid: int
    lower_bound_uid: int
    rules_fingerprint: str
    mode: RunMode
    rule_scope: str | None
    sort_direction: SortDirection
    status: str
    cursor_uid: int | None
    started_at: str
    updated_at: str
    completed_at: str | None
    scanned_count: int
    match_count: int
    moved_count: int
    no_match_count: int
    error_count: int
    acted_count: int = 0
    deleted_count: int = 0
    kept_count: int = 0


@dataclass(frozen=True, slots=True)
class MessageResult:
    run_id: str
    uid: int
    outcome: str
    winner_rule_id: str | None
    destination: str | None
    applied: bool
    confirmed: bool
    model: str | None
    request_id: str | None
    error_code: str | None
    processed_at: str

    configured_action: RuleAction | None = None
    detail: str | None = None


def default_progress_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "imapledger" / "progress.sqlite3"


def account_identity_key(imap: ImapSettings | Settings) -> str:
    settings = imap.imap if isinstance(imap, Settings) else imap
    identity = json.dumps(
        {"host": settings.host.casefold(), "port": settings.port, "username": settings.username},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


class ProgressStore:
    """Transactional SQLite ledger for resumable clean runs."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else default_progress_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def begin_run(
        self,
        *,
        account_key: str,
        source_folder: str,
        uidvalidity: int,
        high_watermark_uid: int,
        rules_fingerprint: str,
        mode: RunMode,
        rule_scope: str | None,
        sort_direction: SortDirection,
        new_run: bool = False,
    ) -> ProgressRun:
        _validate_run_identity(
            account_key=account_key,
            source_folder=source_folder,
            uidvalidity=uidvalidity,
            high_watermark_uid=high_watermark_uid,
            rules_fingerprint=rules_fingerprint,
            mode=mode,
            rule_scope=rule_scope,
            sort_direction=sort_direction,
        )
        now = _now()
        invalidated_uidvalidity = False
        with self._transaction() as connection:
            active_runs = connection.execute(
                "SELECT * FROM runs WHERE account_key = ? AND source_folder = ? AND status = 'active'",
                (account_key, source_folder),
            ).fetchall()
            resumable: sqlite3.Row | None = None
            for row in active_runs:
                if row["uidvalidity"] != uidvalidity:
                    connection.execute(
                        "UPDATE runs SET status = 'invalidated', updated_at = ? WHERE id = ?",
                        (now, row["id"]),
                    )
                    invalidated_uidvalidity = True
                    continue
                same_scope = row["mode"] == mode and row["rule_scope"] == rule_scope
                if not same_scope:
                    continue
                same_rules = row["rules_fingerprint"] == rules_fingerprint
                same_sort = row["sort_direction"] == sort_direction
                if not new_run and same_rules and same_sort:
                    resumable = row
                    break
                connection.execute(
                    "UPDATE runs SET status = 'superseded', updated_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
            if resumable is not None:
                return _run_from_row(resumable)
            if invalidated_uidvalidity and not new_run:
                invalidated = True
            else:
                invalidated = False
                run_id = str(uuid.uuid4())
                lower_bound_uid = 0
                if not new_run:
                    previous = connection.execute(
                        """SELECT high_watermark_uid FROM runs
                        WHERE account_key = ? AND source_folder = ? AND uidvalidity = ?
                          AND mode = ? AND rule_scope IS ? AND rules_fingerprint = ?
                          AND status = 'completed'
                        ORDER BY started_at DESC LIMIT 1""",
                        (account_key, source_folder, uidvalidity, mode, rule_scope, rules_fingerprint),
                    ).fetchone()
                    if previous is not None:
                        lower_bound_uid = min(previous["high_watermark_uid"], high_watermark_uid)
                connection.execute(
                    """INSERT INTO runs (
                        id, account_key, source_folder, uidvalidity, high_watermark_uid,
                        lower_bound_uid, rules_fingerprint, mode, rule_scope, sort_direction, status,
                        cursor_uid, started_at, updated_at, completed_at, scanned_count,
                        match_count, moved_count, no_match_count, error_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?, ?, NULL, 0, 0, 0, 0, 0)""",
                    (
                        run_id,
                        account_key,
                        source_folder,
                        uidvalidity,
                        high_watermark_uid,
                        lower_bound_uid,
                        rules_fingerprint,
                        mode,
                        rule_scope,
                        sort_direction,
                        now,
                        now,
                    ),
                )
                row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
                assert row is not None
                created = _run_from_row(row)
        if invalidated:
            raise ProgressResumeError(
                "UIDVALIDITY changed; the previous run was invalidated. Start a new run explicitly."
            )
        if resumable is not None:
            return _run_from_row(resumable)
        return created

    def get_run(self, run_id: str) -> ProgressRun:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise ProgressStoreError(f"run not found: {run_id}")
        return _run_from_row(row)

    def list_runs(
        self,
        *,
        account_key: str | None = None,
        source_folder: str | None = None,
        limit: int = 100,
    ) -> tuple[ProgressRun, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ProgressStoreError("run list limit must be between 1 and 1000")
        clauses: list[str] = []
        values: list[object] = []
        if account_key is not None:
            clauses.append("account_key = ?")
            values.append(account_key)
        if source_folder is not None:
            clauses.append("source_folder = ?")
            values.append(source_folder)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM runs {where} ORDER BY started_at DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
        return tuple(_run_from_row(row) for row in rows)

    def record_result(
        self,
        run_id: str,
        *,
        uid: int,
        outcome: str,
        winner_rule_id: str | None = None,
        destination: str | None = None,
        configured_action: RuleAction | str | None = None,
        detail: str | None = None,
        applied: bool = False,
        confirmed: bool = False,
        model: str | None = None,
        request_id: str | None = None,
        error_code: str | None = None,
        advance_cursor: bool = True,
    ) -> ProgressRun:
        _validate_result(
            uid=uid,
            outcome=outcome,
            applied=applied,
            confirmed=confirmed,
            error_code=error_code,
            configured_action=configured_action,
            detail=detail,
        )
        now = _now()
        with self._transaction() as connection:
            run_row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run_row is None:
                raise ProgressStoreError(f"run not found: {run_id}")
            run = _run_from_row(run_row)
            if run.status != "active":
                raise ProgressStoreError(f"run is not active: {run.status}")
            if uid > run.high_watermark_uid:
                raise ProgressStoreError("result UID exceeds the run high-watermark")
            prior = connection.execute(
                "SELECT * FROM message_results WHERE run_id = ? AND uid = ?",
                (run_id, uid),
            ).fetchone()
            old_counts = _result_counts(prior) if prior is not None else (0, 0, 0, 0, 0, 0, 0)
            result = MessageResult(
                run_id=run_id,
                uid=uid,
                outcome=outcome,
                winner_rule_id=winner_rule_id,
                destination=destination,
                applied=applied,
                confirmed=confirmed,
                model=model,
                request_id=request_id,
                error_code=error_code,
                processed_at=now,
                configured_action=RuleAction(configured_action) if configured_action is not None else None,
                detail=detail,
            )
            connection.execute(
                """INSERT INTO message_results (
                    run_id, uid, outcome, winner_rule_id, destination, applied,
                    confirmed, model, request_id, error_code, configured_action, detail, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, uid) DO UPDATE SET
                    outcome = excluded.outcome,
                    winner_rule_id = excluded.winner_rule_id,
                    destination = excluded.destination,
                    applied = excluded.applied,
                    confirmed = excluded.confirmed,
                    model = excluded.model,
                    request_id = excluded.request_id,
                    error_code = excluded.error_code,
                    configured_action = excluded.configured_action,
                    detail = excluded.detail,
                    processed_at = excluded.processed_at""",
                (
                    result.run_id,
                    result.uid,
                    result.outcome,
                    result.winner_rule_id,
                    result.destination,
                    int(result.applied),
                    int(result.confirmed),
                    result.model,
                    result.request_id,
                    result.error_code,
                    result.configured_action.value if result.configured_action is not None else None,
                    result.detail,
                    result.processed_at,
                ),
            )
            new_counts = _result_counts(result)
            scanned_delta = 0 if prior is not None else 1
            cursor_uid = run.cursor_uid
            if advance_cursor:
                cursor_uid = _advance_cursor(cursor_uid, uid, run.sort_direction)
            connection.execute(
                """UPDATE runs SET
                    cursor_uid = ?, updated_at = ?,
                    scanned_count = scanned_count + ?,
                    match_count = match_count + ?,
                    acted_count = acted_count + ?,
                    moved_count = moved_count + ?,
                    deleted_count = deleted_count + ?,
                    kept_count = kept_count + ?,
                    no_match_count = no_match_count + ?,
                    error_count = error_count + ?
                WHERE id = ?""",
                (
                    cursor_uid,
                    now,
                    scanned_delta,
                    new_counts[0] - old_counts[0],
                    new_counts[1] - old_counts[1],
                    new_counts[2] - old_counts[2],
                    new_counts[3] - old_counts[3],
                    new_counts[4] - old_counts[4],
                    new_counts[5] - old_counts[5],
                    new_counts[6] - old_counts[6],
                    run_id,
                ),
            )
            updated = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            assert updated is not None
            return _run_from_row(updated)

    def get_result(self, run_id: str, uid: int) -> MessageResult | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM message_results WHERE run_id = ? AND uid = ?",
                (run_id, uid),
            ).fetchone()
        return _result_from_row(row) if row is not None else None

    def results(self, run_id: str) -> tuple[MessageResult, ...]:
        run = self.get_run(run_id)
        order = "ASC" if run.sort_direction == "oldest" else "DESC"
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM message_results WHERE run_id = ? ORDER BY uid {order}",
                (run_id,),
            ).fetchall()
        return tuple(_result_from_row(row) for row in rows)

    def errors(self, run_id: str, *, limit: int | None = None) -> tuple[MessageResult, ...]:
        run = self.get_run(run_id)
        order = "ASC" if run.sort_direction == "oldest" else "DESC"
        query = (
            f"SELECT * FROM message_results WHERE run_id = ? AND outcome IN ('error', 'blocked') ORDER BY uid {order}"
        )
        values: tuple[object, ...] = (run_id,)
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ProgressStoreError("error list limit must be a positive integer")
            query += " LIMIT ?"
            values = (run_id, limit)
        with self._connection() as connection:
            rows = connection.execute(query, values).fetchall()
        return tuple(_result_from_row(row) for row in rows)

    def retry_errors(self, run_id: str, *, limit: int | None = None) -> tuple[int, ...]:
        error_rows = self.errors(run_id, limit=limit)
        if not error_rows:
            return ()
        with self._transaction() as connection:
            run = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise ProgressStoreError(f"run not found: {run_id}")
            if run["status"] not in {"active", "completed"}:
                raise ProgressStoreError(f"run cannot be retried: {run['status']}")
            if run["status"] == "completed":
                connection.execute(
                    "UPDATE runs SET status = 'active', completed_at = NULL, updated_at = ? WHERE id = ?",
                    (_now(), run_id),
                )
        return tuple(result.uid for result in error_rows)

    def invalidate_run(self, run_id: str) -> ProgressRun:
        now = _now()
        with self._transaction() as connection:
            row = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise ProgressStoreError(f"run not found: {run_id}")
            if row["status"] not in {"active", "completed"}:
                raise ProgressStoreError(f"run cannot be invalidated: {row['status']}")
            connection.execute(
                "UPDATE runs SET status = 'invalidated', updated_at = ?, completed_at = NULL WHERE id = ?",
                (now, run_id),
            )
            updated = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            assert updated is not None
            return _run_from_row(updated)

    def complete_run(self, run_id: str) -> ProgressRun:
        now = _now()
        with self._transaction() as connection:
            row = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise ProgressStoreError(f"run not found: {run_id}")
            if row["status"] != "active":
                raise ProgressStoreError(f"run is not active: {row['status']}")
            connection.execute(
                "UPDATE runs SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?",
                (now, now, run_id),
            )
            updated = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            assert updated is not None
            return _run_from_row(updated)

    def reset_run(self, run_id: str) -> None:
        with self._transaction() as connection:
            cursor = connection.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            if cursor.rowcount == 0:
                raise ProgressStoreError(f"run not found: {run_id}")

    def reset_folder(self, account_key: str, source_folder: str) -> int:
        with self._transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM runs WHERE account_key = ? AND source_folder = ?",
                (account_key, source_folder),
            )
            return cursor.rowcount

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > 3:
                raise ProgressStoreError(f"unsupported progress database version: {version}")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    account_key TEXT NOT NULL,
                    source_folder TEXT NOT NULL,
                    uidvalidity INTEGER NOT NULL,
                    high_watermark_uid INTEGER NOT NULL,
                    lower_bound_uid INTEGER NOT NULL DEFAULT 0,
                    rules_fingerprint TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    rule_scope TEXT,
                    sort_direction TEXT NOT NULL,
                    status TEXT NOT NULL,
                    cursor_uid INTEGER,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    scanned_count INTEGER NOT NULL DEFAULT 0,
                    match_count INTEGER NOT NULL DEFAULT 0,
                    acted_count INTEGER NOT NULL DEFAULT 0,
                    moved_count INTEGER NOT NULL DEFAULT 0,
                    deleted_count INTEGER NOT NULL DEFAULT 0,
                    kept_count INTEGER NOT NULL DEFAULT 0,
                    no_match_count INTEGER NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS runs_identity_idx
                    ON runs(account_key, source_folder, status, started_at);
                CREATE TABLE IF NOT EXISTS message_results (
                    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                    uid INTEGER NOT NULL,
                    outcome TEXT NOT NULL,
                    winner_rule_id TEXT,
                    destination TEXT,
                    applied INTEGER NOT NULL,
                    confirmed INTEGER NOT NULL,
                    model TEXT,
                    request_id TEXT,
                    error_code TEXT,
                    configured_action TEXT,
                    detail TEXT,
                    processed_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, uid)
                );"""
            )
            run_columns = {row["name"] for row in connection.execute("PRAGMA table_info(runs)")}
            run_additions = {
                "lower_bound_uid": "INTEGER NOT NULL DEFAULT 0",
                "acted_count": "INTEGER NOT NULL DEFAULT 0",
                "deleted_count": "INTEGER NOT NULL DEFAULT 0",
                "kept_count": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in run_additions.items():
                if name not in run_columns:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {name} {definition}")
            result_columns = {row["name"] for row in connection.execute("PRAGMA table_info(message_results)")}
            if "configured_action" not in result_columns:
                connection.execute("ALTER TABLE message_results ADD COLUMN configured_action TEXT")
            if "detail" not in result_columns:
                connection.execute("ALTER TABLE message_results ADD COLUMN detail TEXT")

            if version < 3:
                connection.execute(
                    """UPDATE message_results SET configured_action = CASE
                        WHEN outcome IN ('deleted', 'blocked') THEN 'delete'
                        WHEN destination IS NOT NULL OR outcome = 'already_there' THEN 'move'
                        WHEN outcome = 'match' AND winner_rule_id IS NOT NULL THEN 'keep'
                        ELSE configured_action END
                        WHERE configured_action IS NULL"""
                )
                connection.execute(
                    """UPDATE message_results SET outcome = CASE configured_action
                        WHEN 'move' THEN 'moved'
                        WHEN 'keep' THEN 'kept'
                        WHEN 'delete' THEN 'deleted'
                        ELSE outcome END
                        WHERE outcome = 'match' AND applied = 1 AND confirmed = 1"""
                )
                connection.execute(
                    """UPDATE runs SET
                        match_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.winner_rule_id IS NOT NULL
                              AND r.outcome NOT IN ('error', 'blocked', 'reconciled_missing')),
                        acted_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.applied = 1 AND r.confirmed = 1
                              AND r.configured_action IS NOT NULL),
                        moved_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.outcome = 'moved'),
                        deleted_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.outcome = 'deleted'),
                        kept_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.outcome = 'kept'),
                        no_match_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.outcome = 'no_match'),
                        error_count = (SELECT COUNT(*) FROM message_results r
                            WHERE r.run_id = runs.id AND r.outcome IN ('error', 'blocked'))"""
                )
            connection.execute("PRAGMA user_version = 3")
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def _validate_run_identity(
    *,
    account_key: str,
    source_folder: str,
    uidvalidity: int,
    high_watermark_uid: int,
    rules_fingerprint: str,
    mode: str,
    rule_scope: str | None,
    sort_direction: str,
) -> None:
    if not isinstance(account_key, str) or not account_key:
        raise ProgressStoreError("account key must be non-empty")
    if not isinstance(source_folder, str) or not source_folder.strip():
        raise ProgressStoreError("source folder must be non-empty")
    if isinstance(uidvalidity, bool) or not isinstance(uidvalidity, int) or uidvalidity < 1:
        raise ProgressStoreError("UIDVALIDITY must be a positive integer")
    if isinstance(high_watermark_uid, bool) or not isinstance(high_watermark_uid, int) or high_watermark_uid < 0:
        raise ProgressStoreError("high-watermark UID must be a non-negative integer")
    if not isinstance(rules_fingerprint, str) or not rules_fingerprint:
        raise ProgressStoreError("rules fingerprint must be non-empty")
    if mode not in {"full", "single-rule"}:
        raise ProgressStoreError("run mode must be full or single-rule")
    if mode == "single-rule" and (not isinstance(rule_scope, str) or not rule_scope):
        raise ProgressStoreError("single-rule mode requires a rule scope")
    if mode == "full" and rule_scope is not None:
        raise ProgressStoreError("full mode cannot have a rule scope")
    if sort_direction not in {"oldest", "newest"}:
        raise ProgressStoreError("sort direction must be oldest or newest")


def _validate_result(
    *,
    uid: int,
    outcome: str,
    applied: bool,
    confirmed: bool,
    error_code: str | None,
    configured_action: RuleAction | str | None,
    detail: str | None,
) -> None:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
        raise ProgressStoreError("message UID must be a positive integer")
    if outcome not in _RESULT_OUTCOMES:
        raise ProgressStoreError(f"unsupported message outcome: {outcome}")
    if not isinstance(applied, bool) or not isinstance(confirmed, bool):
        raise ProgressStoreError("applied and confirmed must be booleans")
    if configured_action is not None:
        try:
            RuleAction(configured_action)
        except (TypeError, ValueError) as exc:
            raise ProgressStoreError("configured action must be move, delete, or keep") from exc
    if error_code is not None and (not isinstance(error_code, str) or _ERROR_CODE.fullmatch(error_code) is None):
        raise ProgressStoreError("error code must be a short identifier, not an exception message")
    if detail is not None and (not isinstance(detail, str) or len(detail) > 512):
        raise ProgressStoreError("result detail must be a string of at most 512 characters")


def _result_counts(result: sqlite3.Row | MessageResult) -> tuple[int, int, int, int, int, int, int]:
    outcome = result["outcome"] if isinstance(result, sqlite3.Row) else result.outcome
    winner = result["winner_rule_id"] if isinstance(result, sqlite3.Row) else result.winner_rule_id
    applied = bool(result["applied"] if isinstance(result, sqlite3.Row) else result.applied)
    confirmed = bool(result["confirmed"] if isinstance(result, sqlite3.Row) else result.confirmed)
    configured_action = result["configured_action"] if isinstance(result, sqlite3.Row) else result.configured_action
    is_error = outcome in {"error", "blocked"}
    matched = outcome not in {"error", "reconciled_missing"} and winner is not None
    acted = applied and confirmed and configured_action is not None
    moved = acted and configured_action == RuleAction.MOVE.value and outcome == "moved"
    deleted = acted and configured_action == RuleAction.DELETE.value and outcome == "deleted"
    kept = acted and configured_action == RuleAction.KEEP.value and outcome == "kept"
    return (
        int(matched),
        int(acted),
        int(moved),
        int(deleted),
        int(kept),
        int(outcome == "no_match"),
        int(is_error),
    )


def _advance_cursor(current: int | None, uid: int, direction: SortDirection) -> int:
    if current is None:
        return uid
    return max(current, uid) if direction == "oldest" else min(current, uid)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _run_from_row(row: sqlite3.Row) -> ProgressRun:
    return ProgressRun(
        id=row["id"],
        account_key=row["account_key"],
        source_folder=row["source_folder"],
        uidvalidity=row["uidvalidity"],
        high_watermark_uid=row["high_watermark_uid"],
        lower_bound_uid=row["lower_bound_uid"],
        rules_fingerprint=row["rules_fingerprint"],
        mode=row["mode"],
        rule_scope=row["rule_scope"],
        sort_direction=row["sort_direction"],
        status=row["status"],
        cursor_uid=row["cursor_uid"],
        started_at=row["started_at"],
        updated_at=row["updated_at"],
        completed_at=row["completed_at"],
        scanned_count=row["scanned_count"],
        match_count=row["match_count"],
        moved_count=row["moved_count"],
        acted_count=row["acted_count"],
        deleted_count=row["deleted_count"],
        kept_count=row["kept_count"],
        no_match_count=row["no_match_count"],
        error_count=row["error_count"],
    )


def _result_from_row(row: sqlite3.Row) -> MessageResult:
    return MessageResult(
        run_id=row["run_id"],
        uid=row["uid"],
        outcome=row["outcome"],
        winner_rule_id=row["winner_rule_id"],
        destination=row["destination"],
        applied=bool(row["applied"]),
        confirmed=bool(row["confirmed"]),
        model=row["model"],
        request_id=row["request_id"],
        error_code=row["error_code"],
        processed_at=row["processed_at"],
        configured_action=RuleAction(row["configured_action"]) if row["configured_action"] is not None else None,
        detail=row["detail"],
    )
