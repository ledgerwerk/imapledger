from __future__ import annotations

import sqlite3

import pytest

from imapledger.config import ImapSettings, Settings
from imapledger.progress_store import (
    ProgressResumeError,
    ProgressStore,
    ProgressStoreError,
    account_identity_key,
    default_progress_path,
)
from imapledger.routing_actions import RuleAction


def _settings(host: str = "imap.example.org", username: str = "user@example.org") -> Settings:
    return Settings(
        imap=ImapSettings(host=host, username=username),
    )


def _begin(
    store: ProgressStore,
    *,
    uidvalidity: int = 42,
    high_watermark_uid: int = 100,
    fingerprint: str = "fingerprint-a",
    mode: str = "full",
    rule_scope: str | None = None,
    sort_direction: str = "oldest",
    new_run: bool = False,
):
    return store.begin_run(
        account_key=account_identity_key(_settings()),
        source_folder="INBOX",
        uidvalidity=uidvalidity,
        high_watermark_uid=high_watermark_uid,
        rules_fingerprint=fingerprint,
        mode=mode,
        rule_scope=rule_scope,
        sort_direction=sort_direction,
        new_run=new_run,
    )


def test_account_key_is_stable_and_default_database_uses_xdg_state_home(tmp_path, monkeypatch) -> None:
    settings = _settings()
    assert account_identity_key(settings) == account_identity_key(_settings("IMAP.EXAMPLE.ORG"))
    assert account_identity_key(settings) != account_identity_key(_settings(username="other@example.org"))

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert default_progress_path() == tmp_path / "imapledger" / "progress.sqlite3"


def test_begin_run_resumes_same_identity_and_preserves_stable_high_watermark(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    first = _begin(store, high_watermark_uid=100)

    reopened_store = ProgressStore(store.path)
    resumed = _begin(reopened_store, high_watermark_uid=250)

    assert resumed.id == first.id
    assert resumed.high_watermark_uid == 100
    assert resumed.cursor_uid is None
    assert resumed.scanned_count == 0
    assert store.results(first.id) == ()


def test_changed_fingerprint_supersedes_old_run_and_starts_new_identity(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    old = _begin(store)
    store.record_result(old.id, uid=9, outcome="moved",
        configured_action=RuleAction.MOVE,
        applied=True,
        confirmed=True, winner_rule_id="invoice")

    current = _begin(store, fingerprint="fingerprint-b", high_watermark_uid=120)

    assert current.id != old.id
    assert current.cursor_uid is None
    assert store.get_run(old.id).status == "superseded"
    assert store.get_run(old.id).cursor_uid == 9
    assert current.high_watermark_uid == 120


def test_uidvalidity_change_invalidates_and_requires_explicit_new_run(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    old = _begin(store)

    with pytest.raises(ProgressResumeError, match="UIDVALIDITY changed"):
        _begin(store, uidvalidity=43)

    assert store.get_run(old.id).status == "invalidated"
    current = _begin(store, uidvalidity=43, new_run=True)
    assert current.id != old.id
    assert current.uidvalidity == 43
    assert current.status == "active"


def test_completed_run_can_be_invalidated_when_retry_observes_new_uidvalidity(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    run = _begin(store)
    store.record_result(run.id, uid=9, outcome="error", error_code="RuntimeError")
    store.complete_run(run.id)

    invalidated = store.invalidate_run(run.id)

    assert invalidated.status == "invalidated"
    assert invalidated.completed_at is None


def test_apply_checkpoints_are_transactional_idempotent_and_retryable(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    run = _begin(store)

    checkpoint = store.record_result(
        run.id,
        uid=9,
        outcome="moved",
        winner_rule_id="invoice",
        destination="Invoices",
        applied=True,
        configured_action=RuleAction.MOVE,
        confirmed=True,
        model="bundle-model",
        request_id="request-9",
    )
    assert (checkpoint.cursor_uid, checkpoint.scanned_count, checkpoint.match_count) == (9, 1, 1)
    assert checkpoint.moved_count == 1
    assert checkpoint.acted_count == 1

    error = store.record_result(run.id, uid=20, outcome="error", error_code="RuntimeError")
    assert (error.cursor_uid, error.scanned_count, error.error_count) == (20, 2, 1)
    assert tuple(result.uid for result in store.errors(run.id)) == (20,)
    assert store.complete_run(run.id).status == "completed"

    assert store.retry_errors(run.id) == (20,)
    assert store.get_run(run.id).status == "active"
    retried = store.record_result(
        run.id,
        uid=20,
        outcome="no_match",
        advance_cursor=True,
    )
    assert (retried.cursor_uid, retried.scanned_count) == (20, 2)
    assert (retried.error_count, retried.no_match_count, retried.moved_count) == (0, 1, 1)
    completed = store.complete_run(run.id)
    assert completed.status == "completed"
    assert completed.completed_at is not None

    next_run = _begin(store, high_watermark_uid=120)
    assert next_run.id != run.id
    assert next_run.lower_bound_uid == 100
    assert next_run.status == "active"


def test_newest_cursor_moves_downward_and_single_rule_nonmatch_is_checkpointed(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    run = _begin(store, mode="single-rule", rule_scope="invoice", sort_direction="newest")

    newer = store.record_result(run.id, uid=100, outcome="no_match")
    older = store.record_result(run.id, uid=80, outcome="no_match")

    assert newer.cursor_uid == 100
    assert older.cursor_uid == 80
    assert older.scanned_count == 2
    assert older.no_match_count == 2
    assert older.moved_count == 0
    assert tuple(result.uid for result in store.results(run.id)) == (100, 80)


def test_progress_rows_do_not_expose_mail_content_or_password_fields(tmp_path) -> None:
    database = tmp_path / "progress.sqlite3"
    settings = _settings(username="sensitive-account@example.org")
    store = ProgressStore(database)
    run = store.begin_run(
        account_key=account_identity_key(settings),
        source_folder="INBOX",
        uidvalidity=42,
        high_watermark_uid=100,
        rules_fingerprint="fingerprint-a",
        mode="full",
        rule_scope=None,
        sort_direction="oldest",
    )
    store.record_result(
        run.id,
        uid=9,
        outcome="error",
        error_code="RuntimeError",
        model="bundle-model",
        request_id="request-9",
    )

    with sqlite3.connect(database) as connection:
        run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
        result_columns = {row[1] for row in connection.execute("PRAGMA table_info(message_results)")}
    forbidden = {"password", "body", "headers", "subject", "sender", "attachment"}
    assert not forbidden.intersection(run_columns | result_columns)
    stored = database.read_bytes()
    assert b"sensitive-account@example.org" not in stored
    assert b"MAIL-BODY-SECRET" not in stored


def test_progress_rejects_results_outside_high_watermark_and_unsafe_error_details(tmp_path) -> None:
    store = ProgressStore(tmp_path / "progress.sqlite3")
    run = _begin(store, high_watermark_uid=10)

    with pytest.raises(ProgressStoreError, match="exceeds"):
        store.record_result(run.id, uid=11, outcome="no_match")
    with pytest.raises(ProgressStoreError, match="short identifier"):
        store.record_result(run.id, uid=9, outcome="error", error_code="MAIL BODY SECRET: content")



def test_schema_two_progress_database_migrates_action_results_and_counters(tmp_path) -> None:
    database = tmp_path / "legacy-progress.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """PRAGMA user_version = 2;
            CREATE TABLE runs (
                id TEXT PRIMARY KEY, account_key TEXT NOT NULL, source_folder TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL, high_watermark_uid INTEGER NOT NULL,
                lower_bound_uid INTEGER NOT NULL DEFAULT 0, rules_fingerprint TEXT NOT NULL,
                mode TEXT NOT NULL, rule_scope TEXT, sort_direction TEXT NOT NULL,
                status TEXT NOT NULL, cursor_uid INTEGER, started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, completed_at TEXT, scanned_count INTEGER NOT NULL,
                match_count INTEGER NOT NULL, moved_count INTEGER NOT NULL,
                no_match_count INTEGER NOT NULL, error_count INTEGER NOT NULL
            );
            CREATE TABLE message_results (
                run_id TEXT NOT NULL, uid INTEGER NOT NULL, outcome TEXT NOT NULL,
                winner_rule_id TEXT, destination TEXT, applied INTEGER NOT NULL,
                confirmed INTEGER NOT NULL, model TEXT, request_id TEXT,
                error_code TEXT, processed_at TEXT NOT NULL, PRIMARY KEY(run_id, uid)
            );"""
        )
        connection.execute(
            """INSERT INTO runs VALUES (
                'legacy-run', 'account', 'INBOX', 42, 3, 0, 'fingerprint', 'full', NULL,
                'oldest', 'completed', 3, 'start', 'update', 'complete', 3, 2, 1, 1, 0
            )"""
        )
        connection.executemany(
            "INSERT INTO message_results VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'processed')",
            (
                ("legacy-run", 1, "match", "spam", "Archive", 1, 1),
                ("legacy-run", 2, "match", "keep-rule", None, 1, 1),
                ("legacy-run", 3, "no_match", None, None, 0, 0),
            ),
        )

    store = ProgressStore(database)
    run = store.get_run("legacy-run")
    results = store.results("legacy-run")
    with sqlite3.connect(database) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]

    assert version == 3
    assert (run.acted_count, run.moved_count, run.deleted_count, run.kept_count) == (2, 1, 0, 1)
    assert (run.match_count, run.no_match_count, run.error_count) == (2, 1, 0)
    assert [result.outcome for result in results] == ["moved", "kept", "no_match"]
    assert [result.configured_action for result in results] == [RuleAction.MOVE, RuleAction.KEEP, None]
