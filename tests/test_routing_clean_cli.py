from __future__ import annotations

import pytest
from typer.testing import CliRunner

from imapledger import cli
from imapledger.config import ImapSettings, Settings, SpamSettings
from imapledger.progress_store import ProgressStore, account_identity_key


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )


def _create_run(store: ProgressStore):
    return store.begin_run(
        account_key=account_identity_key(_settings()),
        source_folder="INBOX",
        uidvalidity=7,
        high_watermark_uid=12,
        rules_fingerprint="fingerprint-a",
        mode="full",
        rule_scope=None,
        sort_direction="oldest",
    )


def test_clean_folder_dispatches_resumable_options(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(cli, "_routing_clean", lambda folder, **kwargs: calls.append((folder, kwargs)))

    result = CliRunner().invoke(
        cli.app,
        [
            "clean",
            "INBOX",
            "--apply",
            "--limit",
            "2",
            "--rule",
            "invoice",
            "--sort",
            "oldest",
            "--new-run",
            "--no-progress",
            "--progress-db",
            str(tmp_path / "progress.sqlite3"),
            "--config",
            str(tmp_path / "config.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    folder, options = calls[0]
    assert folder == "INBOX"
    assert options["apply"] is True
    assert options["limit"] == 2
    assert options["rule"] == "invoice"
    assert options["sort"].value == "oldest"
    assert options["new_run"] is True
    assert options["retry_errors"] is False
    assert options["progress"] is False


def test_clean_folder_defaults_to_oldest_and_retry_requires_apply(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(cli, "_routing_clean", lambda folder, **kwargs: calls.append((folder, kwargs)))

    default_sort = CliRunner().invoke(
        cli.app,
        ["clean", "INBOX", "--config", str(tmp_path / "config.toml")],
    )
    assert default_sort.exit_code == 0, default_sort.output
    assert calls[0][1]["sort"].value == "oldest"

    missing_apply = CliRunner().invoke(cli.app, ["clean", "INBOX", "--retry-errors"])
    assert missing_apply.exit_code == 2
    assert "--retry-errors requires --apply" in missing_apply.output


def test_bare_clean_requires_compatibility_source_folders(monkeypatch) -> None:
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=()),
    )
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(cli, "_resolve_password", lambda _imap: pytest.fail("must not connect"))

    result = CliRunner().invoke(cli.app, ["clean"])

    assert result.exit_code == 2
    assert "bare `clean` requires spam.folders" in result.output


def test_rule_migrate_cli_previews_then_applies_explicitly(tmp_path) -> None:
    config = tmp_path / "imapledger.toml"
    path = tmp_path / "rules.toml"
    original = (
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "github"\n'
        'enabled = true\nsource_folders = ["INBOX"]\naction = "move"\n'
        'destination = "Development"\nmatch = { from_domain = "github.com" }\n'
    )
    path.write_text(original, encoding="utf-8")

    preview = CliRunner().invoke(
        cli.app,
        ["rule", "migrate", "--preview", "--config", str(config)],
    )
    assert preview.exit_code == 0, preview.output
    assert "Preview only" in preview.output
    assert "No fallback was inferred" in preview.output
    assert path.read_text(encoding="utf-8") == original

    applied = CliRunner().invoke(
        cli.app,
        ["rule", "migrate", "--apply", "--config", str(config)],
    )
    assert applied.exit_code == 0, applied.output
    assert "Migration applied" in applied.output
    assert "schema = 2" in path.read_text(encoding="utf-8")


def test_progress_show_errors_and_reset_are_account_scoped(monkeypatch, tmp_path) -> None:
    settings = _settings()
    database = tmp_path / "progress.sqlite3"
    store = ProgressStore(database)
    run = _create_run(store)
    store.record_result(run.id, uid=9, outcome="error", error_code="RuntimeError")
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)

    listed = CliRunner().invoke(
        cli.app,
        ["progress", "list", "--progress-db", str(database)],
    )
    assert listed.exit_code == 0
    assert "INBOX" in listed.output

    shown = CliRunner().invoke(
        cli.app,
        ["progress", "show", "INBOX", "--progress-db", str(database)],
    )
    assert shown.exit_code == 0
    assert "folder=INBOX" in shown.output
    assert "scanned=1" in shown.output

    errors = CliRunner().invoke(
        cli.app,
        ["progress", "errors", "INBOX", "--progress-db", str(database)],
    )
    assert errors.exit_code == 0
    assert "uid=9 error=RuntimeError" in errors.output

    reset = CliRunner().invoke(
        cli.app,
        ["progress", "reset", "INBOX", "--progress-db", str(database)],
        input="y\n",
    )
    assert reset.exit_code == 0
    assert "Deleted 1 progress run(s)" in reset.output
    assert store.list_runs(account_key=account_identity_key(settings), source_folder="INBOX") == ()
