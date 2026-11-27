from __future__ import annotations

import pytest
from typer.testing import CliRunner

from imapledger import cli
from imapledger.config import ImapSettings, Settings
from imapledger.progress_store import ProgressStore, account_identity_key
from imapledger.routing_config import load_routing_rules


def _settings() -> Settings:
    return Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org"))


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


def test_clean_is_a_deprecated_alias_to_the_shared_rule_run(monkeypatch, tmp_path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli, "_execute_rule_run", lambda **kwargs: calls.append(kwargs))

    result = CliRunner().invoke(
        cli.app,
        [
            "clean",
            "INBOX",
            "--apply",
            "--yes",
            "--limit",
            "2",
            "--rule",
            "invoice",
            "--sort",
            "oldest",
            "--new-run",
            "--progress-db",
            str(tmp_path / "progress.sqlite3"),
            "--config",
            str(tmp_path / "config.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Deprecation warning" in result.output
    assert len(calls) == 1
    options = calls[0]
    assert options["folder"] == "INBOX"
    assert options["all_folders"] is False
    assert options["apply"] is True
    assert options["limit"] == 2
    assert options["rule_scope"] == "invoice"
    assert options["sort"].value == "oldest"
    assert options["new_run"] is True
    assert options["retry_errors"] is False
    assert options["yes"] is True


def test_clean_retry_requires_apply() -> None:
    result = CliRunner().invoke(cli.app, ["clean", "INBOX", "--retry-errors"])

    assert result.exit_code == 2
    assert "--retry-errors requires --apply" in result.output


def test_bare_clean_is_retired_without_connecting(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_resolve_password", lambda _imap: pytest.fail("must not connect"))

    result = CliRunner().invoke(cli.app, ["clean"])

    assert result.exit_code == 2
    assert "{folder}" in result.output
    assert "spam.folders" not in result.output


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
    assert "schema: 1 -> 4" in preview.output
    assert path.read_text(encoding="utf-8") == original

    applied = CliRunner().invoke(
        cli.app,
        ["rule", "migrate", "--apply", "--config", str(config)],
    )
    assert applied.exit_code == 0, applied.output
    assert "Migration applied" in applied.output
    assert "schema = 4" in path.read_text(encoding="utf-8")


def test_rule_preview_and_apply_dispatch_shared_run_options(monkeypatch, tmp_path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli, "_execute_rule_run", lambda **kwargs: calls.append(kwargs))

    preview = CliRunner().invoke(
        cli.app,
        [
            "rule",
            "preview",
            "INBOX",
            "--limit",
            "3",
            "--rule",
            "invoice",
            "--sort",
            "newest",
            "--config",
            str(tmp_path / "config.toml"),
        ],
    )
    apply = CliRunner().invoke(
        cli.app,
        ["rule", "apply", "--all-folders", "--limit", "4", "--retry-errors", "--yes"],
    )

    assert preview.exit_code == 0, preview.output
    assert apply.exit_code == 0, apply.output
    assert calls[0]["folder"] == "INBOX"
    assert calls[0]["apply"] is False
    assert calls[0]["limit"] == 3
    assert calls[0]["rule_scope"] == "invoice"
    assert calls[0]["sort"].value == "newest"
    assert calls[1]["all_folders"] is True
    assert calls[1]["apply"] is True
    assert calls[1]["retry_errors"] is True
    assert calls[1]["yes"] is True


def test_rule_apply_confirmation_decline_does_not_load_settings_or_connect(monkeypatch) -> None:
    monkeypatch.setattr(cli.typer, "confirm", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(cli, "load_settings", lambda _path: pytest.fail("declined apply loaded settings"))
    monkeypatch.setattr(cli, "_resolve_password", lambda _imap: pytest.fail("declined apply connected"))

    result = CliRunner().invoke(cli.app, ["rule", "apply", "INBOX"])

    assert result.exit_code == 0, result.output
    assert "No mailbox changes made." in result.output


def test_rule_add_and_edit_are_global_by_default_and_local_only(tmp_path) -> None:
    config = tmp_path / "config.toml"
    added = CliRunner().invoke(
        cli.app,
        [
            "rule",
            "add",
            "receipt",
            "--type",
            "header",
            "--destination",
            "INBOX.Receipts",
            "--match",
            "from_domain=example.org",
            "--config",
            str(config),
        ],
    )
    edited = CliRunner().invoke(
        cli.app,
        ["rule", "edit", "receipt", "--source-folder", "INBOX", "--config", str(config)],
    )

    assert added.exit_code == 0, added.output
    assert edited.exit_code == 0, edited.output
    rule = load_routing_rules(config.with_name("rules.toml")).rules[0]
    assert rule.source_folders == ("INBOX",)
    assert rule.destination == "INBOX.Receipts"
    assert rule.match_any[0].from_domain == "example.org"


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
    assert "Routing progress" in listed.output

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
