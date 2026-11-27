from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from imapledger import cli
from imapledger.config import ImapSettings, Settings, load_settings, write_settings
from imapledger.routing_actions import RuleAction
from imapledger.routing_config import load_routing_rules, routing_rules_path_for_config
from imapledger.routing_models import RuleType


def _write_config(path: Path) -> None:
    write_settings(Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org")), path)


def test_init_writes_connection_only_config_without_creating_rules(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"

    result = CliRunner().invoke(
        cli.app,
        ["init", "--host", "imap.example.org", "--username", "user@example.org", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert "[imap]" in config.read_text(encoding="utf-8")
    assert "[spam]" not in config.read_text(encoding="utf-8")
    assert not routing_rules_path_for_config(config).exists()
    assert "No mail rules are configured" in result.output


def test_rule_commands_work_without_spam_configuration_and_allow_spam_ids(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write_config(config)
    runner = CliRunner()

    listed = runner.invoke(cli.app, ["rule", "list", "--config", str(config)])
    assert listed.exit_code == 0, listed.output
    assert "No mail rules are configured" in listed.output

    added = runner.invoke(
        cli.app,
        [
            "rule",
            "add",
            "spam",
            "--type",
            "semantic",
            "--action",
            "keep",
            "--description",
            "Mail matching an ordinary semantic rule",
            "--config",
            str(config),
        ],
    )
    assert added.exit_code == 0, added.output
    assert load_routing_rules(routing_rules_path_for_config(config)).rules[0].id == "spam"

    shown = runner.invoke(cli.app, ["rule", "show", "spam", "--config", str(config)])
    assert shown.exit_code == 0, shown.output
    assert "id: spam" in shown.output
    assert "action: keep" in shown.output

    edited = runner.invoke(
        cli.app,
        ["rule", "edit", "spam", "--action", "move", "--destination", "INBOX.Archive", "--config", str(config)],
    )
    assert edited.exit_code == 0, edited.output
    updated = load_routing_rules(routing_rules_path_for_config(config)).rules[0]
    assert updated.id == "spam"
    assert updated.action is RuleAction.MOVE
    assert updated.destination == "INBOX.Archive"

    removed = runner.invoke(cli.app, ["rule", "remove", "spam", "--yes", "--config", str(config)])
    assert removed.exit_code == 0, removed.output
    assert load_routing_rules(routing_rules_path_for_config(config)).rules == ()


def test_recipe_catalog_show_and_add_materialize_ordinary_rule(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write_config(config)
    runner = CliRunner()

    listed = runner.invoke(cli.app, ["rule", "recipe", "list", "--search", "spam"])
    assert listed.exit_code == 0, listed.output
    assert "spam" in listed.output

    shown = runner.invoke(cli.app, ["rule", "recipe", "show", "spam"])
    assert shown.exit_code == 0, shown.output
    assert "Spam / scam" in shown.output

    added = runner.invoke(
        cli.app,
        [
            "rule",
            "recipe",
            "add",
            "spam",
            "--id",
            "junk-filter",
            "--action",
            "keep",
            "--option",
            "phishing_match_at=0.93",
            "--config",
            str(config),
        ],
    )
    assert added.exit_code == 0, added.output
    rule = load_routing_rules(routing_rules_path_for_config(config)).rules[0]
    assert rule.id == "junk-filter"
    assert rule.type is RuleType.RECIPE
    assert rule.recipe == "spam"
    assert rule.action is RuleAction.KEEP
    assert rule.options["phishing_match_at"] == 0.93


def test_legacy_spam_config_error_points_to_explicit_migration(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "user@example.org"\n\n[spam]\nfolders = ["Spam"]\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli.app, ["config", "show", "--config", str(config)])

    assert result.exit_code == 2
    assert "[spam] configuration was removed" in result.output
    assert "imapledger rule migrate --preview" in result.output


def test_removed_category_classifier_returns_rule_guidance() -> None:
    result = CliRunner().invoke(cli.app, ["mail", "classify", "10", "--folder", "INBOX"])

    assert result.exit_code == 2
    assert "was removed" in result.output
    assert "rule evaluate" in result.output


def test_rule_apply_passes_explicit_delete_authorization(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "config.toml"
    _write_config(config)
    monkeypatch.setattr(cli, "_resolve_password", lambda _imap: "secret")
    authorizations: list[bool] = []

    class FakeRuleRunOperation:
        def __init__(self, _settings, _rules):
            pass

        def preflight(self, request):
            authorizations.append(request.allow_delete)

        def run(self, _request, *, password, event_callback=None, on_result=None):
            assert password == "secret"
            return SimpleNamespace(progress=(), messages=())

    monkeypatch.setattr(cli, "RuleRunOperation", FakeRuleRunOperation)
    runner = CliRunner()
    common = [
        "rule",
        "apply",
        "INBOX",
        "--yes",
        "--config",
        str(config),
        "--progress-db",
        str(tmp_path / "progress.db"),
    ]

    without_authorization = runner.invoke(cli.app, common)
    with_authorization = runner.invoke(cli.app, [*common, "--allow-delete"])

    assert without_authorization.exit_code == 0, without_authorization.output
    assert with_authorization.exit_code == 0, with_authorization.output
    assert authorizations == [False, True]


def test_rule_move_reorders_ordinary_rules(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write_config(config)
    runner = CliRunner()
    for rule_id in ("first", "second"):
        added = runner.invoke(
            cli.app,
            [
                "rule",
                "add",
                rule_id,
                "--type",
                "semantic",
                "--action",
                "keep",
                "--description",
                f"Semantic rule {rule_id}",
                "--config",
                str(config),
            ],
        )
        assert added.exit_code == 0, added.output

    moved = runner.invoke(cli.app, ["rule", "move", "second", "up", "--config", str(config)])

    assert moved.exit_code == 0, moved.output
    assert [rule.id for rule in load_routing_rules(routing_rules_path_for_config(config)).rules] == ["second", "first"]


def _write_legacy_spam_config(path: Path, *, spam_action: str, destination: str | None = None) -> None:
    spam_destination = f'destination = "{destination}"\n' if destination is not None else ""
    path.write_text(
        "[imap]\n"
        'host = "imap.example.org"\n'
        'username = "user@example.org"\n'
        "\n[spam]\n"
        'folders = ["Spam"]\n'
        "max_message_bytes = 4096\n"
        "max_body_chars = 8192\n"
        "\n[spam.actions.spam]\n"
        f'action = "{spam_action}"\n'
        f"{spam_destination}"
        "\n[spam.actions.not_spam]\n"
        'action = "keep"\n'
        "\n[spam.actions.review]\n"
        'action = "move"\n'
        'destination = "Review"\n'
        "\n[spam.policy]\n"
        "phishing_delete_at = 0.95\n"
        "\n[spam.authentication]\n"
        'trusted_authserv_ids = ["mx.example.org"]\n'
        "\n[spam.provider]\n"
        'trusted_spam_headers = ["X-Spam-Flag"]\n',
        encoding="utf-8",
    )


def test_rule_migrate_previews_and_applies_legacy_spam_configuration(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write_legacy_spam_config(config, spam_action="move", destination="Trash")
    rules_path = routing_rules_path_for_config(config)
    runner = CliRunner()

    preview = runner.invoke(cli.app, ["rule", "migrate", "--preview", "--config", str(config)])
    assert preview.exit_code == 0, preview.output
    assert "source_folders" in preview.output
    assert "not_spam/review category actions are not migrated automatically" in preview.output
    assert "[spam]" in config.read_text(encoding="utf-8")
    assert not rules_path.exists()

    applied = runner.invoke(cli.app, ["rule", "migrate", "--apply", "--config", str(config)])
    assert applied.exit_code == 0, applied.output
    assert "[spam]" not in config.read_text(encoding="utf-8")
    assert load_settings(config).mail.max_message_bytes == 4096
    rules = load_routing_rules(rules_path)
    rule = rules.rules[0]
    assert rule.id == "spam"
    assert rule.type is RuleType.RECIPE
    assert rule.recipe == "spam"
    assert rule.action is RuleAction.MOVE
    assert rule.destination == "Trash"
    assert rule.source_folders == ("Spam",)
    assert rule.options["phishing_match_at"] == 0.95
    assert rules.evidence.trusted_authserv_ids == ("mx.example.org",)
    assert rules.evidence.trusted_provider_headers == ("X-Spam-Flag",)
    assert not any(item.id in {"not_spam", "review"} for item in rules.rules)


def test_rule_migrate_requires_delete_authorization_for_legacy_delete(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write_legacy_spam_config(config, spam_action="delete")
    original = config.read_text(encoding="utf-8")
    rules_path = routing_rules_path_for_config(config)
    runner = CliRunner()

    denied = runner.invoke(cli.app, ["rule", "migrate", "--apply", "--config", str(config)])

    assert denied.exit_code == 2
    assert "--allow-delete" in denied.output
    assert config.read_text(encoding="utf-8") == original
    assert not rules_path.exists()

    authorized = runner.invoke(
        cli.app,
        ["rule", "migrate", "--apply", "--allow-delete", "--config", str(config)],
    )
    assert authorized.exit_code == 0, authorized.output
    assert load_routing_rules(rules_path).rules[0].action is RuleAction.DELETE
