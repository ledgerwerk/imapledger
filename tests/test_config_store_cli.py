from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from imapledger import cli, config_store_cli
from imapledger.application import doctor as doctor_operations
from imapledger.config import (
    ActionKind,
    ConfigStoreSettings,
    ImapSettings,
    MessageAction,
    Settings,
    SpamSettings,
)
from imapledger.config_mailbox import ConfigStoreMailbox
from imapledger.config_snapshot import create_snapshot, serialize_snapshot
from imapledger.preflight import SourcePreflightResult
from imapledger.rules import MailRule, RuleMatch, RuleSet
from tests.fakes import ConfigStoreFakeClient

STORE_FOLDER = "INBOX.imapledger.Config"


def _write_config(path: Path, *, store_folder: str = STORE_FOLDER, with_store: bool = True) -> None:
    text = '[imap]\nhost = "imap.example.org"\nusername = "user@example.org"\n'
    if with_store:
        text += f'\n[config_store]\nfolder = "{store_folder}"\nmax_file_bytes = 1048576\n'
    path.write_text(text, encoding="utf-8")


def _install_config_store(monkeypatch, fake: ConfigStoreFakeClient) -> list[ImapSettings]:
    resolved = []

    def mailbox_factory(**kwargs):
        return ConfigStoreMailbox(
            **kwargs,
            client_factory=lambda *args, **options: fake,
        )

    monkeypatch.setattr(config_store_cli, "ConfigStoreMailbox", mailbox_factory)
    monkeypatch.setattr(cli, "_resolve_password", lambda imap: resolved.append(imap) or "password")
    return resolved


def _remote_message(content: bytes = b"value = 1\n") -> bytes:
    snapshot = create_snapshot(
        tool="xyz",
        content=content,
        default_path="~/.config/xyz/config.toml",
        filename="config.toml",
    )
    return serialize_snapshot(snapshot, username="user@example.org")


def test_config_commands_list_push_versions_and_cat_without_spam_settings(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)
    local = tmp_path / "tool.toml"
    local.write_text("value = 1\n", encoding="utf-8")
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})
    resolved = _install_config_store(monkeypatch, fake)
    runner = CliRunner()

    pushed = runner.invoke(cli.app, ["config", "push", "XYZ", str(local), "--config", str(config)])
    assert pushed.exit_code == 0, pushed.output
    assert "tool: xyz" in pushed.output
    assert "imap folder: INBOX.imapledger.Config" in pushed.output
    assert "pushed:" in pushed.output
    assert len(fake.appends) == 1
    assert len(resolved) == 1

    fake.fetch_selectors.clear()
    listed = runner.invoke(cli.app, ["config", "list", "--config", str(config)])
    assert listed.exit_code == 0, listed.output
    assert "xyz" in listed.output
    assert "OK" in listed.output
    assert all(selector != ("BODY.PEEK[]",) for selector in fake.fetch_selectors)

    fake.fetch_selectors.clear()
    versions = runner.invoke(cli.app, ["config", "versions", "xyz", "--config", str(config)])
    assert versions.exit_code == 0, versions.output
    assert "Configuration versions: xyz" in versions.output
    assert "*" in versions.output
    assert all(selector != ("BODY.PEEK[]",) for selector in fake.fetch_selectors)

    content = runner.invoke(cli.app, ["config", "cat", "xyz", "--config", str(config)])
    assert content.exit_code == 0, content.output
    assert content.output == "value = 1\n"


def test_config_push_requires_explicit_plaintext_acknowledgement(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)
    local = tmp_path / "secrets.toml"
    local.write_text('password = "do-not-print-this"\n', encoding="utf-8")
    fake = ConfigStoreFakeClient({STORE_FOLDER: {}})
    _install_config_store(monkeypatch, fake)
    runner = CliRunner()

    refused = runner.invoke(cli.app, ["config", "push", "xyz", str(local), "--config", str(config)])
    assert refused.exit_code == 2
    assert "do-not-print-this" not in refused.output
    assert fake.appends == []

    accepted = runner.invoke(
        cli.app,
        [
            "config",
            "push",
            "xyz",
            str(local),
            "--allow-sensitive-plaintext",
            "--config",
            str(config),
        ],
    )
    assert accepted.exit_code == 0, accepted.output
    assert len(fake.appends) == 1


def test_config_pull_confirms_overwrite_and_force_can_show_diff(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)
    target = tmp_path / "existing.toml"
    target.write_text("value = 0\n", encoding="utf-8")
    fake = ConfigStoreFakeClient({STORE_FOLDER: {1: _remote_message()}})
    _install_config_store(monkeypatch, fake)
    runner = CliRunner()

    declined = runner.invoke(
        cli.app,
        ["config", "pull", "xyz", "--to", str(target), "--config", str(config)],
        input="n\n",
    )
    assert declined.exit_code == 0, declined.output
    assert "-value = 0" in declined.output
    assert "No changes made." in declined.output
    assert target.read_text(encoding="utf-8") == "value = 0\n"

    forced = runner.invoke(
        cli.app,
        [
            "config",
            "pull",
            "xyz",
            "--to",
            str(target),
            "--force",
            "--show-diff",
            "--config",
            str(config),
        ],
    )
    assert forced.exit_code == 0, forced.output
    assert "-value = 0" in forced.output
    assert "Wrote" in forced.output
    assert target.read_text(encoding="utf-8") == "value = 1\n"


def test_config_diff_returns_one_for_differences_and_zero_when_identical(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)
    local = tmp_path / "local.toml"
    local.write_text("value = 0\n", encoding="utf-8")
    fake = ConfigStoreFakeClient({STORE_FOLDER: {1: _remote_message()}})
    _install_config_store(monkeypatch, fake)
    runner = CliRunner()
    arguments = [
        "config",
        "diff",
        "xyz",
        "--path",
        str(local),
        "--direction",
        "local-to-imap",
        "--config",
        str(config),
    ]

    different = runner.invoke(cli.app, arguments)
    assert different.exit_code == 1
    assert "-value = 0" in different.output
    assert "+value = 1" in different.output

    local.write_text("value = 1\n", encoding="utf-8")
    identical = runner.invoke(cli.app, arguments)
    assert identical.exit_code == 0
    assert identical.output == ""


def test_config_list_is_graceful_without_store_and_remote_commands_require_it(monkeypatch, tmp_path):
    missing_config = tmp_path / "missing-store.toml"
    _write_config(missing_config, with_store=False)
    fake = ConfigStoreFakeClient({"INBOX": {}})
    resolved = _install_config_store(monkeypatch, fake)

    unconfigured = CliRunner().invoke(
        cli.app,
        ["config", "list", "--config", str(missing_config)],
    )
    assert unconfigured.exit_code == 0
    assert "Config store: disabled" in unconfigured.output
    assert "Add a [config_store] table" in unconfigured.output

    remote = CliRunner().invoke(
        cli.app,
        ["config", "versions", "xyz", "--config", str(missing_config)],
    )
    assert remote.exit_code == 2
    assert "add a [config_store] table" in remote.output
    assert resolved == []

    config = tmp_path / "configured.toml"
    _write_config(config)
    missing = CliRunner().invoke(cli.app, ["config", "list", "--config", str(config)])
    assert missing.exit_code == 2
    assert "does not exist" in missing.output
    assert fake.folder_queries == [STORE_FOLDER]
    assert STORE_FOLDER not in fake.folders
    assert fake.logged_out


@pytest.mark.parametrize("store_exists", [True, False])
def test_doctor_checks_config_store_folder_read_only(monkeypatch, tmp_path, store_exists):
    from imapledger import cli as cli_module

    store_folder = STORE_FOLDER
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
        config_store=ConfigStoreSettings(folder=store_folder),
    )
    source_result = SourcePreflightResult(
        folder="Spam",
        opened=True,
        probe=None,
        capabilities=frozenset(),
        missing_capabilities=(),
        destinations=(),
        errors=(),
    )
    store_folders = {store_folder: {}} if store_exists else {"INBOX": {}}
    store_fake = ConfigStoreFakeClient(store_folders)
    monkeypatch.setattr(cli_module, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli_module, "load_rules", lambda path, *, source_folders: RuleSet())
    monkeypatch.setattr(doctor_operations, "preflight_source", lambda *args, **kwargs: source_result)
    monkeypatch.setattr(cli_module, "_resolve_password", lambda imap: "password")
    monkeypatch.setattr(
        cli_module,
        "ConfigStoreMailbox",
        lambda **kwargs: ConfigStoreMailbox(
            **kwargs,
            client_factory=lambda *args, **options: store_fake,
        ),
    )

    result = CliRunner().invoke(cli_module.app, ["doctor", "--config", str(tmp_path / "unused.toml")])

    expected = "OK" if store_exists else "MISSING"
    assert f"config store folder: {store_folder}: {expected}" in result.output
    assert store_fake.readonly_selections == ([True] if store_exists else [])
    assert (result.exit_code == 0) is store_exists
    assert (store_folder in store_fake.folders) is store_exists


def test_clean_rejects_rule_destination_matching_config_store_before_credentials(monkeypatch):
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(folders=("Spam",)),
        config_store=ConfigStoreSettings(folder=STORE_FOLDER),
    )
    rules = RuleSet(
        rules=(
            MailRule(
                id="route-to-store",
                enabled=True,
                source_folders=("Spam",),
                action=MessageAction(ActionKind.MOVE, STORE_FOLDER),
                match=RuleMatch(subject="test"),
            ),
        )
    )
    monkeypatch.setattr(cli, "load_settings", lambda path: settings)
    monkeypatch.setattr(cli, "load_rules", lambda path, *, source_folders: rules)
    monkeypatch.setattr(cli, "_resolve_password", lambda imap: pytest.fail("reserved-folder check prompted"))

    result = CliRunner().invoke(cli.app, ["clean"])

    assert result.exit_code == 2
    assert "move destination" in result.output


def test_config_cli_reports_history_conflict_and_supports_explicit_version(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)
    base = create_snapshot(
        tool="xyz",
        content=b"value = 0\n",
        default_path="~/.config/xyz/config.toml",
        filename="config.toml",
    )
    left = create_snapshot(
        tool="xyz",
        content=b"value = 1\n",
        default_path="~/.config/xyz/config.toml",
        filename="config.toml",
        parent_version_ids=(base.meta.version_id,),
    )
    right = create_snapshot(
        tool="xyz",
        content=b"value = 2\n",
        default_path="~/.config/xyz/config.toml",
        filename="config.toml",
        parent_version_ids=(base.meta.version_id,),
    )
    messages = {
        1: serialize_snapshot(base, username="user@example.org"),
        2: serialize_snapshot(left, username="user@example.org"),
        3: serialize_snapshot(right, username="user@example.org"),
    }
    fake = ConfigStoreFakeClient({STORE_FOLDER: messages})
    _install_config_store(monkeypatch, fake)
    runner = CliRunner()

    listed = runner.invoke(cli.app, ["config", "list", "--config", str(config)])
    assert listed.exit_code == 0
    assert "CONFLICT" in listed.output
    assert "2 heads" in listed.output

    ambiguous = runner.invoke(cli.app, ["config", "cat", "xyz", "--config", str(config)])
    assert ambiguous.exit_code == 2
    assert "2 current heads" in ambiguous.output

    selected = runner.invoke(
        cli.app,
        ["config", "cat", "xyz", "--version", left.meta.version_id, "--config", str(config)],
    )
    assert selected.exit_code == 0
    assert selected.output == "value = 1\n"


def test_config_cli_uses_existing_credential_error_flow(monkeypatch, tmp_path):
    config = tmp_path / "imapledger.toml"
    _write_config(config)

    def fail_resolver(imap):
        raise cli.CredentialError("credential unavailable")

    monkeypatch.setattr(cli, "resolve_credential", fail_resolver)
    monkeypatch.setattr(
        config_store_cli,
        "ConfigStoreMailbox",
        lambda **kwargs: pytest.fail("credential failure reached IMAP transport"),
    )

    result = CliRunner().invoke(cli.app, ["config", "list", "--config", str(config)])

    assert result.exit_code == 2
    assert "Credential error: credential unavailable" in result.output
