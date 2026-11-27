from __future__ import annotations

import os
from pathlib import Path

import pytest
from ledgercore import AtomicWriteError
from vaultconfig.secrets import DEFAULT_MIN_PASSPHRASE_LENGTH

import imapledger.config as config_module
from imapledger.config import (
    ActionKind,
    AuthSource,
    ConfigError,
    ConfigStoreContext,
    ConfigStoreSettings,
    ImapAuthSettings,
    ImapSettings,
    MailSettings,
    MessageAction,
    Settings,
    load_config_store_context,
    load_imap_settings,
    load_legacy_spam_configuration,
    load_settings,
    render_settings,
    write_auth_config,
    write_settings,
)


def _settings(*, mail: MailSettings | None = None) -> Settings:
    return Settings(imap=ImapSettings(host="imap.example.org", username="me@example.org"), mail=mail or MailSettings())


def test_minimal_connection_configuration_loads_without_spam(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """[imap]
host = "nahrstaedt.de"
port = 993
username = "holger@nahrstaedt.de"

[imap.auth]
source = "vault"
vault_path = "~/.local/share/imapledger/credentials.enc"
vault_min_passphrase_length = 10
""",
        encoding="utf-8",
    )

    settings = load_settings(path)

    assert settings.imap == ImapSettings(
        host="nahrstaedt.de",
        username="holger@nahrstaedt.de",
        auth=ImapAuthSettings(AuthSource.VAULT, Path("~/.local/share/imapledger/credentials.enc"), 10),
    )
    assert settings.mail == MailSettings()
    assert "spam" not in settings.__dataclass_fields__


def test_render_settings_omits_spam_and_default_mail_table(tmp_path: Path) -> None:
    rendered = render_settings(_settings())
    path = tmp_path / "rendered.toml"
    path.write_text(rendered, encoding="utf-8")

    assert "[spam]" not in rendered
    assert "[mail]" not in rendered
    assert "password" not in rendered.lower()
    assert load_settings(path) == _settings()


def test_optional_mail_settings_round_trip(tmp_path: Path) -> None:
    settings = _settings(mail=MailSettings(max_message_bytes=1234, max_body_chars=5678))
    rendered = render_settings(settings)
    path = tmp_path / "config.toml"
    path.write_text(rendered, encoding="utf-8")

    assert "[mail]" in rendered
    assert "max_message_bytes = 1234" in rendered
    assert load_settings(path) == settings


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('[mail]\nmax_message_bytes = 0\n', "mail.max_message_bytes must be a positive integer"),
        ('[mail]\nmax_body_chars = true\n', "mail.max_body_chars must be a positive integer"),
        ('[mail]\nunknown = 1\n', r"unknown key in \[mail\]"),
    ],
)
def test_mail_settings_validation(tmp_path: Path, body: str, message: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n' + body, encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_settings(path)


def test_legacy_spam_table_is_rejected_by_normal_loaders(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[spam]\nfolders = ["Spam"]\n',
        encoding="utf-8",
    )

    for loader in (load_settings, load_imap_settings):
        with pytest.raises(ConfigError, match=r"\[spam\] configuration was removed") as raised:
            loader(path)
        assert "imapledger rule migrate --preview" in str(raised.value)
        assert "imapledger rule migrate --apply" in str(raised.value)


def test_explicit_legacy_config_reader_extracts_migration_inputs(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """[imap]
host = "imap.example.org"
username = "me@example.org"

[spam]
folders = ["INBOX.Junk", "INBOX.Spam"]
max_message_bytes = 1000000
max_body_chars = 10000

[spam.actions.spam]
action = "move"
destination = "INBOX.Trash"

[spam.actions.not_spam]
action = "move"
destination = "INBOX.NotSpam"

[spam.policy]
phishing_delete_at = 0.91
delete_safe_at = 0.87

[spam.authentication]
trusted_authserv_ids = ["mx.example.org"]

[spam.provider]
trusted_spam_headers = ["X-Spam-Flag"]
""",
        encoding="utf-8",
    )

    legacy = load_legacy_spam_configuration(path)

    assert legacy is not None
    assert legacy.folders == ("INBOX.Junk", "INBOX.Spam")
    assert legacy.actions["spam"] == MessageAction(ActionKind.MOVE, "INBOX.Trash")
    assert legacy.actions["not_spam"] == MessageAction(ActionKind.MOVE, "INBOX.NotSpam")
    assert legacy.policy == {"phishing_delete_at": 0.91, "delete_safe_at": 0.87}
    assert legacy.max_message_bytes == 1_000_000
    assert legacy.max_body_chars == 10_000
    assert legacy.trusted_authserv_ids == ("mx.example.org",)
    assert legacy.trusted_provider_headers == ("X-Spam-Flag",)


def test_explicit_legacy_reader_returns_none_without_spam(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n', encoding="utf-8")

    assert load_legacy_spam_configuration(path) is None


def test_config_writer_uses_atomic_writer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = []

    def fake_atomic_write(target: Path, contents: str) -> None:
        calls.append((target, contents))
        target.write_text(contents, encoding="utf-8")

    monkeypatch.setattr(config_module, "atomic_write_text", fake_atomic_write)

    path = tmp_path / "config.toml"
    assert write_settings(_settings(), path) == path
    assert calls[0][0] == path
    assert "[imap]" in calls[0][1]
    assert "[spam]" not in calls[0][1]


def test_atomic_write_error_becomes_config_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail_atomic_write(path: Path, contents: str) -> None:
        raise AtomicWriteError("storage write failed")

    monkeypatch.setattr(config_module, "atomic_write_text", fail_atomic_write)
    with pytest.raises(ConfigError, match="could not write config") as raised:
        write_settings(_settings(), tmp_path / "config.toml")
    assert isinstance(raised.value.__cause__, AtomicWriteError)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions are unavailable")
def test_config_mode_is_0600_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    write_settings(_settings(), path)
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("source", [AuthSource.PROMPT, AuthSource.KEYRING, AuthSource.VAULT])
def test_imap_auth_source_round_trips_without_credentials(tmp_path: Path, source: AuthSource) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        f'[imap.auth]\nsource = "{source.value}"\n',
        encoding="utf-8",
    )
    imap = load_imap_settings(path)
    assert imap.auth.source is source
    assert imap.auth.vault_min_passphrase_length == DEFAULT_MIN_PASSPHRASE_LENGTH

    settings = Settings(imap=imap)
    rendered = render_settings(settings)
    assert f'source = "{source.value}"' in rendered
    assert "password" not in rendered.lower()
    path.write_text(rendered, encoding="utf-8")
    assert load_settings(path) == settings


def test_load_imap_settings_validates_connection_and_auth(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[imap.auth]\nsource = "vault"\nvault_min_passphrase_length = 10\n',
        encoding="utf-8",
    )
    imap = load_imap_settings(path)
    assert imap.auth.vault_min_passphrase_length == 10

    path.write_text('[imap]\nhost = ""\nusername = "me@example.org"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="host must not be empty"):
        load_imap_settings(path)


def test_write_auth_config_preserves_unrelated_toml_and_vault_path(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """# keep this comment
[imap]
host = "imap.example.org"
username = "me@example.org"

[imap.auth]
# keep auth comments
source = "prompt"

[mail]
max_body_chars = 1000
""",
        encoding="utf-8",
    )

    write_auth_config(path, source=AuthSource.VAULT, vault_path=Path("~/vaults/account.enc"))
    updated = path.read_text(encoding="utf-8")
    assert "# keep this comment" in updated
    assert "# keep auth comments" in updated
    assert "max_body_chars = 1000" in updated
    assert load_settings(path).imap.auth.vault_path == Path("~/vaults/account.enc")

    write_auth_config(path, source=AuthSource.KEYRING)
    assert load_settings(path).imap.auth.source is AuthSource.KEYRING
    assert load_settings(path).imap.auth.vault_path == Path("~/vaults/account.enc")


def test_config_store_context_and_full_settings_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        mail=MailSettings(max_body_chars=12000),
        config_store=ConfigStoreSettings("INBOX.imapledger.Config", 2_000_000),
    )
    rendered = render_settings(settings)
    path.write_text(rendered, encoding="utf-8")

    assert load_settings(path) == settings
    assert load_config_store_context(path) == ConfigStoreContext(
        imap=settings.imap,
        store=settings.config_store,
    )
    assert "[config_store]\nfolder = \"INBOX.imapledger.Config\"\nmax_file_bytes = 2000000" in rendered


def test_config_store_settings_validate_folder_and_size() -> None:
    for folder, size in (("", 1), ("   ", 1), (" INBOX.Config", 1), ("INBOX.Config", 0), ("INBOX.Config", True)):
        with pytest.raises(ConfigError):
            ConfigStoreSettings(folder, size)
    with pytest.raises(ConfigError, match="10 MiB"):
        ConfigStoreSettings("INBOX.Config", 10 * 1024 * 1024 + 1)
