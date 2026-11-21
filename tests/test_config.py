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
    ClassificationStateBackend,
    ClassificationStateSettings,
    ConfigError,
    ConfigStoreContext,
    ConfigStoreSettings,
    ImapAuthSettings,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    load_config_store_context,
    load_imap_settings,
    load_settings,
    render_settings,
    write_auth_config,
    write_settings,
)
from imapledger.policy import SpamPolicy


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(
            folders=("INBOX.Junk", "INBOX.Spam"),
            actions=SpamActions(
                spam=MessageAction(ActionKind.MOVE, "INBOX.Trash"),
                not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
                review=MessageAction(ActionKind.KEEP),
            ),
            policy=SpamPolicy(delete_safe_at=0.97),
            trusted_authserv_ids=("mx.example.org",),
            trusted_provider_headers=("X-Spam-Flag",),
        ),
    )


def _load_spam(tmp_path: Path, spam_contents: str):
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[spam]\n' + spam_contents,
        encoding="utf-8",
    )
    return load_settings(path)


def test_config_roundtrip_preserves_multi_folder_actions_without_password(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    settings = _settings()

    write_settings(settings, path)

    text = path.read_text(encoding="utf-8")
    assert "password" not in text.lower()
    assert "threshold =" not in text
    assert 'folders = ["INBOX.Junk", "INBOX.Spam"]' in text
    assert "[spam.actions.spam]" in text
    assert 'action = "move"' in text
    assert load_settings(path) == settings


def test_config_writer_uses_atomic_writer_and_new_schema(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    calls = []

    def fake_atomic_write(target: Path, contents: str) -> None:
        calls.append((target, contents))
        target.write_text(contents, encoding="utf-8")

    monkeypatch.setattr(config_module, "atomic_write_text", fake_atomic_write)

    assert write_settings(_settings(), path) == path
    assert calls[0][0] == path
    assert "[imap]" in calls[0][1]
    assert "[spam.policy]" in calls[0][1]
    assert "[spam.actions.spam]" in calls[0][1]
    assert "folder =" not in calls[0][1]
    assert "password" not in calls[0][1].lower()


def test_render_settings_includes_defaults_and_roundtrips_without_credentials(tmp_path: Path) -> None:
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folders=("Spam",)),
    )

    rendered = render_settings(settings)
    path = tmp_path / "rendered.toml"
    assert f"vault_min_passphrase_length = {DEFAULT_MIN_PASSPHRASE_LENGTH}" in rendered
    path.write_text(rendered, encoding="utf-8")

    assert '[spam.actions.spam]\naction = "delete"' in rendered
    assert '[spam.actions.not_spam]\naction = "keep"' in rendered
    assert '[spam.actions.review]\naction = "keep"' in rendered
    assert "password" not in rendered.lower()
    assert load_settings(path) == settings


def test_atomic_write_error_becomes_config_error(monkeypatch, tmp_path: Path) -> None:
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


def test_legacy_scalar_folder_warns_and_preserves_delete_defaults(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="spam.folder is deprecated"):
        settings = _load_spam(tmp_path, 'folder = "Spam"\n')

    assert settings.spam.folders == ("Spam",)
    assert settings.spam.actions.spam.action is ActionKind.DELETE
    assert settings.spam.actions.not_spam.action is ActionKind.KEEP
    assert settings.spam.actions.review.action is ActionKind.KEEP


def test_new_folder_schema_without_actions_defaults_to_keep(tmp_path: Path) -> None:
    settings = _load_spam(tmp_path, 'folders = ["Spam"]\n')

    assert settings.spam.actions.spam.action is ActionKind.KEEP
    assert settings.spam.actions.not_spam.action is ActionKind.KEEP
    assert settings.spam.actions.review.action is ActionKind.KEEP


def test_folder_and_folders_cannot_both_be_configured(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot both"):
        _load_spam(tmp_path, 'folder = "Spam"\nfolders = ["Spam"]\n')


@pytest.mark.parametrize(
    ("folders", "message"),
    [
        ("[]", "must not be empty"),
        ('["", "INBOX.Spam"]', "must not be empty"),
        ('["   "]', "must not be empty"),
        ('["Spam", "Spam"]', "duplicates"),
        ('[" Spam"]', "whitespace"),
        ("[1]", "entries must be strings"),
    ],
)
def test_invalid_folder_lists_are_rejected(tmp_path: Path, folders: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _load_spam(tmp_path, f"folders = {folders}\n")


@pytest.mark.parametrize(
    ("action_table", "message"),
    [
        ('[spam.actions.spam]\naction = "archive"\n', "unknown action"),
        ('[spam.actions.spam]\naction = "move"\n', "requires a destination"),
        ('[spam.actions.spam]\naction = "keep"\ndestination = "Trash"\n', "must not have a destination"),
        ('[spam.actions.spam]\naction = "delete"\ndestination = "Trash"\n', "must not have a destination"),
        ('[spam.actions.not_spam]\naction = "delete"\n', "not supported for the not_spam"),
        ('[spam.actions.review]\naction = "delete"\n', "not supported for the review"),
        (
            '[spam.actions.spam]\naction = "move"\ndestination = "Spam"\n',
            "destination must not be a source folder",
        ),
        (
            '[spam.actions.spam]\naction = "move"\ndestination = " Trash"\n',
            "leading or trailing whitespace",
        ),
    ],
)
def test_invalid_actions_are_rejected(tmp_path: Path, action_table: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _load_spam(tmp_path, f'folders = ["Spam"]\n\n{action_table}')


def test_legacy_scalar_threshold_is_warned_about_and_ignored(tmp_path: Path) -> None:
    path = tmp_path / "legacy.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[spam]\nfolder = "Spam"\nthreshold = 0.99\n',
        encoding="utf-8",
    )

    with pytest.warns(UserWarning) as caught:
        settings = load_settings(path)

    assert any("threshold is deprecated and ignored" in str(warning.message) for warning in caught)
    assert any("spam.folder is deprecated" in str(warning.message) for warning in caught)
    assert settings.spam.policy == SpamPolicy()


def test_load_imap_settings_accepts_imap_only_config(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\nport = 1993\n',
        encoding="utf-8",
    )

    assert load_imap_settings(path) == ImapSettings(host="imap.example.org", username="me@example.org", port=1993)
    assert load_imap_settings(path).auth.source is AuthSource.PROMPT


def test_load_imap_settings_ignores_invalid_spam_section(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[spam]\nfolders = 42\n',
        encoding="utf-8",
    )

    assert load_imap_settings(path) == ImapSettings(host="imap.example.org", username="me@example.org")


def test_load_imap_settings_requires_imap_table(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[spam]\nfolders = ["Spam"]\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="requires an \\[imap\\] table"):
        load_imap_settings(path)


@pytest.mark.parametrize(
    ("imap_table", "message"),
    [
        ('host = ""\nusername = "me@example.org"', "host must not be empty"),
        ('host = "imap.example.org"\nusername = ""', "username must not be empty"),
        ('host = "imap.example.org"\nusername = "me@example.org"\nport = 0', "port must be between"),
    ],
)
def test_load_imap_settings_validates_imap_values(tmp_path: Path, imap_table: str, message: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f"[imap]\n{imap_table}\n", encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_imap_settings(path)


def test_load_settings_still_requires_spam_table(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="requires a \\[spam\\] table"):
        load_settings(path)


@pytest.mark.parametrize(
    "source",
    [AuthSource.PROMPT, AuthSource.KEYRING, AuthSource.VAULT],
)
def test_imap_auth_source_roundtrips_without_credentials(
    tmp_path: Path,
    source: AuthSource,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[imap.auth]\nsource = "{source.value}"\n',
        encoding="utf-8",
    )
    imap = load_imap_settings(path)
    assert imap.auth.source is source

    settings = Settings(
        imap=ImapSettings(
            host=imap.host,
            username=imap.username,
            port=imap.port,
            auth=ImapAuthSettings(source),
        ),
        spam=SpamSettings(folders=("Spam",)),
    )
    rendered = render_settings(settings)
    assert f'source = "{source.value}"' in rendered
    assert "password" not in rendered.lower()
    path.write_text(rendered, encoding="utf-8")
    assert load_settings(path) == settings


@pytest.mark.parametrize(
    ("auth_line", "message"),
    [
        ('source = "invalid"', "source must be one of"),
        ("source = 42", "source must be one of"),
        ('other = "keyring"', "unknown key in imap.auth"),
    ],
)
def test_invalid_imap_auth_configuration_is_rejected(
    tmp_path: Path,
    auth_line: str,
    message: str,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[imap.auth]\n{auth_line}\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=message):
        load_imap_settings(path)


def test_imap_auth_configuration_requires_a_table(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\nauth = "keyring"\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="imap.auth must be a table"):
        load_imap_settings(path)


def test_optional_auth_vault_path_round_trips_without_expanding(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """[imap]
host = "imap.example.org"
username = "me@example.org"

[imap.auth]
source = "vault"
vault_path = "~/credentials/custom.enc"

[spam]
folders = ["Spam"]
""",
        encoding="utf-8",
    )

    settings = load_settings(path)

    assert settings.imap.auth.vault_path == Path("~/credentials/custom.enc")
    rendered = render_settings(settings)
    assert 'vault_path = "~/credentials/custom.enc"' in rendered
    roundtrip = tmp_path / "roundtrip.toml"
    roundtrip.write_text(rendered, encoding="utf-8")
    assert load_settings(roundtrip) == settings


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

[spam]
folders = ["Spam"]
unrelated = "keep-me"
""",
        encoding="utf-8",
    )

    write_auth_config(path, source=AuthSource.VAULT, vault_path=Path("~/vaults/account.enc"))
    updated = path.read_text(encoding="utf-8")

    assert "# keep this comment" in updated
    assert "# keep auth comments" in updated
    assert 'unrelated = "keep-me"' in updated
    assert load_settings(path).imap.auth.source is AuthSource.VAULT
    assert load_settings(path).imap.auth.vault_path == Path("~/vaults/account.enc")

    write_auth_config(path, source=AuthSource.KEYRING)
    settings = load_settings(path)
    assert settings.imap.auth.source is AuthSource.KEYRING
    assert settings.imap.auth.vault_path == Path("~/vaults/account.enc")


def test_distinct_configs_preserve_distinct_vault_paths(tmp_path: Path) -> None:
    config_a = tmp_path / "a.toml"
    config_b = tmp_path / "b.toml"
    vault_a = Path("~/imapledger/a.enc")
    vault_b = Path("~/imapledger/b.enc")

    write_settings(_settings(), config_a)
    write_settings(_settings(), config_b)
    write_auth_config(config_a, source=AuthSource.VAULT, vault_path=vault_a)
    write_auth_config(config_b, source=AuthSource.VAULT, vault_path=vault_b)

    assert load_settings(config_a).imap.auth.vault_path == vault_a
    assert load_settings(config_b).imap.auth.vault_path == vault_b


def test_vault_min_passphrase_length_defaults_and_custom_value_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n[imap.auth]\nsource = "vault"\n',
        encoding="utf-8",
    )
    assert load_imap_settings(path).auth.vault_min_passphrase_length == DEFAULT_MIN_PASSPHRASE_LENGTH

    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[imap.auth]\nsource = "vault"\nvault_min_passphrase_length = 10\n',
        encoding="utf-8",
    )
    imap = load_imap_settings(path)
    assert imap.auth.vault_min_passphrase_length == 10

    rendered = render_settings(Settings(imap=imap, spam=SpamSettings(folders=("Spam",))))
    assert "vault_min_passphrase_length = 10" in rendered
    round_trip = tmp_path / "round-trip.toml"
    round_trip.write_text(rendered, encoding="utf-8")
    assert load_settings(round_trip).imap.auth.vault_min_passphrase_length == 10


@pytest.mark.parametrize("raw_value", ["0", "-1", '"10"', "true", "10.0"])
def test_invalid_vault_min_passphrase_length_is_rejected(tmp_path: Path, raw_value: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        f"[imap.auth]\nvault_min_passphrase_length = {raw_value}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match=r"imap\.auth\.vault_min_passphrase_length must be a positive integer",
    ):
        load_imap_settings(path)


def test_write_auth_config_preserves_custom_vault_minimum_across_source_updates(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[imap.auth]\nsource = "prompt"\nvault_min_passphrase_length = 10\n',
        encoding="utf-8",
    )

    write_auth_config(path, source=AuthSource.VAULT, vault_path=Path("~/credentials.enc"))
    assert load_imap_settings(path).auth.vault_min_passphrase_length == 10
    write_auth_config(path, source=AuthSource.KEYRING)
    assert load_imap_settings(path).auth.vault_min_passphrase_length == 10
    write_auth_config(path, source=AuthSource.PROMPT)
    settings = load_imap_settings(path)
    assert settings.auth.source is AuthSource.PROMPT
    assert settings.auth.vault_min_passphrase_length == 10


@pytest.mark.parametrize("backend", ["none", "imap-keywords"])
def test_classification_state_backend_round_trips(tmp_path: Path, backend: str) -> None:
    settings = _load_spam(tmp_path, f'folders = ["Spam"]\n\n[spam.state]\nbackend = "{backend}"\n')

    assert settings.spam.state == ClassificationStateSettings(ClassificationStateBackend(backend))
    rendered = render_settings(settings)
    assert f'[spam.state]\nbackend = "{backend}"' in rendered
    path = tmp_path / "roundtrip.toml"
    path.write_text(rendered, encoding="utf-8")
    assert load_settings(path) == settings


def test_legacy_config_defaults_state_backend_to_none(tmp_path: Path) -> None:
    settings = _load_spam(tmp_path, 'folders = ["Spam"]\n')

    assert settings.spam.state.backend is ClassificationStateBackend.NONE
    assert '[spam.state]\nbackend = "none"' in render_settings(settings)


@pytest.mark.parametrize(
    ("state_table", "message"),
    [
        ('[spam.state]\nbackend = "headers"\n', "spam.state.backend must be one of"),
        ('[spam.state]\nmarker = "custom"\n', "unknown key in spam.state"),
        ('state = "imap-keywords"\n', "spam.state must be a table"),
    ],
)
def test_invalid_classification_state_config_is_rejected(
    tmp_path: Path,
    state_table: str,
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        _load_spam(tmp_path, f'folders = ["Spam"]\n\n{state_table}')


def test_config_store_context_loads_without_spam_section(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[config_store]\nfolder = "INBOX.imapledger.Config"\n',
        encoding="utf-8",
    )

    context = load_config_store_context(path)

    assert context == ConfigStoreContext(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        store=ConfigStoreSettings(folder="INBOX.imapledger.Config"),
    )
    assert context.store.max_file_bytes == 1_048_576


def test_config_store_settings_roundtrip_with_full_settings(tmp_path: Path) -> None:
    original = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folders=("INBOX.Junk",)),
        config_store=ConfigStoreSettings("INBOX.imapledger.Config", 2_000_000),
    )
    rendered = render_settings(original)
    path = tmp_path / "config.toml"
    path.write_text(rendered, encoding="utf-8")

    assert '[config_store]\nfolder = "INBOX.imapledger.Config"\nmax_file_bytes = 2000000' in rendered
    assert load_settings(path) == original


@pytest.mark.parametrize(
    ("folder", "max_file_bytes", "message"),
    [
        ("", 1, "non-empty"),
        ("   ", 1, "must not be empty"),
        (" INBOX.Config", 1, "whitespace"),
        ("INBOX.Config", 0, "positive integer"),
        ("INBOX.Config", True, "positive integer"),
        ("INBOX.Config", 10 * 1024 * 1024 + 1, "10 MiB"),
    ],
)
def test_config_store_settings_validate_folder_and_size(
    folder: str,
    max_file_bytes: int,
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        ConfigStoreSettings(folder, max_file_bytes)


def test_config_store_folder_cannot_be_spam_source_or_move_destination() -> None:
    store = ConfigStoreSettings("INBOX.imapledger.Config")
    with pytest.raises(ConfigError, match="spam source folder"):
        Settings(
            imap=ImapSettings(host="imap.example.org", username="me@example.org"),
            spam=SpamSettings(folders=(store.folder,)),
            config_store=store,
        )

    spam = SpamSettings(
        folders=("INBOX.Junk",),
        actions=SpamActions(spam=MessageAction(ActionKind.MOVE, store.folder)),
    )
    with pytest.raises(ConfigError, match="spam.actions.spam destination"):
        Settings(
            imap=ImapSettings(host="imap.example.org", username="me@example.org"),
            spam=spam,
            config_store=store,
        )


def test_load_settings_rejects_invalid_config_store_values(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[spam]\nfolders = ["INBOX.Junk"]\n\n'
        '[config_store]\nfolder = "INBOX.Config"\nmax_file_bytes = true\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="positive integer"):
        load_settings(path)
