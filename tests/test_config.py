from __future__ import annotations

import os
from pathlib import Path

import pytest
from ledgercore import AtomicWriteError

import imapledger.config as config_module
from imapledger.config import (
    ActionKind,
    ConfigError,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    load_settings,
    render_settings,
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
    assert '[spam.actions.spam]' in text
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
        ('[1]', "entries must be strings"),
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
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[spam]\nfolder = "Spam"\nthreshold = 0.99\n',
        encoding="utf-8",
    )

    with pytest.warns(UserWarning) as caught:
        settings = load_settings(path)

    assert any("threshold is deprecated and ignored" in str(warning.message) for warning in caught)
    assert any("spam.folder is deprecated" in str(warning.message) for warning in caught)
    assert settings.spam.policy == SpamPolicy()
