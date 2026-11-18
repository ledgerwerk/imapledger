from __future__ import annotations

import os
from pathlib import Path

import pytest
from ledgercore import AtomicWriteError

import imapledger.config as config_module
from imapledger.config import (
    ConfigError,
    ImapSettings,
    Settings,
    SpamSettings,
    load_settings,
    write_settings,
)
from imapledger.policy import SpamPolicy


def test_config_roundtrip_does_not_store_password(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(
            folder="Spam",
            policy=SpamPolicy(delete_safe_at=0.97),
            trusted_authserv_ids=("mx.example.org",),
            trusted_provider_headers=("X-Spam-Flag",),
        ),
    )
    write_settings(settings, path)

    text = path.read_text(encoding="utf-8")
    assert "password" not in text.lower()
    assert "threshold =" not in text
    assert load_settings(path) == settings


def test_config_write_uses_atomic_writer(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    calls = []

    def fake_atomic_write(target: Path, contents: str) -> None:
        calls.append((target, contents))
        target.write_text(contents, encoding="utf-8")

    monkeypatch.setattr(config_module, "atomic_write_text", fake_atomic_write)
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folder="Spam"),
    )

    assert write_settings(settings, path) == path
    assert calls[0][0] == path
    assert "[imap]" in calls[0][1]
    assert "[spam.policy]" in calls[0][1]
    assert "password" not in calls[0][1].lower()


def test_atomic_write_error_becomes_config_error(monkeypatch, tmp_path: Path) -> None:
    def fail_atomic_write(path: Path, contents: str) -> None:
        raise AtomicWriteError("storage write failed")

    monkeypatch.setattr(config_module, "atomic_write_text", fail_atomic_write)
    path = tmp_path / "config.toml"
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folder="Spam"),
    )

    with pytest.raises(ConfigError, match="could not write config") as raised:
        write_settings(settings, path)

    assert isinstance(raised.value.__cause__, AtomicWriteError)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions are unavailable")
def test_config_mode_is_0600_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    settings = Settings(
        imap=ImapSettings(host="imap.example.org", username="me@example.org"),
        spam=SpamSettings(folder="Spam"),
    )

    write_settings(settings, path)

    assert path.stat().st_mode & 0o777 == 0o600


def test_legacy_scalar_threshold_is_warned_about_and_ignored(tmp_path: Path) -> None:
    path = tmp_path / "legacy.toml"
    path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "me@example.org"\n\n'
        '[spam]\nfolder = "Spam"\nthreshold = 0.99\n',
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match="deprecated and ignored"):
        settings = load_settings(path)

    assert settings.spam.policy == SpamPolicy()
