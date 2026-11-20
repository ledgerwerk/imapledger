from __future__ import annotations

from pathlib import Path

import pytest

import imapledger.credential_service as credential_service
from imapledger.config import AuthSource, ConfigError, ImapAuthSettings, ImapSettings, Settings, SpamSettings
from imapledger.credentials import (
    CredentialAlreadyExistsError,
    CredentialError,
    CredentialRef,
    CredentialTransactionError,
)


class RecordingBackend:
    def __init__(self, source: AuthSource, events: list[str]) -> None:
        self.source = source
        self.events = events
        self.create_error: CredentialError | None = None
        self.replace_error: CredentialError | None = None
        self.delete_error: CredentialError | None = None

    def create(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        self.events.append("create")
        if self.create_error is not None:
            raise self.create_error

    def replace(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        self.events.append("replace")
        if self.replace_error is not None:
            raise self.replace_error

    def delete(self, ref: CredentialRef, *, passphrase: str | None = None) -> bool:
        self.events.append("delete")
        if self.delete_error is not None:
            raise self.delete_error
        return True


def _settings(source: AuthSource) -> Settings:
    return Settings(
        imap=ImapSettings(
            host="imap.example.org",
            username="user@example.org",
            auth=ImapAuthSettings(source),
        ),
        spam=SpamSettings(folders=("Spam",)),
    )


def _record_config_writes(monkeypatch: pytest.MonkeyPatch, events: list[str]) -> None:
    def write_auth_config(path: Path, *, source: AuthSource, vault_path: Path | None = None) -> None:
        events.append(f"config:{source.value}")

    monkeypatch.setattr(credential_service, "write_auth_config", write_auth_config)


def test_configure_stored_credential_creates_then_switches_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    config = _settings(AuthSource.PROMPT)
    backend = RecordingBackend(AuthSource.KEYRING, events)

    credential_service.configure_stored_credential(
        config_path=tmp_path / "config.toml",
        config=config,
        backend=backend,
        ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
        password="UNIQUE_IMAP_PASSWORD_SENTINEL",
    )

    assert events == ["create", "config:keyring"]


def test_configure_stored_credential_create_failure_does_not_write_or_delete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    config = _settings(AuthSource.PROMPT)
    backend = RecordingBackend(AuthSource.KEYRING, events)
    backend.create_error = CredentialAlreadyExistsError("already exists")

    with pytest.raises(CredentialAlreadyExistsError):
        credential_service.configure_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
            password="UNIQUE_IMAP_PASSWORD_SENTINEL",
        )

    assert events == ["create"]


def test_configure_stored_credential_rolls_back_only_after_config_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    monkeypatch.setattr(
        credential_service,
        "write_auth_config",
        lambda path, *, source, vault_path=None: (
            events.append(f"config:{source.value}") or (_ for _ in ()).throw(ConfigError("write failed"))
        ),
    )
    config = _settings(AuthSource.PROMPT)
    backend = RecordingBackend(AuthSource.KEYRING, events)

    with pytest.raises(CredentialTransactionError, match="was rolled back") as error:
        credential_service.configure_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
            password="UNIQUE_IMAP_PASSWORD_SENTINEL",
        )

    assert events == ["create", "config:keyring", "delete"]
    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_configure_stored_credential_reports_failed_rollback_without_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        credential_service,
        "write_auth_config",
        lambda path, *, source, vault_path=None: (_ for _ in ()).throw(ConfigError("write failed")),
    )
    config = _settings(AuthSource.PROMPT)
    backend = RecordingBackend(AuthSource.KEYRING, events)
    backend.delete_error = CredentialError("rollback failed")

    with pytest.raises(CredentialTransactionError, match="may be orphaned") as error:
        credential_service.configure_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
            password="UNIQUE_IMAP_PASSWORD_SENTINEL",
        )

    assert events == ["create", "delete"]
    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_replace_does_not_rewrite_unchanged_source_or_write_when_backend_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    config = _settings(AuthSource.KEYRING)
    backend = RecordingBackend(AuthSource.KEYRING, events)
    ref = CredentialRef(config.imap.host, config.imap.port, config.imap.username)

    credential_service.configure_stored_credential(
        config_path=tmp_path / "config.toml",
        config=config,
        backend=backend,
        ref=ref,
        password="replacement",
        replace=True,
    )
    assert events == ["replace"]

    events.clear()
    backend.replace_error = CredentialError("replace failed")
    with pytest.raises(CredentialError):
        credential_service.configure_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=ref,
            password="replacement",
            replace=True,
        )
    assert events == ["replace"]


def test_remove_stored_credential_switches_config_before_deleting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    config = _settings(AuthSource.VAULT)
    backend = RecordingBackend(AuthSource.VAULT, events)

    assert credential_service.remove_stored_credential(
        config_path=tmp_path / "config.toml",
        config=config,
        backend=backend,
        ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
    )
    assert events == ["config:prompt", "delete"]


def test_remove_stored_credential_does_not_delete_if_config_write_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        credential_service,
        "write_auth_config",
        lambda path, *, source, vault_path=None: (_ for _ in ()).throw(ConfigError("write failed")),
    )
    config = _settings(AuthSource.KEYRING)
    backend = RecordingBackend(AuthSource.KEYRING, events)

    with pytest.raises(CredentialTransactionError, match="credential was retained"):
        credential_service.remove_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
        )
    assert events == []


def test_remove_stored_credential_restores_source_after_delete_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _record_config_writes(monkeypatch, events)
    config = _settings(AuthSource.KEYRING)
    backend = RecordingBackend(AuthSource.KEYRING, events)
    backend.delete_error = CredentialError("delete failed")

    with pytest.raises(CredentialTransactionError, match="auth source was restored"):
        credential_service.remove_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
        )
    assert events == ["config:prompt", "delete", "config:keyring"]


def test_remove_stored_credential_reports_failed_config_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []

    def fail_restoration(path: Path, *, source: AuthSource, vault_path: Path | None = None) -> None:
        events.append(f"config:{source.value}")
        if source is AuthSource.KEYRING:
            raise ConfigError("restore failed")

    monkeypatch.setattr(credential_service, "write_auth_config", fail_restoration)
    config = _settings(AuthSource.KEYRING)
    backend = RecordingBackend(AuthSource.KEYRING, events)
    backend.delete_error = CredentialError("delete failed")

    with pytest.raises(CredentialTransactionError, match="may be inconsistent"):
        credential_service.remove_stored_credential(
            config_path=tmp_path / "config.toml",
            config=config,
            backend=backend,
            ref=CredentialRef(config.imap.host, config.imap.port, config.imap.username),
        )
    assert events == ["config:prompt", "delete", "config:keyring"]
