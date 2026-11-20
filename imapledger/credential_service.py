from __future__ import annotations

from pathlib import Path

from .config import AuthSource, ConfigError, Settings, write_auth_config
from .credentials import CredentialBackend, CredentialError, CredentialRef, CredentialTransactionError


def _write_source(
    config_path: Path,
    backend: CredentialBackend,
) -> None:
    write_auth_config(config_path, source=backend.source)


def configure_stored_credential(
    *,
    config_path: Path,
    config: Settings,
    backend: CredentialBackend,
    ref: CredentialRef,
    password: str,
    passphrase: str | None = None,
    replace: bool = False,
) -> None:
    if not password:
        raise CredentialError("IMAP password must not be empty")

    old_source = config.imap.auth.source
    if replace:
        backend.replace(ref, password, passphrase=passphrase)
        if old_source is not backend.source:
            try:
                _write_source(config_path, backend)
            except ConfigError:
                raise CredentialTransactionError(
                    "Credential was replaced, but the config source could not be updated."
                ) from None
        return

    try:
        backend.create(ref, password, passphrase=passphrase)
    except CredentialError:
        raise

    try:
        _write_source(config_path, backend)
    except ConfigError:
        try:
            backend.delete(ref, passphrase=passphrase)
        except CredentialError:
            raise CredentialTransactionError(
                "Config update failed and the newly stored credential could not be rolled back. "
                "The credential may be orphaned in secure storage."
            ) from None
        raise CredentialTransactionError("Config update failed; the newly stored credential was rolled back.") from None


def remove_stored_credential(
    *,
    config_path: Path,
    config: Settings,
    backend: CredentialBackend,
    ref: CredentialRef,
    passphrase: str | None = None,
) -> bool:
    old_source = config.imap.auth.source
    if old_source is AuthSource.PROMPT:
        return False

    try:
        write_auth_config(config_path, source=AuthSource.PROMPT)
    except ConfigError:
        raise CredentialTransactionError(
            "Could not switch auth source to prompt; the stored credential was retained."
        ) from None

    try:
        return backend.delete(ref, passphrase=passphrase)
    except CredentialError:
        try:
            write_auth_config(config_path, source=old_source)
        except ConfigError:
            raise CredentialTransactionError(
                "Credential deletion failed and config rollback also failed. "
                "Configuration and secure storage may be inconsistent."
            ) from None
        raise CredentialTransactionError("Credential deletion failed; the auth source was restored.") from None
