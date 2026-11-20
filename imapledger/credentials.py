from __future__ import annotations

import getpass
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from vaultconfig.secrets import (
    DEFAULT_MIN_PASSPHRASE_LENGTH,
    FileVault,
    KeyringVault,
    SecretBackendInfo,
    SecretExistsError,
    SecretNotFoundError,
    SecretStoreUnavailableError,
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultPassphrasePolicyError,
    VaultPermissionError,
    VaultUnlockError,
)

from .config import AuthSource, ImapSettings


class CredentialError(RuntimeError):
    """Raised when the configured IMAP credential source cannot provide a password."""


class CredentialNotFoundError(CredentialError):
    pass


class CredentialAlreadyExistsError(CredentialError):
    pass


class CredentialBackendUnavailableError(CredentialError):
    pass


class CredentialTransactionError(CredentialError):
    pass


@dataclass(frozen=True, slots=True)
class CredentialRef:
    host: str
    port: int
    username: str

    @property
    def normalized_host(self) -> str:
        return self.host.lower().rstrip(".")


CredentialContext = CredentialRef


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    password: str = field(repr=False)
    source: AuthSource
    username: str = ""

    def __repr__(self) -> str:
        return f"ResolvedCredential(username={self.username!r}, source={self.source.value!r}, password=<redacted>)"


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    source: AuthSource
    available: bool | None
    backend_name: str | None = None
    backend_available: bool | None = None
    reason: str | None = None
    vault_path: Path | None = None
    vault_format: str | None = None
    kdf_name: str | None = None
    memlimit_bytes: int | None = None
    opslimit: int | None = None
    entry_count: int | None = None


class CredentialBackend(Protocol):
    source: AuthSource

    def get(self, ref: CredentialRef, *, passphrase: str | None = None) -> str | None: ...

    def create(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None: ...

    def replace(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None: ...

    def delete(self, ref: CredentialRef, *, passphrase: str | None = None) -> bool: ...

    def status(self, ref: CredentialRef, *, passphrase: str | None = None) -> CredentialStatus: ...

    def resolve_for_login(
        self,
        ref: CredentialRef,
        *,
        prompt_secret: Callable[[str], str],
    ) -> str | None: ...


def default_credential_vault_path() -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return (data_home / "imapledger" / "credentials.enc").expanduser().absolute()


def credential_vault_path(path: Path | None = None) -> Path:
    return (path or default_credential_vault_path()).expanduser().absolute()


def keyring_service(ref: CredentialRef) -> str:
    return f"imapledger:{ref.normalized_host}:{ref.port}"


def keyring_account(ref: CredentialRef) -> str:
    return ref.username


def vault_secret_name(ref: CredentialRef) -> str:
    identity = json.dumps(
        [ref.normalized_host, ref.port, ref.username],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return f"imapledger:{identity}"


def _translate_vault_error(error: VaultError, *, source: AuthSource, operation: str) -> CredentialError:
    if isinstance(error, VaultPassphrasePolicyError):
        minimum = error.minimum_length
        if minimum is not None:
            return CredentialError(
                f"Master passphrase must be at least {minimum} characters for encrypted-file storage. "
                "Configure [imap.auth].vault_min_passphrase_length to use a different minimum."
            )
        return CredentialError("Master passphrase does not satisfy the encrypted-vault passphrase policy.")
    if isinstance(error, SecretExistsError):
        if source is AuthSource.VAULT:
            return CredentialAlreadyExistsError("an IMAP credential already exists in the encrypted vault")
        return CredentialAlreadyExistsError("an IMAP credential already exists in the OS keyring")
    if isinstance(error, SecretNotFoundError):
        return CredentialNotFoundError("IMAP credential was not found in secure storage")
    if isinstance(error, VaultUnlockError):
        return CredentialError("could not unlock the encrypted credential vault")
    if isinstance(error, VaultPermissionError):
        return CredentialBackendUnavailableError("credential vault is unavailable or unsafe")
    if isinstance(error, VaultConflictError):
        return CredentialTransactionError("credential vault changed during the operation")
    if isinstance(error, SecretStoreUnavailableError):
        return CredentialBackendUnavailableError(
            "OS keyring backend is unavailable. Install `imapledger[keyring]` or use "
            "`imapledger auth set --storage vault`."
        )
    if isinstance(error, VaultFormatError):
        return CredentialError("encrypted credential vault is invalid or unavailable")
    return CredentialError(f"could not {operation} the {source.value} credential")


def _raise_translated(error: VaultError, *, source: AuthSource, operation: str) -> None:
    translated = _translate_vault_error(error, source=source, operation=operation)
    raise translated from None


def _require_password(value: str) -> None:
    if not value:
        raise CredentialError("IMAP password must not be empty")


def _require_vault_passphrase(passphrase: str | None) -> str:
    if not passphrase:
        raise CredentialError("credential vault master passphrase is required")
    return passphrase


def _keyring_unavailable_reason(reason: str | None) -> str:
    return {
        "not-installed": "keyring support is not installed",
        "no-backend": "no supported OS keyring is available",
        "backend-locked": "the OS keyring is locked or unavailable",
        "backend-rejected": "the configured keyring backend is not an approved OS keyring",
        "backend-error": "the OS keyring could not be inspected",
    }.get(reason or "", "the OS keyring is unavailable")


class PromptCredentialBackend:
    source = AuthSource.PROMPT

    def get(self, ref: CredentialRef, *, passphrase: str | None = None) -> str | None:
        return None

    def create(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        raise CredentialError("prompt source does not store IMAP credentials")

    def replace(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        raise CredentialError("prompt source does not store IMAP credentials")

    def delete(self, ref: CredentialRef, *, passphrase: str | None = None) -> bool:
        return False

    def status(self, ref: CredentialRef, *, passphrase: str | None = None) -> CredentialStatus:
        return CredentialStatus(self.source, False, backend_available=True)

    def resolve_for_login(
        self,
        ref: CredentialRef,
        *,
        prompt_secret: Callable[[str], str],
    ) -> str:
        return prompt_secret("IMAP password: ")


class KeyringCredentialBackend:
    source = AuthSource.KEYRING

    def probe(self) -> SecretBackendInfo:
        try:
            return KeyringVault(service="imapledger-probe").probe()
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="inspect")

    def get(self, ref: CredentialRef, *, passphrase: str | None = None) -> str | None:
        try:
            return KeyringVault(service=keyring_service(ref)).get_secret(keyring_account(ref))
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="read")

    def create(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        _require_password(value)
        try:
            store = KeyringVault(service=keyring_service(ref))
            if store.get_secret(keyring_account(ref)) is not None:
                raise CredentialAlreadyExistsError("an IMAP credential already exists in the OS keyring")
            store.set_secret(keyring_account(ref), value)
        except CredentialError:
            raise
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="store")

    def replace(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        _require_password(value)
        try:
            KeyringVault(service=keyring_service(ref)).set_secret(keyring_account(ref), value)
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="replace")

    def delete(self, ref: CredentialRef, *, passphrase: str | None = None) -> bool:
        try:
            return KeyringVault(service=keyring_service(ref)).delete_secret(keyring_account(ref))
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="delete")

    def status(self, ref: CredentialRef, *, passphrase: str | None = None) -> CredentialStatus:
        try:
            store = KeyringVault(service=keyring_service(ref))
            info = self.probe()
            if not info.available:
                return CredentialStatus(
                    self.source,
                    False,
                    backend_available=False,
                    reason=_keyring_unavailable_reason(info.reason),
                )
            available = store.get_secret(keyring_account(ref)) is not None
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="inspect")
        backend_name = (
            info.backend if info.backend in {"SecretService", "KWallet", "macOS", "Windows Vault"} else "unknown"
        )
        return CredentialStatus(self.source, available, backend_name, backend_available=True)

    def resolve_for_login(
        self,
        ref: CredentialRef,
        *,
        prompt_secret: Callable[[str], str],
    ) -> str | None:
        password = self.get(ref)
        if password is None:
            raise CredentialNotFoundError(
                "IMAP credential is not configured in the OS keyring; run `imapledger auth set`"
            )
        return password


class FileVaultCredentialBackend:
    source = AuthSource.VAULT

    def __init__(
        self,
        vault_path: Path | None = None,
        *,
        min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
    ) -> None:
        self.vault_path = credential_vault_path(vault_path)
        self.min_passphrase_length = min_passphrase_length

    def _vault(self) -> FileVault:
        return FileVault(self.vault_path, min_passphrase_length=self.min_passphrase_length)

    def get(self, ref: CredentialRef, *, passphrase: str | None = None) -> str | None:
        secret = _require_vault_passphrase(passphrase)
        try:
            with self._vault().open(secret) as store:
                return store.get_secret(vault_secret_name(ref))
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="read")

    def create(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        _require_password(value)
        secret = _require_vault_passphrase(passphrase)
        vault = self._vault()
        try:
            if not self.vault_path.exists():
                vault.initialize(secret)
            with vault.open(secret) as store:
                store.create_secret(vault_secret_name(ref), value)
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="store")

    def replace(self, ref: CredentialRef, value: str, *, passphrase: str | None = None) -> None:
        _require_password(value)
        secret = _require_vault_passphrase(passphrase)
        vault = self._vault()
        try:
            if not self.vault_path.exists():
                vault.initialize(secret)
            with vault.open(secret) as store:
                store.set_secret(vault_secret_name(ref), value)
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="replace")

    def delete(self, ref: CredentialRef, *, passphrase: str | None = None) -> bool:
        secret = _require_vault_passphrase(passphrase)
        if not self.vault_path.exists():
            return False
        try:
            with self._vault().open(secret) as store:
                return store.delete_secret(vault_secret_name(ref))
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="delete")

    def status(self, ref: CredentialRef, *, passphrase: str | None = None) -> CredentialStatus:
        if not self.vault_path.exists() and not self.vault_path.parent.exists():
            return CredentialStatus(self.source, False, backend_available=True, vault_path=self.vault_path)
        try:
            info = self._vault().inspect()
        except VaultFormatError as error:
            if str(error) == "vault file does not exist":
                return CredentialStatus(self.source, False, backend_available=True, vault_path=self.vault_path)
            _raise_translated(error, source=self.source, operation="inspect")
        except VaultError as error:
            _raise_translated(error, source=self.source, operation="inspect")
        account_present = None
        if passphrase is not None:
            account_present = self.get(ref, passphrase=passphrase) is not None
        return CredentialStatus(
            self.source,
            account_present,
            backend_available=True,
            vault_path=self.vault_path,
            vault_format=info.format.removeprefix("vaultconfig-secret-"),
            kdf_name=info.kdf_name,
            memlimit_bytes=info.memlimit_bytes,
            opslimit=info.opslimit,
            entry_count=info.entry_count,
        )

    def resolve_for_login(
        self,
        ref: CredentialRef,
        *,
        prompt_secret: Callable[[str], str],
    ) -> str | None:
        passphrase = prompt_secret("Credential vault passphrase: ")
        if not passphrase:
            raise CredentialError("credential vault master passphrase must not be empty")
        password = self.get(ref, passphrase=passphrase)
        if password is None:
            raise CredentialNotFoundError(
                "IMAP credential is not configured in the encrypted vault; run `imapledger auth set`"
            )
        return password


def credential_backend_for(
    source: AuthSource,
    *,
    vault_path: Path | None = None,
    vault_min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
) -> CredentialBackend:
    source = AuthSource(source)
    if source is AuthSource.PROMPT:
        return PromptCredentialBackend()
    if source is AuthSource.KEYRING:
        return KeyringCredentialBackend()
    if source is AuthSource.VAULT:
        return FileVaultCredentialBackend(vault_path, min_passphrase_length=vault_min_passphrase_length)
    raise CredentialError("unsupported IMAP credential source")


def credential_backend_for_storage(
    storage: str,
    *,
    vault_path: Path | None = None,
    vault_min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
) -> CredentialBackend:
    if storage in {"auto", "keyring"}:
        backend = cast(KeyringCredentialBackend, credential_backend_for(AuthSource.KEYRING))
        try:
            info = backend.probe()
        except CredentialError:
            info = None
        if info is not None and info.available:
            return backend
        if storage == "auto":
            raise CredentialBackendUnavailableError(
                "No supported OS keyring is available.\n\n"
                "Install:\n    pip install 'imapledger[keyring]'\n\n"
                "or use the encrypted file vault explicitly:\n    imapledger auth set --storage vault"
            )
        reason = _keyring_unavailable_reason(info.reason if info is not None else None)
        raise CredentialBackendUnavailableError(
            f"{reason}. Install `imapledger[keyring]` or use `imapledger auth set --storage vault`."
        )
    if storage in {"vault", "encrypted-file"}:
        return credential_backend_for(
            AuthSource.VAULT,
            vault_path=vault_path,
            vault_min_passphrase_length=vault_min_passphrase_length,
        )
    raise CredentialError("storage must be auto, keyring, or vault")


def resolve_credential(
    imap: ImapSettings,
    *,
    vault_path: Path | None = None,
    prompt_secret: Callable[[str], str] | None = None,
) -> ResolvedCredential:
    ref = CredentialRef(imap.host, imap.port, imap.username)
    path = imap.auth.vault_path or vault_path
    backend = credential_backend_for(
        imap.auth.source,
        vault_path=path,
        vault_min_passphrase_length=imap.auth.vault_min_passphrase_length,
    )
    password = backend.resolve_for_login(ref, prompt_secret=prompt_secret or getpass.getpass)
    if password is None:
        raise CredentialNotFoundError("IMAP credential was not found")
    if password == "":
        if imap.auth.source is AuthSource.PROMPT:
            raise CredentialError("IMAP password must not be empty")
        raise CredentialError("Stored IMAP credential is empty")
    return ResolvedCredential(password=password, source=imap.auth.source, username=ref.username)


def store_imap_credential(
    imap: ImapSettings,
    password: str,
    source: AuthSource,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> None:
    ref = CredentialRef(imap.host, imap.port, imap.username)
    path = imap.auth.vault_path or vault_path
    credential_backend_for(
        source,
        vault_path=path,
        vault_min_passphrase_length=imap.auth.vault_min_passphrase_length,
    ).create(ref, password, passphrase=master_passphrase)


def replace_imap_credential(
    imap: ImapSettings,
    password: str,
    source: AuthSource,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> None:
    ref = CredentialRef(imap.host, imap.port, imap.username)
    path = imap.auth.vault_path or vault_path
    credential_backend_for(
        source,
        vault_path=path,
        vault_min_passphrase_length=imap.auth.vault_min_passphrase_length,
    ).replace(ref, password, passphrase=master_passphrase)


def credential_status(
    imap: ImapSettings,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> CredentialStatus:
    ref = CredentialRef(imap.host, imap.port, imap.username)
    path = imap.auth.vault_path or vault_path
    return credential_backend_for(
        imap.auth.source,
        vault_path=path,
        vault_min_passphrase_length=imap.auth.vault_min_passphrase_length,
    ).status(ref, passphrase=master_passphrase)


def delete_imap_credential(
    imap: ImapSettings,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> bool:
    ref = CredentialRef(imap.host, imap.port, imap.username)
    path = imap.auth.vault_path or vault_path
    return credential_backend_for(
        imap.auth.source,
        vault_path=path,
        vault_min_passphrase_length=imap.auth.vault_min_passphrase_length,
    ).delete(ref, passphrase=master_passphrase)


def change_credential_vault_passphrase(
    old_passphrase: str,
    new_passphrase: str,
    *,
    vault_path: Path | None = None,
    min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
) -> None:
    try:
        FileVault(
            credential_vault_path(vault_path),
            min_passphrase_length=min_passphrase_length,
        ).change_passphrase(old_passphrase, new_passphrase)
    except VaultError as error:
        _raise_translated(error, source=AuthSource.VAULT, operation="change")
