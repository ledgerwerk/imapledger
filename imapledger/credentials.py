from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from vaultconfig.secrets import FileVault, KeyringVault, VaultError

from .config import AuthSource, ImapSettings


class CredentialError(RuntimeError):
    """Raised when the configured IMAP credential source cannot provide a password."""


@dataclass(frozen=True, slots=True)
class CredentialContext:
    host: str
    port: int
    username: str


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    password: str = field(repr=False)
    source: AuthSource

    def __repr__(self) -> str:
        return f"ResolvedCredential(source={self.source.value!r}, password=<redacted>)"


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    source: AuthSource
    available: bool
    backend_name: str | None = None


def default_credential_vault_path() -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return data_home / "imapledger" / "credentials.enc"


def keyring_service(context: CredentialContext) -> str:
    host = context.host.lower().rstrip(".")
    return f"imapledger:{host}:{context.port}"


def vault_secret_name(context: CredentialContext) -> str:
    identity = json.dumps(
        [context.host.lower().rstrip("."), context.port, context.username],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return f"imapledger:{identity}"


def resolve_credential(
    imap: ImapSettings,
    *,
    vault_path: Path | None = None,
) -> ResolvedCredential:
    context = CredentialContext(imap.host, imap.port, imap.username)
    source = imap.auth.source

    if source is AuthSource.PROMPT:
        password = getpass.getpass("IMAP password: ")
        if not password:
            raise CredentialError("empty IMAP password")
        return ResolvedCredential(password, source)

    if source is AuthSource.KEYRING:
        try:
            password = KeyringVault(service=keyring_service(context)).get_secret(imap.username)
        except VaultError:
            raise CredentialError(
                "could not read the OS keyring credential; run `imapledger auth set` or configure prompt"
            ) from None
        if not password:
            raise CredentialError("IMAP credential is not configured in the OS keyring; run `imapledger auth set`")
        return ResolvedCredential(password, source)

    if source is AuthSource.VAULT:
        passphrase = getpass.getpass("Credential vault passphrase: ")
        if not passphrase:
            raise CredentialError("empty credential vault passphrase")
        try:
            with FileVault(vault_path or default_credential_vault_path()).open(passphrase) as store:
                password = store.get_secret(vault_secret_name(context))
        except VaultError:
            raise CredentialError("could not unlock the encrypted credential vault") from None
        if not password:
            raise CredentialError("IMAP credential is not configured in the encrypted vault; run `imapledger auth set`")
        return ResolvedCredential(password, source)

    raise CredentialError("unsupported IMAP credential source")


def store_imap_credential(
    imap: ImapSettings,
    password: str,
    source: AuthSource,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> None:
    if not password:
        raise CredentialError("empty IMAP password")
    context = CredentialContext(imap.host, imap.port, imap.username)

    if source is AuthSource.KEYRING:
        try:
            store = KeyringVault(service=keyring_service(context))
            if store.get_secret(imap.username) is not None:
                raise CredentialError("an IMAP credential already exists in the OS keyring")
            store.set_secret(imap.username, password)
        except VaultError:
            raise CredentialError("could not store the IMAP credential in the OS keyring") from None
        return

    if source is AuthSource.VAULT:
        if not master_passphrase:
            raise CredentialError("credential vault passphrase is required")
        path = vault_path or default_credential_vault_path()
        vault = FileVault(path)
        try:
            if not path.exists():
                vault.initialize(master_passphrase)
            with vault.open(master_passphrase) as store:
                name = vault_secret_name(context)
                if store.get_secret(name) is not None:
                    raise CredentialError("an IMAP credential already exists in the encrypted vault")
                store.set_secret(name, password)
        except VaultError:
            raise CredentialError("could not store the IMAP credential in the encrypted vault") from None
        return

    raise CredentialError("prompt source does not store IMAP credentials")


def credential_status(
    imap: ImapSettings,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> CredentialStatus:
    source = imap.auth.source
    if source is AuthSource.PROMPT:
        return CredentialStatus(source, available=False)

    context = CredentialContext(imap.host, imap.port, imap.username)
    if source is AuthSource.KEYRING:
        try:
            store = KeyringVault(service=keyring_service(context))
            backend = store.backend_info().get("backend", "unknown")
            available = bool(store.get_secret(imap.username))
        except VaultError:
            raise CredentialError("could not inspect the OS keyring credential") from None
        backend_name = str(backend).removeprefix("keyring.backends.").split(".", maxsplit=1)[0]
        return CredentialStatus(source, available, backend_name)

    if source is AuthSource.VAULT:
        if not master_passphrase:
            raise CredentialError("credential vault passphrase is required")
        try:
            with FileVault(vault_path or default_credential_vault_path()).open(master_passphrase) as store:
                available = bool(store.get_secret(vault_secret_name(context)))
        except VaultError:
            raise CredentialError("could not unlock the encrypted credential vault") from None
        return CredentialStatus(source, available)

    raise CredentialError("unsupported IMAP credential source")


def delete_imap_credential(
    imap: ImapSettings,
    *,
    master_passphrase: str | None = None,
    vault_path: Path | None = None,
) -> bool:
    source = imap.auth.source
    context = CredentialContext(imap.host, imap.port, imap.username)
    if source is AuthSource.PROMPT:
        return False

    if source is AuthSource.KEYRING:
        try:
            return KeyringVault(service=keyring_service(context)).delete_secret(imap.username)
        except VaultError:
            raise CredentialError("could not delete the OS keyring credential") from None

    if source is AuthSource.VAULT:
        if not master_passphrase:
            raise CredentialError("credential vault passphrase is required")
        try:
            with FileVault(vault_path or default_credential_vault_path()).open(master_passphrase) as store:
                return store.delete_secret(vault_secret_name(context))
        except VaultError:
            raise CredentialError("could not unlock the encrypted credential vault") from None

    raise CredentialError("unsupported IMAP credential source")


def change_credential_vault_passphrase(
    old_passphrase: str,
    new_passphrase: str,
    *,
    vault_path: Path | None = None,
) -> None:
    try:
        FileVault(vault_path or default_credential_vault_path()).change_passphrase(
            old_passphrase,
            new_passphrase,
        )
    except VaultError:
        raise CredentialError("could not change the encrypted credential vault passphrase") from None
