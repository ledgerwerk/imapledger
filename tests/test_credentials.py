from __future__ import annotations

from pathlib import Path

import pytest
from vaultconfig.secrets import FileVault, VaultError

import imapledger.credentials as credentials
from imapledger.config import AuthSource, ImapAuthSettings, ImapSettings
from imapledger.credentials import (
    CredentialContext,
    CredentialError,
    change_credential_vault_passphrase,
    credential_status,
    default_credential_vault_path,
    delete_imap_credential,
    keyring_service,
    resolve_credential,
    store_imap_credential,
    vault_secret_name,
)

PASSPHRASE = "a sufficiently long test passphrase"


def _imap(source: AuthSource, *, host: str = "mail.example.org") -> ImapSettings:
    return ImapSettings(
        host=host,
        username="alice@example.org",
        port=993,
        auth=ImapAuthSettings(source),
    )


def test_prompt_is_the_default_and_resolved_password_repr_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts: list[str] = []

    def prompt(message: str) -> str:
        prompts.append(message)
        return "do-not-print-this"

    monkeypatch.setattr(credentials.getpass, "getpass", prompt)
    resolved = resolve_credential(ImapSettings("mail.example.org", "alice@example.org"))

    assert resolved.source is AuthSource.PROMPT
    assert resolved.password == "do-not-print-this"
    assert "do-not-print-this" not in repr(resolved)
    assert prompts == ["IMAP password: "]


def test_keyring_resolver_uses_normalized_host_and_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []

    class FakeKeyringVault:
        def __init__(self, *, service: str) -> None:
            observed.append(("service", service))

        def get_secret(self, name: str) -> str:
            observed.append(("name", name))
            return "keyring-password"

    monkeypatch.setattr(credentials, "KeyringVault", FakeKeyringVault)
    resolved = resolve_credential(_imap(AuthSource.KEYRING, host="Mail.Example.Org."))

    assert resolved.password == "keyring-password"
    assert resolved.source is AuthSource.KEYRING
    assert observed == [
        ("service", "imapledger:mail.example.org:993"),
        ("name", "alice@example.org"),
    ]


def test_missing_or_unavailable_keyring_credentials_fail_without_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts: list[str] = []

    class MissingKeyringVault:
        def __init__(self, *, service: str) -> None:
            pass

        def get_secret(self, name: str) -> None:
            return None

    monkeypatch.setattr(credentials, "KeyringVault", MissingKeyringVault)
    monkeypatch.setattr(credentials.getpass, "getpass", lambda message: prompts.append(message))
    with pytest.raises(CredentialError, match="not configured in the OS keyring"):
        resolve_credential(_imap(AuthSource.KEYRING))
    assert prompts == []

    class FailedKeyringVault:
        def __init__(self, *, service: str) -> None:
            pass

        def get_secret(self, name: str) -> None:
            raise VaultError("backend error containing a secret")

    monkeypatch.setattr(credentials, "KeyringVault", FailedKeyringVault)
    with pytest.raises(CredentialError) as error:
        resolve_credential(_imap(AuthSource.KEYRING))
    assert "backend error" not in str(error.value)


def test_vault_resolver_unlocks_only_the_account_specific_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "data" / "credentials.enc"
    context = CredentialContext("Mail.Example.Org.", 993, "alice@example.org")
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    with vault.open(PASSPHRASE) as store:
        store.set_secret(vault_secret_name(context), "vault-password")

    prompts: list[str] = []
    monkeypatch.setattr(
        credentials.getpass,
        "getpass",
        lambda message: prompts.append(message) or PASSPHRASE,
    )
    resolved = resolve_credential(
        _imap(AuthSource.VAULT, host="Mail.Example.Org."),
        vault_path=path,
    )

    assert resolved.password == "vault-password"
    assert resolved.source is AuthSource.VAULT
    assert prompts == ["Credential vault passphrase: "]
    assert vault_secret_name(context) != vault_secret_name(
        CredentialContext("mail.example.org", 993, "other@example.org")
    )


def test_missing_or_locked_vault_fails_without_falling_back_to_imap_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passphrases: list[str] = []
    monkeypatch.setattr(
        credentials.getpass,
        "getpass",
        lambda message: passphrases.append(message) or PASSPHRASE,
    )
    with pytest.raises(CredentialError, match="encrypted credential vault"):
        resolve_credential(_imap(AuthSource.VAULT), vault_path=tmp_path / "missing.enc")
    assert passphrases == ["Credential vault passphrase: "]

    path = tmp_path / "credentials.enc"
    FileVault(path).initialize(PASSPHRASE)
    monkeypatch.setattr(credentials.getpass, "getpass", lambda message: "wrong passphrase")
    with pytest.raises(CredentialError, match="encrypted credential vault") as error:
        resolve_credential(_imap(AuthSource.VAULT), vault_path=path)
    assert "wrong passphrase" not in str(error.value)
    assert PASSPHRASE not in str(error.value)


def test_default_vault_path_uses_xdg_data_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    assert default_credential_vault_path() == tmp_path / "data" / "imapledger" / "credentials.enc"


def test_direct_connection_mode_uses_prompt_credential_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from imapledger.cli import _resolve_folder_imap_settings

    prompts: list[str] = []
    monkeypatch.setattr(
        credentials.getpass,
        "getpass",
        lambda message: prompts.append(message) or "direct-password",
    )
    imap = _resolve_folder_imap_settings(
        tmp_path / "unused-config.toml",
        host="Mail.Example.Org.",
        username="alice@example.org",
        port=993,
    )
    resolved = resolve_credential(imap)

    assert imap.auth.source is AuthSource.PROMPT
    assert resolved.password == "direct-password"
    assert prompts == ["IMAP password: "]


def test_account_identity_uses_normalized_host_port_and_username() -> None:
    first = CredentialContext("Mail.Example.Org.", 993, "alice@example.org")
    same = CredentialContext("mail.example.org", 993, "alice@example.org")
    other_port = CredentialContext("mail.example.org", 143, "alice@example.org")

    assert keyring_service(first) == "imapledger:mail.example.org:993"
    assert keyring_service(first) == keyring_service(same)
    assert vault_secret_name(first) == vault_secret_name(same)
    assert vault_secret_name(first) != vault_secret_name(other_port)


def test_keyring_store_refuses_to_overwrite_an_existing_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExistingKeyringVault:
        def __init__(self, *, service: str) -> None:
            pass

        def get_secret(self, name: str) -> str:
            return "existing-password"

        def set_secret(self, name: str, value: str) -> None:
            pytest.fail("existing keyring credential must not be overwritten")

    monkeypatch.setattr(credentials, "KeyringVault", ExistingKeyringVault)
    with pytest.raises(CredentialError, match="already exists in the OS keyring"):
        store_imap_credential(_imap(AuthSource.KEYRING), "replacement", AuthSource.KEYRING)


def test_file_vault_storage_is_account_scoped_deletable_and_rekeyable(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    imap = _imap(AuthSource.VAULT)
    store_imap_credential(
        imap,
        "first-account-password",
        AuthSource.VAULT,
        master_passphrase=PASSPHRASE,
        vault_path=path,
    )
    with pytest.raises(CredentialError, match="already exists in the encrypted vault"):
        store_imap_credential(
            imap,
            "replacement",
            AuthSource.VAULT,
            master_passphrase=PASSPHRASE,
            vault_path=path,
        )

    other = ImapSettings(
        host=imap.host,
        username="bob@example.org",
        port=imap.port,
        auth=ImapAuthSettings(AuthSource.VAULT),
    )
    store_imap_credential(
        other,
        "second-account-password",
        AuthSource.VAULT,
        master_passphrase=PASSPHRASE,
        vault_path=path,
    )
    status = credential_status(imap, master_passphrase=PASSPHRASE, vault_path=path)
    assert status.available is True
    assert "first-account-password" not in repr(status)

    assert delete_imap_credential(imap, master_passphrase=PASSPHRASE, vault_path=path)
    first_context = CredentialContext(imap.host, imap.port, imap.username)
    other_context = CredentialContext(other.host, other.port, other.username)
    with FileVault(path).open(PASSPHRASE) as store:
        assert store.get_secret(vault_secret_name(first_context)) is None
        assert store.get_secret(vault_secret_name(other_context)) == "second-account-password"

    new_passphrase = "another sufficiently long vault passphrase"
    change_credential_vault_passphrase(PASSPHRASE, new_passphrase, vault_path=path)
    with pytest.raises(VaultError):
        with FileVault(path).open(PASSPHRASE):
            pass
    with FileVault(path).open(new_passphrase) as store:
        assert store.get_secret(vault_secret_name(other_context)) == "second-account-password"


def test_keyring_status_reports_backend_without_returning_the_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeKeyringVault:
        def __init__(self, *, service: str) -> None:
            pass

        def backend_info(self) -> dict[str, str]:
            return {"backend": "keyring.backends.SecretService.Keyring"}

        def get_secret(self, name: str) -> str:
            return "status-secret"

    monkeypatch.setattr(credentials, "KeyringVault", FakeKeyringVault)
    status = credential_status(_imap(AuthSource.KEYRING))

    assert status.available is True
    assert status.backend_name == "SecretService"
    assert "status-secret" not in repr(status)


def test_keyring_store_writes_only_the_selected_account(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[tuple[str, str, str]] = []

    class EmptyKeyringVault:
        def __init__(self, *, service: str) -> None:
            self.service = service

        def get_secret(self, name: str) -> None:
            return None

        def set_secret(self, name: str, value: str) -> None:
            observed.append((self.service, name, value))

    monkeypatch.setattr(credentials, "KeyringVault", EmptyKeyringVault)
    store_imap_credential(
        _imap(AuthSource.KEYRING, host="Mail.Example.Org."),
        "new-password",
        AuthSource.KEYRING,
    )

    assert observed == [("imapledger:mail.example.org:993", "alice@example.org", "new-password")]
