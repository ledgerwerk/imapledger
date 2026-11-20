from __future__ import annotations

from pathlib import Path

import pytest
from vaultconfig.secrets import (
    DEFAULT_MIN_PASSPHRASE_LENGTH,
    FileVault,
    SecretBackendInfo,
    VaultConflictError,
    VaultError,
    VaultPassphrasePolicyError,
)

import imapledger.credentials as credentials
from imapledger.config import AuthSource, ImapAuthSettings, ImapSettings
from imapledger.credentials import (
    CredentialBackendUnavailableError,
    CredentialContext,
    CredentialError,
    CredentialRef,
    CredentialTransactionError,
    change_credential_vault_passphrase,
    credential_backend_for,
    credential_backend_for_storage,
    credential_status,
    credential_vault_path,
    default_credential_vault_path,
    delete_imap_credential,
    keyring_service,
    resolve_credential,
    store_imap_credential,
    vault_secret_name,
)

PASSPHRASE = "a sufficiently long test passphrase"


def _imap(
    source: AuthSource,
    *,
    host: str = "mail.example.org",
    vault_path: Path | None = None,
    vault_min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
) -> ImapSettings:
    return ImapSettings(
        host=host,
        username="alice@example.org",
        port=993,
        auth=ImapAuthSettings(source, vault_path, vault_min_passphrase_length),
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
    resolved = resolve_credential(_imap(AuthSource.VAULT, host="Mail.Example.Org.", vault_path=path))

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

        def probe(self) -> SecretBackendInfo:
            return SecretBackendInfo("keyring", True, "SecretService")

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


def test_credential_ref_normalizes_host_without_lowercasing_username() -> None:
    ref = CredentialRef("Mail.Example.Org.", 993, "Alice@Example.org")

    assert ref.normalized_host == "mail.example.org"
    assert keyring_service(ref) == "imapledger:mail.example.org:993"
    assert vault_secret_name(ref) == 'imapledger:["mail.example.org",993,"Alice@Example.org"]'


def test_vault_path_expands_home_at_use_time(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    backend = credential_backend_for(AuthSource.VAULT, vault_path=Path("~/vaults/account.enc"))

    assert isinstance(backend, credentials.FileVaultCredentialBackend)
    assert backend.vault_path == tmp_path / "vaults" / "account.enc"
    assert credential_vault_path(Path("~/vaults/account.enc")) == backend.vault_path


def test_empty_stored_keyring_credential_is_present_but_rejected_for_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyKeyringVault:
        def __init__(self, *, service: str) -> None:
            pass

        def probe(self) -> SecretBackendInfo:
            return SecretBackendInfo("keyring", True, "SecretService")

        def get_secret(self, name: str) -> str:
            return ""

    monkeypatch.setattr(credentials, "KeyringVault", EmptyKeyringVault)

    with pytest.raises(CredentialError, match="Stored IMAP credential is empty"):
        resolve_credential(_imap(AuthSource.KEYRING))
    assert credential_status(_imap(AuthSource.KEYRING)).available is True


def test_storage_auto_uses_a_probed_keyring_without_silent_vault_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AvailableKeyring:
        def __init__(self, *, service: str) -> None:
            pass

        def probe(self) -> SecretBackendInfo:
            return SecretBackendInfo("keyring", True, "SecretService")

    monkeypatch.setattr(credentials, "KeyringVault", AvailableKeyring)

    backend = credential_backend_for_storage("auto")

    assert isinstance(backend, credentials.KeyringCredentialBackend)


def test_storage_auto_without_keyring_shows_explicit_choices(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnavailableKeyring:
        def __init__(self, *, service: str) -> None:
            pass

        def probe(self) -> SecretBackendInfo:
            return SecretBackendInfo("keyring", False, reason="not-installed")

    monkeypatch.setattr(credentials, "KeyringVault", UnavailableKeyring)
    monkeypatch.setattr(
        credentials,
        "FileVaultCredentialBackend",
        lambda path: pytest.fail("auto selection must not create a vault backend"),
    )

    with pytest.raises(CredentialBackendUnavailableError) as error:
        credential_backend_for_storage("auto")

    assert "pip install 'imapledger[keyring]'" in str(error.value)
    assert "--storage vault" in str(error.value)


def test_explicit_keyring_reports_install_hint_and_vault_selection_does_not_probe_keyring(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    probe_calls = []

    class UnavailableKeyring:
        def __init__(self, *, service: str) -> None:
            pass

        def probe(self) -> SecretBackendInfo:
            probe_calls.append(self)
            return SecretBackendInfo("keyring", False, reason="backend-rejected")

    monkeypatch.setattr(credentials, "KeyringVault", UnavailableKeyring)

    with pytest.raises(CredentialBackendUnavailableError, match="imapledger\\[keyring\\]"):
        credential_backend_for_storage("keyring")
    backend = credential_backend_for_storage("vault", vault_path=tmp_path / "credentials.enc")
    assert isinstance(backend, credentials.FileVaultCredentialBackend)
    assert len(probe_calls) == 1


def test_file_vault_status_uses_safe_inspection_without_unlocking(tmp_path: Path) -> None:
    path = tmp_path / "data" / "credentials.enc"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    with vault.open(PASSPHRASE) as store:
        store.create_secret(vault_secret_name(CredentialRef("mail.example.org", 993, "alice")), "status-secret")

    status = credential_status(_imap(AuthSource.VAULT, vault_path=path))

    assert status.available is None
    assert status.vault_format == "v2"
    assert status.kdf_name == "argon2id"
    assert status.memlimit_bytes == 64 * 1024 * 1024
    assert status.opslimit == 2
    assert status.entry_count == 1
    assert "status-secret" not in repr(status)


def test_vault_conflict_error_is_stable_and_does_not_expose_backend_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentials.enc"
    FileVault(path).initialize(PASSPHRASE)
    backend = credential_backend_for(AuthSource.VAULT, vault_path=path)

    class ConflictingStore:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def set_secret(self, name: str, value: str) -> None:
            raise VaultConflictError(f"conflict while writing {value}")

    class ConflictingVault:
        def open(self, passphrase: str) -> ConflictingStore:
            return ConflictingStore()

    monkeypatch.setattr(backend, "_vault", lambda: ConflictingVault())

    with pytest.raises(CredentialTransactionError, match="vault changed") as error:
        backend.replace(
            CredentialRef("mail.example.org", 993, "alice@example.org"),
            "UNIQUE_IMAP_PASSWORD_SENTINEL",
            passphrase=PASSPHRASE,
        )

    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_short_vault_passphrases_get_configured_minimum_guidance_during_setup_and_change(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    backend = credential_backend_for(AuthSource.VAULT, vault_path=path)
    ref = CredentialRef("mail.example.org", 993, "alice@example.org")

    with pytest.raises(CredentialError, match="Master passphrase must be at least 12 characters") as setup_error:
        backend.create(ref, "UNIQUE_IMAP_PASSWORD_SENTINEL", passphrase="12345678901")
    assert "Configure [imap.auth].vault_min_passphrase_length" in str(setup_error.value)
    assert "12345678901" not in str(setup_error.value)
    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(setup_error.value)

    FileVault(path).initialize(PASSPHRASE)
    with pytest.raises(CredentialError, match="Master passphrase must be at least 10 characters") as change_error:
        change_credential_vault_passphrase(
            PASSPHRASE,
            "123456789",
            vault_path=path,
            min_passphrase_length=10,
        )
    assert "123456789" not in str(change_error.value)


def test_empty_password_is_rejected_before_secure_storage() -> None:
    with pytest.raises(CredentialError, match="IMAP password must not be empty"):
        store_imap_credential(_imap(AuthSource.KEYRING), "", AuthSource.KEYRING)


def test_unsafe_vault_permissions_report_only_a_stable_error(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    FileVault(path).initialize(PASSPHRASE)
    path.chmod(0o644)

    with pytest.raises(CredentialBackendUnavailableError, match="unavailable or unsafe") as error:
        credential_status(_imap(AuthSource.VAULT, vault_path=path))

    assert PASSPHRASE not in str(error.value)


def test_file_vault_replace_creates_absent_and_updates_existing_credential(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    backend = credential_backend_for(AuthSource.VAULT, vault_path=path)
    ref = CredentialRef("mail.example.org", 993, "alice@example.org")

    backend.replace(ref, "first-password", passphrase=PASSPHRASE)
    assert backend.get(ref, passphrase=PASSPHRASE) == "first-password"

    backend.replace(ref, "second-password", passphrase=PASSPHRASE)
    assert backend.get(ref, passphrase=PASSPHRASE) == "second-password"


def test_keyring_replace_failure_redacts_backend_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailedKeyring:
        def __init__(self, *, service: str) -> None:
            pass

        def set_secret(self, name: str, value: str) -> None:
            raise VaultError(f"backend failed while storing {value}")

    monkeypatch.setattr(credentials, "KeyringVault", FailedKeyring)
    backend = credential_backend_for(AuthSource.KEYRING)

    with pytest.raises(CredentialError, match="could not replace") as error:
        backend.replace(
            CredentialRef("mail.example.org", 993, "alice@example.org"),
            "UNIQUE_IMAP_PASSWORD_SENTINEL",
        )

    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_keyring_status_maps_backend_rejection_to_safe_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    class RejectedKeyring:
        def __init__(self, *, service: str) -> None:
            pass

        def probe(self) -> SecretBackendInfo:
            return SecretBackendInfo("keyring", False, reason="backend-rejected")

    monkeypatch.setattr(credentials, "KeyringVault", RejectedKeyring)

    status = credential_status(_imap(AuthSource.KEYRING))

    assert status.available is False
    assert status.backend_available is False
    assert status.reason == "the configured keyring backend is not an approved OS keyring"
    assert "backend-rejected" not in repr(status)


def test_keyring_constructor_errors_are_translated_without_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailedKeyring:
        def __init__(self, *, service: str) -> None:
            raise VaultError("constructor payload contains UNIQUE_IMAP_PASSWORD_SENTINEL")

    monkeypatch.setattr(credentials, "KeyringVault", FailedKeyring)
    backend = credential_backend_for(AuthSource.KEYRING)

    with pytest.raises(CredentialError, match="could not store") as error:
        backend.create(
            CredentialRef("mail.example.org", 993, "alice@example.org"),
            "UNIQUE_IMAP_PASSWORD_SENTINEL",
        )

    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_vault_passphrase_policy_translation_uses_structured_fields() -> None:
    error = VaultPassphrasePolicyError(
        "altered backend policy message",
        reason="minimum_length",
        minimum_length=10,
    )

    translated = credentials._translate_vault_error(error, source=AuthSource.VAULT, operation="store")
    assert str(translated) == (
        "Master passphrase must be at least 10 characters for encrypted-file storage. "
        "Configure [imap.auth].vault_min_passphrase_length to use a different minimum."
    )
    assert "altered backend policy message" not in str(translated)

    unspecified = VaultPassphrasePolicyError("backend detail", reason="policy", minimum_length=None)
    translated_unspecified = credentials._translate_vault_error(
        unspecified,
        source=AuthSource.VAULT,
        operation="store",
    )
    assert str(translated_unspecified) == "Master passphrase does not satisfy the encrypted-vault passphrase policy."
    assert "backend detail" not in str(translated_unspecified)


def test_custom_vault_minimum_accepts_ten_characters_and_rejects_nine(tmp_path: Path) -> None:
    ref = CredentialRef("mail.example.org", 993, "alice@example.org")
    accepted_path = tmp_path / "accepted.enc"
    backend = credential_backend_for(
        AuthSource.VAULT,
        vault_path=accepted_path,
        vault_min_passphrase_length=10,
    )
    backend.create(ref, "UNIQUE_IMAP_PASSWORD_SENTINEL", passphrase="1234567890")
    assert backend.get(ref, passphrase="1234567890") == "UNIQUE_IMAP_PASSWORD_SENTINEL"

    rejected_path = tmp_path / "rejected.enc"
    backend = credential_backend_for(
        AuthSource.VAULT,
        vault_path=rejected_path,
        vault_min_passphrase_length=10,
    )
    with pytest.raises(CredentialError, match="Master passphrase must be at least 10 characters") as error:
        backend.create(ref, "UNIQUE_IMAP_PASSWORD_SENTINEL", passphrase="123456789")
    assert "123456789" not in str(error.value)
    assert "UNIQUE_IMAP_PASSWORD_SENTINEL" not in str(error.value)


def test_existing_vault_unlocks_when_current_minimum_is_higher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentials.enc"
    short_passphrase = "1234567890"
    vault = FileVault(path, min_passphrase_length=10)
    vault.initialize(short_passphrase)
    ref = CredentialRef("mail.example.org", 993, "alice@example.org")
    with vault.open(short_passphrase) as store:
        store.set_secret(vault_secret_name(ref), "stored-imap-password")

    monkeypatch.setattr(credentials.getpass, "getpass", lambda prompt: short_passphrase)
    resolved = resolve_credential(_imap(AuthSource.VAULT, vault_path=path))
    assert resolved.password == "stored-imap-password"


def test_passphrase_change_enforces_configured_new_minimum_and_preserves_credentials(tmp_path: Path) -> None:
    path = tmp_path / "credentials.enc"
    old_passphrase = "oldpass"
    new_passphrase = "1234567890"
    ref = CredentialRef("mail.example.org", 993, "alice@example.org")
    vault = FileVault(path, min_passphrase_length=7)
    vault.initialize(old_passphrase)
    with vault.open(old_passphrase) as store:
        store.set_secret(vault_secret_name(ref), "stored-imap-password")

    change_credential_vault_passphrase(
        old_passphrase,
        new_passphrase,
        vault_path=path,
        min_passphrase_length=10,
    )
    with FileVault(path, min_passphrase_length=10).open(new_passphrase) as store:
        assert store.get_secret(vault_secret_name(ref)) == "stored-imap-password"

    with pytest.raises(CredentialError, match="Master passphrase must be at least 10 characters"):
        change_credential_vault_passphrase(
            new_passphrase,
            "123456789",
            vault_path=path,
            min_passphrase_length=10,
        )
    with FileVault(path, min_passphrase_length=10).open(new_passphrase) as store:
        assert store.get_secret(vault_secret_name(ref)) == "stored-imap-password"
