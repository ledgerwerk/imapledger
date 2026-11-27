from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

from textual.widgets import Button, Input, Select, Static

from imapledger.config import (
    AuthSource,
    ImapAuthSettings,
    ImapSettings,
    Settings,
    load_settings,
    write_auth_config,
    write_settings,
)
from imapledger.credentials import CredentialStatus, ResolvedCredential
from imapledger.mailbox import FolderInfo
from imapledger.tui.app import MailReviewApp
from imapledger.tui.session import AppSession, SessionState
from imapledger.tui.system_screens import (
    ConnectDialog,
    CredentialSetDialog,
    SetupDialog,
    SystemScreen,
)

SETTINGS = Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org"))


class _Closable:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _MailService(_Closable):
    def list_folders(self, *, include_counts: bool):
        return (FolderInfo("INBOX", ".", frozenset(), 1, 0),)

    def refresh_folder_counts(self, folders):
        return {folder: (1, 0) for folder in folders}


def test_session_loads_local_states_without_connecting(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    session = AppSession(config_path)
    assert session.load_local() is SessionState.NO_CONFIG

    config_path.write_text("[imap\n", encoding="utf-8")
    assert session.load_local() is SessionState.CONFIG_ERROR
    assert session.error_type == "ConfigError"

    write_settings(SETTINGS, config_path, overwrite=True)
    assert session.load_local() is SessionState.DISCONNECTED
    assert session.mail_service is None
    assert "password requested" in session.credential_summary

    keyring_settings = replace(
        SETTINGS,
        imap=replace(SETTINGS.imap, auth=ImapAuthSettings(source=AuthSource.KEYRING)),
    )
    write_settings(keyring_settings, config_path, overwrite=True)
    missing_status = CredentialStatus(
        source=AuthSource.KEYRING,
        available=False,
        backend_name="OS keyring",
        backend_available=True,
        reason="No credential stored",
    )
    missing_session = AppSession(
        config_path,
        credential_status_resolver=lambda _imap: missing_status,
    )
    assert missing_session.load_local() is SessionState.CREDENTIAL_MISSING
    assert missing_session.mail_service is None


def test_session_connect_and_disconnect_owns_services(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_settings(SETTINGS, config_path)
    mail = _MailService()
    action = _Closable()
    session = AppSession(
        config_path,
        credential_resolver=lambda imap, **_kwargs: ResolvedCredential(
            "hidden-password", AuthSource.PROMPT, imap.username
        ),
        mail_service_factory=lambda *_args: mail,
        analysis_service_factory=lambda *_args: object(),
        action_service_factory=lambda *_args, **_kwargs: action,
    )
    assert session.load_local() is SessionState.DISCONNECTED
    session.connect("typed-password")
    assert session.status is SessionState.CONNECTED
    assert session.password == "hidden-password"
    assert "hidden-password" not in repr(session)

    session.disconnect()
    assert session.status is SessionState.DISCONNECTED
    assert session.password == ""
    assert mail.closed
    assert action.closed


def test_disconnected_tui_bootstraps_config_and_connects_after_reload(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    session = AppSession(config_path)
    app = MailReviewApp(config_path, session=session)

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SystemScreen)
            await pilot.click("#system-setup")
            await pilot.pause()
            assert isinstance(app.screen, SetupDialog)
            app.screen.query_one("#setup-host", Input).value = "imap.example.org"
            app.screen.query_one("#setup-username", Input).value = "user@example.org"
            await pilot.click("#setup-save")
            await pilot.pause(0.3)
            assert config_path.exists()
            assert load_settings(config_path).imap.host == "imap.example.org"
            app.action_system()
            await pilot.pause()
            assert isinstance(app.screen, SystemScreen)
            assert not app.screen.query_one("#system-connect", Button).disabled
            assert "user@example.org @ imap.example.org:993" in str(
                app.screen.query_one("#system-summary", Static).render()
            )
            assert session.status is SessionState.DISCONNECTED
            assert session.mail_service is None

            mail = _MailService()
            action = _Closable()
            session._credential_resolver = lambda imap, **_kwargs: ResolvedCredential(
                "not-a-ui-value", AuthSource.PROMPT, imap.username
            )
            session._mail_service_factory = lambda *_args: mail
            session._analysis_service_factory = lambda *_args: object()
            session._action_service_factory = lambda *_args, **_kwargs: action
            await pilot.click("#system-connect")
            await pilot.pause()
            # Prompt auth requires an explicit secret dialog before connecting.
            assert isinstance(app.screen, ConnectDialog)
            app.screen.query_one("#connect-secret", Input).value = "typed-password"
            await pilot.click("#connect-confirm")
            await pilot.pause(0.3)
            assert session.status is SessionState.CONNECTED
            assert app.mail_service is mail

    asyncio.run(scenario())


def test_disconnected_tui_setup_and_connect_with_keyboard(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    session = AppSession(config_path)
    app = MailReviewApp(config_path, session=session)

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SystemScreen)
            assert app.focused is app.screen.query_one("#system-setup", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, SetupDialog)
            assert app.focused is app.screen.query_one("#setup-path", Input)

            app.screen.query_one("#setup-host", Input).value = "imap.example.org"
            app.screen.query_one("#setup-username", Input).value = "user@example.org"
            await pilot.press("tab", "tab", "tab", "tab", "tab")
            assert app.focused is app.screen.query_one("#setup-save", Button)
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause(0.3)
            assert config_path.exists()

            mail = _MailService()
            action = _Closable()
            session._credential_resolver = lambda imap, **_kwargs: ResolvedCredential(
                "not-a-ui-value", AuthSource.PROMPT, imap.username
            )
            session._mail_service_factory = lambda *_args: mail
            session._analysis_service_factory = lambda *_args: object()
            session._action_service_factory = lambda *_args, **_kwargs: action

            if not isinstance(app.screen, SystemScreen):
                app.action_system()
                await pilot.pause()
            system = app.screen
            await pilot.press("tab", "tab", "tab")
            assert app.focused is system.query_one("#system-connect", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ConnectDialog)
            assert app.focused is app.screen.query_one("#connect-secret", Input)
            app.screen.query_one("#connect-secret", Input).value = "typed-password"
            await pilot.press("tab", "enter")
            await pilot.pause(0.3)
            assert session.status is SessionState.CONNECTED
            assert app.mail_service is mail

    asyncio.run(scenario())


def test_tui_connected_startup_lists_mail_folders(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_settings(SETTINGS, config_path)
    mail = _MailService()
    action = _Closable()
    session = AppSession(
        config_path,
        credential_resolver=lambda imap, **_kwargs: ResolvedCredential(
            "hidden-password", AuthSource.PROMPT, imap.username
        ),
        mail_service_factory=lambda *_args: mail,
        analysis_service_factory=lambda *_args: object(),
        action_service_factory=lambda *_args, **_kwargs: action,
    )
    session.load_local()
    session.connect("typed-password")
    app = MailReviewApp(config_path, session=session)

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause(0.2)
            assert session.status is SessionState.CONNECTED
            assert tuple(folder.name for folder in app.folders) == ("INBOX",)
            assert app.mail_service is mail

    asyncio.run(scenario())


def test_credential_dialog_masks_secrets_and_stores_outside_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_settings(SETTINGS, config_path)
    session = AppSession(config_path)
    session.load_local()
    app = MailReviewApp(config_path, session=session)
    captured: dict[str, str] = {}
    backend = type("Backend", (), {"source": AuthSource.VAULT})()

    def fake_configure(**kwargs) -> None:
        captured["password"] = kwargs["password"]
        captured["passphrase"] = kwargs["passphrase"]
        write_auth_config(config_path, source=AuthSource.VAULT)

    monkeypatch.setattr("imapledger.tui.app.credential_backend_for_storage", lambda *_args, **_kwargs: backend)
    monkeypatch.setattr("imapledger.tui.app.configure_stored_credential", fake_configure)

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            app.action_system()
            await pilot.pause()
            await pilot.click("#system-auth-set")
            await pilot.pause()
            assert isinstance(app.screen, CredentialSetDialog)
            app.screen.query_one("#credential-storage", Select).value = "vault"
            password = app.screen.query_one("#credential-password", Input)
            passphrase = app.screen.query_one("#credential-passphrase", Input)
            confirmation = app.screen.query_one("#credential-passphrase-confirm", Input)
            assert password.password
            assert passphrase.password
            password.value = "sensitive-imap-password"
            passphrase.value = "sensitive-vault-passphrase"
            confirmation.value = "sensitive-vault-passphrase"
            await pilot.click("#credential-set-save")
            await pilot.pause(0.3)
            assert captured == {
                "password": "sensitive-imap-password",
                "passphrase": "sensitive-vault-passphrase",
            }
            assert "sensitive-imap-password" not in config_path.read_text(encoding="utf-8")
            assert "sensitive-vault-passphrase" not in config_path.read_text(encoding="utf-8")
            assert "sensitive-imap-password" not in str(app.query_one("#status", Static).render())

    asyncio.run(scenario())
