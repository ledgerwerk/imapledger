from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from ..config import (
    AuthSource,
    ConfigError,
    ImapSettings,
    Settings,
    render_settings,
)
from .session import SessionState


@dataclass(frozen=True, slots=True)
class SetupRequest:
    config_path: Path
    settings: Settings
    overwrite: bool


@dataclass(slots=True)
class CredentialSetRequest:
    storage: str
    password: str = field(repr=False)
    passphrase: str | None = field(default=None, repr=False)
    replace: bool = False


@dataclass(slots=True)
class VaultPassphraseChange:
    old_passphrase: str = field(repr=False)
    new_passphrase: str = field(repr=False)


class SystemScreen(ModalScreen[str | None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    SystemScreen { align: center middle; }
    #system-box { width: 88; height: auto; max-height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #system-summary { height: auto; margin-bottom: 1; }
    #system-buttons { height: auto; }
    #system-buttons Button { margin-right: 1; margin-bottom: 1; }
    """

    def __init__(
        self,
        config_path: Path,
        state: SessionState,
        *,
        settings: Settings | None,
        credential_summary: str,
        error_type: str | None = None,
    ) -> None:
        super().__init__()
        self.config_path = config_path
        self.state = state
        self.settings = settings
        self.credential_summary = credential_summary
        self.error_type = error_type

    def _summary_text(self) -> str:
        lines = [f"Session: {self.state.value}", f"Config path: {self.config_path}"]
        if self.settings is not None:
            lines.extend(
                (
                    f"IMAP: {self.settings.imap.username} @ {self.settings.imap.host}:{self.settings.imap.port}",
                    f"Credential source: {self.settings.imap.auth.source.value}",
                    f"Credential status: {self.credential_summary}",
                )
            )
        else:
            lines.append("Configuration: not loaded")
        if self.error_type:
            lines.append(f"Last error type: {self.error_type}")
        return "\n".join(lines)

    def compose(self) -> ComposeResult:
        with Vertical(id="system-box"):
            yield Static("System / Connection / Credentials / Configuration", markup=False)
            yield Static(self._summary_text(), id="system-summary", markup=False)
            with Vertical(id="system-buttons"):
                with Horizontal():
                    yield Button("Setup / edit config…", id="system-setup")
                    yield Button("Show effective config", id="system-config", disabled=self.settings is None)
                    yield Button("Reload session", id="system-reload")
                with Horizontal():
                    yield Button(
                        "Connect…",
                        id="system-connect",
                        disabled=self.settings is None or self.state is SessionState.CONNECTING,
                    )
                    yield Button(
                        "Disconnect",
                        id="system-disconnect",
                        disabled=self.state is not SessionState.CONNECTED,
                    )
                    yield Button("Set / replace credential…", id="system-auth-set", disabled=self.settings is None)
                with Horizontal():
                    yield Button(
                        "Delete stored credential…",
                        id="system-auth-delete",
                        disabled=self.settings is None or self.settings.imap.auth.source is AuthSource.PROMPT,
                        variant="error",
                    )
                    yield Button(
                        "Change vault passphrase…",
                        id="system-auth-passphrase",
                        disabled=self.settings is None or self.settings.imap.auth.source is not AuthSource.VAULT,
                    )
                    yield Button("Close", id="system-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None if event.button.id == "system-close" else event.button.id.removeprefix("system-"))

    def action_close(self) -> None:
        self.dismiss(None)


class ReloadConfirmation(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ReloadConfirmation { align: center middle; }
    #reload-confirm-box { width: 72; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #reload-confirm-buttons { height: 3; align-horizontal: right; }
    #reload-confirm-buttons Button { margin-left: 1; }
    """

    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason

    def compose(self) -> ComposeResult:
        with Vertical(id="reload-confirm-box"):
            yield Static(f"{self.reason}\n\nReloading closes the active IMAP session.", markup=False)
            with Horizontal(id="reload-confirm-buttons"):
                yield Button("Continue and reload", id="reload-confirm", variant="warning")
                yield Button("Cancel", id="reload-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "reload-confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class ConnectDialog(ModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConnectDialog { align: center middle; }
    #connect-box { width: 70; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #connect-buttons { height: 3; align-horizontal: right; }
    #connect-buttons Button { margin-left: 1; }
    """

    def __init__(self, source: AuthSource) -> None:
        super().__init__()
        self.source = source

    def compose(self) -> ComposeResult:
        prompt = "IMAP password" if self.source is AuthSource.PROMPT else "Vault master passphrase"
        with Vertical(id="connect-box"):
            yield Static(f"Connect using {self.source.value} credentials", markup=False)
            if self.source is not AuthSource.KEYRING:
                yield Label(prompt)
                yield Input(password=True, id="connect-secret")
            else:
                yield Static("The configured OS keyring credential will be used.", markup=False)
            with Horizontal(id="connect-buttons"):
                yield Button("Connect", id="connect-confirm")
                yield Button("Cancel", id="connect-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect-cancel":
            self.dismiss(None)
            return
        value = ""
        if self.source is not AuthSource.KEYRING:
            secret = self.query_one("#connect-secret", Input)
            value = secret.value
            secret.value = ""
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SetupDialog(ModalScreen[SetupRequest | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    SetupDialog { align: center middle; }
    #setup-box { width: 96; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #setup-form { height: 1fr; }
    #setup-buttons { height: 3; align-horizontal: right; }
    #setup-buttons Button { margin-left: 1; }
    """

    def __init__(self, config_path: Path, settings: Settings | None) -> None:
        super().__init__()
        self.config_path = config_path
        self.settings = settings

    def compose(self) -> ComposeResult:
        settings = self.settings
        imap = settings.imap if settings else None
        with Vertical(id="setup-box"):
            yield Static("Setup / Edit Connection", markup=False)
            with VerticalScroll(id="setup-form"):
                yield Label("Config path")
                yield Input(str(self.config_path), id="setup-path")
                yield Label("IMAP host")
                yield Input(imap.host if imap else "", id="setup-host")
                yield Label("IMAP port")
                yield Input(str(imap.port if imap else 993), id="setup-port")
                yield Label("IMAP username")
                yield Input(imap.username if imap else "", id="setup-username")
                yield Checkbox("Overwrite the target configuration file", id="setup-overwrite")
                yield Static("Passwords are never written to the configuration file.", markup=False)
                yield Static("", id="setup-error", markup=False)
            with Horizontal(id="setup-buttons"):
                yield Button("Save config", id="setup-save")
                yield Button("Cancel", id="setup-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "setup-cancel":
            self.dismiss(None)
            return
        try:
            path = Path(self.query_one("#setup-path", Input).value.strip()).expanduser()
            host = self.query_one("#setup-host", Input).value.strip()
            username = self.query_one("#setup-username", Input).value.strip()
            port = int(self.query_one("#setup-port", Input).value.strip())
            if not path.name:
                raise ValueError("Config path is required.")
            if self.settings:
                imap = replace(self.settings.imap, host=host, port=port, username=username)
                settings = replace(self.settings, imap=imap)
            else:
                settings = Settings(imap=ImapSettings(host=host, username=username, port=port))
            request = SetupRequest(path, settings, self.query_one("#setup-overwrite", Checkbox).value)
        except (ConfigError, ValueError, TypeError) as exc:
            self.query_one("#setup-error", Static).update(str(exc))
            return
        self.dismiss(request)
    def action_cancel(self) -> None:
        self.dismiss(None)


class EffectiveConfigScreen(ModalScreen[None]):
    CSS = """
    EffectiveConfigScreen { align: center middle; }
    #effective-config-box { width: 88; height: 88%; border: round $accent; padding: 1 2; background: $surface; }
    #effective-config-text { height: 1fr; }
    """

    def __init__(self, settings: Settings, config_path: Path) -> None:
        super().__init__()
        self.settings = settings
        self.config_path = config_path

    def compose(self) -> ComposeResult:
        with Vertical(id="effective-config-box"):
            yield Static(
                f"Effective configuration: {self.config_path}\nCredentials are stored separately.",
                markup=False,
            )
            with VerticalScroll():
                yield Static(render_settings(self.settings), id="effective-config-text", markup=False)
            yield Button("Close", id="effective-config-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)


class CredentialSetDialog(ModalScreen[CredentialSetRequest | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    CredentialSetDialog { align: center middle; }
    #credential-set-box { width: 78; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #credential-set-buttons { height: 3; align-horizontal: right; }
    #credential-set-buttons Button { margin-left: 1; }
    """

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        with Vertical(id="credential-set-box"):
            yield Static("Store IMAP credentials in secure storage", markup=False)
            yield Label("Storage backend")
            yield Select(
                [("Auto (OS keyring)", "auto"), ("OS keyring", "keyring"), ("Encrypted vault", "vault")],
                value="auto",
                allow_blank=False,
                id="credential-storage",
            )
            yield Label("IMAP password")
            yield Input(password=True, id="credential-password")
            yield Label("Vault master passphrase (vault only)")
            yield Input(password=True, id="credential-passphrase")
            yield Label("Confirm vault master passphrase")
            yield Input(password=True, id="credential-passphrase-confirm")
            yield Checkbox("Replace any existing credential in the selected backend", id="credential-replace")
            yield Static("Secrets are never shown in operation history or saved to config.", markup=False)
            yield Static("", id="credential-set-error", markup=False)
            with Horizontal(id="credential-set-buttons"):
                yield Button("Store credential", id="credential-set-save")
                yield Button("Cancel", id="credential-set-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "credential-set-cancel":
            self._clear_secrets()
            self.dismiss(None)
            return
        try:
            storage = self.query_one("#credential-storage", Select).value
            if not isinstance(storage, str):
                raise ValueError("Choose a credential storage backend.")
            password = self.query_one("#credential-password", Input).value
            passphrase = self.query_one("#credential-passphrase", Input).value
            confirmation = self.query_one("#credential-passphrase-confirm", Input).value
            if not password:
                raise ValueError("IMAP password must not be empty.")
            if storage == "vault" and (not passphrase or passphrase != confirmation):
                raise ValueError("Vault passphrases are required and must match.")
            request = CredentialSetRequest(
                storage,
                password,
                passphrase if storage == "vault" else None,
                self.query_one("#credential-replace", Checkbox).value,
            )
        except (ValueError, TypeError) as exc:
            self.query_one("#credential-set-error", Static).update(str(exc))
            return
        self._clear_secrets()
        self.dismiss(request)

    def _clear_secrets(self) -> None:
        for selector in ("#credential-password", "#credential-passphrase", "#credential-passphrase-confirm"):
            self.query_one(selector, Input).value = ""

    def action_cancel(self) -> None:
        self._clear_secrets()
        self.dismiss(None)


class CredentialDeleteDialog(ModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    CredentialDeleteDialog { align: center middle; }
    #credential-delete-box { width: 72; height: auto; border: round $error; padding: 1 2; background: $surface; }
    #credential-delete-buttons { height: 3; align-horizontal: right; }
    #credential-delete-buttons Button { margin-left: 1; }
    """

    def __init__(self, source: AuthSource) -> None:
        super().__init__()
        self.source = source

    def compose(self) -> ComposeResult:
        with Vertical(id="credential-delete-box"):
            yield Static("Delete stored IMAP credential? The auth source returns to prompt mode.", markup=False)
            if self.source is AuthSource.VAULT:
                yield Label("Vault master passphrase")
                yield Input(password=True, id="credential-delete-passphrase")
            with Horizontal(id="credential-delete-buttons"):
                yield Button("Delete credential", id="credential-delete-confirm", variant="error")
                yield Button("Cancel", id="credential-delete-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "credential-delete-cancel":
            self.dismiss(None)
            return
        secret = ""
        if self.source is AuthSource.VAULT:
            widget = self.query_one("#credential-delete-passphrase", Input)
            secret = widget.value
            widget.value = ""
        self.dismiss(secret)

    def action_cancel(self) -> None:
        self.dismiss(None)


class VaultPassphraseDialog(ModalScreen[VaultPassphraseChange | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    VaultPassphraseDialog { align: center middle; }
    #vault-passphrase-box { width: 72; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #vault-passphrase-buttons { height: 3; align-horizontal: right; }
    #vault-passphrase-buttons Button { margin-left: 1; }
    """

    def __init__(self, minimum_length: int) -> None:
        super().__init__()
        self.minimum_length = minimum_length

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-passphrase-box"):
            yield Static(
                f"Change vault passphrase. New passphrase minimum: {self.minimum_length} characters.",
                markup=False,
            )
            yield Label("Current passphrase")
            yield Input(password=True, id="vault-old-passphrase")
            yield Label("New passphrase")
            yield Input(password=True, id="vault-new-passphrase")
            yield Label("Confirm new passphrase")
            yield Input(password=True, id="vault-confirm-passphrase")
            yield Static("", id="vault-passphrase-error", markup=False)
            with Horizontal(id="vault-passphrase-buttons"):
                yield Button("Change passphrase", id="vault-passphrase-save")
                yield Button("Cancel", id="vault-passphrase-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault-passphrase-cancel":
            self._clear_secrets()
            self.dismiss(None)
            return
        old_widget = self.query_one("#vault-old-passphrase", Input)
        new_widget = self.query_one("#vault-new-passphrase", Input)
        confirm_widget = self.query_one("#vault-confirm-passphrase", Input)
        old_passphrase, new_passphrase, confirmation = old_widget.value, new_widget.value, confirm_widget.value
        if not old_passphrase or len(new_passphrase) < self.minimum_length or new_passphrase != confirmation:
            self.query_one("#vault-passphrase-error", Static).update(
                "Passphrases are missing, too short, or do not match."
            )
            return
        request = VaultPassphraseChange(old_passphrase, new_passphrase)
        self._clear_secrets()
        self.dismiss(request)

    def _clear_secrets(self) -> None:
        for selector in ("#vault-old-passphrase", "#vault-new-passphrase", "#vault-confirm-passphrase"):
            self.query_one(selector, Input).value = ""

    def action_cancel(self) -> None:
        self._clear_secrets()
        self.dismiss(None)
