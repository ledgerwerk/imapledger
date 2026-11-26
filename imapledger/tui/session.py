from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any

from ..config import AuthSource, ConfigError, Settings, load_settings
from ..credentials import CredentialError, CredentialStatus, credential_status, resolve_credential
from ..mail_service import MailService
from ..routing_action_service import RoutingActionService
from ..routing_analysis_service import RoutingAnalysisService
from ..routing_config import RoutingConfigError, load_routing_rules, routing_rules_path_for_config
from ..routing_models import RuleSet as RoutingRuleSet
from ..routing_rule_service import RoutingRuleService


class SessionState(str, Enum):
    NO_CONFIG = "NO_CONFIG"
    CONFIG_ERROR = "CONFIG_ERROR"
    CREDENTIAL_MISSING = "CREDENTIAL_MISSING"
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"


class SessionError(RuntimeError):
    pass


class AppSession:
    """Own local settings and the connected services for one TUI session."""

    def __init__(
        self,
        config_path: Path,
        *,
        settings_loader: Callable[[Path], Settings] = load_settings,
        credential_resolver: Callable[..., Any] = resolve_credential,
        credential_status_resolver: Callable[..., CredentialStatus] = credential_status,
        mail_service_factory: Callable[..., Any] = MailService,
        analysis_service_factory: Callable[..., Any] = RoutingAnalysisService,
        action_service_factory: Callable[..., Any] = RoutingActionService,
        rule_service_factory: Callable[..., Any] = RoutingRuleService,
    ) -> None:
        self.config_path = Path(config_path)
        self._settings_loader = settings_loader
        self._credential_resolver = credential_resolver
        self._credential_status_resolver = credential_status_resolver
        self._mail_service_factory = mail_service_factory
        self._analysis_service_factory = analysis_service_factory
        self._action_service_factory = action_service_factory
        self._rule_service_factory = rule_service_factory
        self.settings: Settings | None = None
        self.credential: CredentialStatus | None = None
        self.credential_summary = "not inspected"
        self.routing_rules = RoutingRuleSet()
        self.routing_rule_service: RoutingRuleService | None = None
        self.mail_service: Any | None = None
        self.analysis_service: Any | None = None
        self.action_service: Any | None = None
        self.status = SessionState.NO_CONFIG
        self.error_type: str | None = None
        self.error_message: str | None = None
        self.rules_error_type: str | None = None
        self._password = ""

    @property
    def connected(self) -> bool:
        return self.status is SessionState.CONNECTED

    @property
    def password(self) -> str:
        return self._password

    def load_local(self) -> SessionState:
        self.close()
        self.error_type = None
        self.error_message = None
        self.rules_error_type = None
        self.credential = None
        self.settings = None
        self.credential_summary = "not inspected"
        self.routing_rules = RoutingRuleSet()
        self.routing_rule_service = None

        if not self.config_path.exists():
            self.status = SessionState.NO_CONFIG
            return self.status
        try:
            self.settings = self._settings_loader(self.config_path)
        except ConfigError as exc:
            self.status = SessionState.CONFIG_ERROR
            self.error_type = type(exc).__name__
            self.error_message = str(exc)
            return self.status

        self.routing_rule_service = self._rule_service_factory(routing_rules_path_for_config(self.config_path))
        try:
            self.routing_rules = load_routing_rules(routing_rules_path_for_config(self.config_path))
        except RoutingConfigError as exc:
            self.rules_error_type = type(exc).__name__
            self.routing_rules = RoutingRuleSet()

        if self.settings.imap.auth.source is AuthSource.PROMPT:
            self.credential_summary = "password requested at connect"
            self.status = SessionState.DISCONNECTED
            return self.status
        try:
            self.credential = self._credential_status_resolver(self.settings.imap)
        except CredentialError as exc:
            self.status = SessionState.CREDENTIAL_MISSING
            self.credential_summary = type(exc).__name__
            self.error_type = type(exc).__name__
            self.error_message = str(exc)
            return self.status

        if self.settings.imap.auth.source is AuthSource.KEYRING:
            if not self.credential.backend_available or not self.credential.available:
                self.status = SessionState.CREDENTIAL_MISSING
                self.credential_summary = self.credential.reason or "credential not available"
                return self.status
            self.credential_summary = f"configured ({self.credential.backend_name or 'OS keyring'})"
        elif self.credential.available is False:
            self.status = SessionState.CREDENTIAL_MISSING
            self.credential_summary = "vault or account credential not available"
            return self.status
        else:
            self.status = SessionState.DISCONNECTED
            self.credential_summary = "configured; unlock required at connect"
        return self.status

    def connect(self, secret: str | None = None) -> None:
        if self.settings is None:
            raise SessionError("valid local configuration is required before connecting")
        if self.connected:
            return
        self.status = SessionState.CONNECTING
        try:
            resolved = self._credential_resolver(
                self.settings.imap,
                prompt_secret=lambda _prompt: secret or "",
            )
            password = resolved.password
            rules_path = routing_rules_path_for_config(self.config_path)
            try:
                routing_rules = load_routing_rules(rules_path)
            except RoutingConfigError:
                routing_rules = RoutingRuleSet()
            mail_service = self._mail_service_factory(self.settings, password)
            action_service = None
            try:
                analysis_service = self._analysis_service_factory(self.settings, routing_rules)
                rule_service = self._rule_service_factory(rules_path)
                action_service = self._action_service_factory(
                    self.settings,
                    password,
                    routing_rules,
                    rules_provider=lambda: load_routing_rules(rules_path),
                )
            except Exception:
                mail_service.close()
                if action_service is not None and hasattr(action_service, "close"):
                    action_service.close()
                raise
        except Exception as exc:
            self.status = SessionState.DISCONNECTED
            self.error_type = type(exc).__name__
            self.error_message = str(exc)
            raise

        self._password = password
        self.mail_service = mail_service
        self.analysis_service = analysis_service
        self.action_service = action_service
        self.routing_rule_service = rule_service
        self.routing_rules = routing_rules
        self.error_type = None
        self.error_message = None
        self.status = SessionState.CONNECTED

    def disconnect(self) -> None:
        self.close()
        if self.settings is None:
            self.status = SessionState.NO_CONFIG
        elif self.settings.imap.auth.source is AuthSource.PROMPT:
            self.status = SessionState.DISCONNECTED
        elif self.credential is not None and self.credential.available is False:
            self.status = SessionState.CREDENTIAL_MISSING
        else:
            self.status = SessionState.DISCONNECTED

    def reload(self, config_path: Path | None = None) -> SessionState:
        if config_path is not None:
            self.config_path = Path(config_path)
        return self.load_local()

    def close(self) -> None:
        if self.mail_service is not None and hasattr(self.mail_service, "close"):
            self.mail_service.close()
        if self.action_service is not None and hasattr(self.action_service, "close"):
            self.action_service.close()
        self.mail_service = None
        self.analysis_service = None
        self.action_service = None
        self._password = ""
        if self.status is SessionState.CONNECTED or self.status is SessionState.CONNECTING:
            self.status = SessionState.DISCONNECTED
