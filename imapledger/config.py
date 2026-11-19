from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from .policy import SpamPolicy

DEFAULT_MAX_MESSAGE_BYTES = 2_000_000
DEFAULT_MAX_BODY_CHARS = 20_000


class ConfigError(ValueError):
    pass


class ActionKind(str, Enum):
    KEEP = "keep"
    MOVE = "move"
    DELETE = "delete"


class AuthSource(str, Enum):
    PROMPT = "prompt"
    KEYRING = "keyring"
    VAULT = "vault"


@dataclass(frozen=True, slots=True)
class ImapAuthSettings:
    source: AuthSource = AuthSource.PROMPT

    def __post_init__(self) -> None:
        if not isinstance(self.source, AuthSource):
            try:
                object.__setattr__(self, "source", AuthSource(self.source))
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"unknown IMAP credential source: {self.source!r}") from exc


@dataclass(frozen=True, slots=True)
class MessageAction:
    action: ActionKind
    destination: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, ActionKind):
            try:
                object.__setattr__(self, "action", ActionKind(self.action))
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"unknown action: {self.action!r}") from exc
        if self.action is ActionKind.MOVE:
            if not isinstance(self.destination, str) or not self.destination.strip():
                raise ConfigError("move action requires a non-empty destination")
            if self.destination != self.destination.strip():
                raise ConfigError("action destination must not have leading or trailing whitespace")
        elif self.destination is not None:
            raise ConfigError(f"{self.action.value} action must not have a destination")


@dataclass(frozen=True, slots=True)
class SpamActions:
    spam: MessageAction = field(default_factory=lambda: MessageAction(ActionKind.DELETE))
    not_spam: MessageAction = field(default_factory=lambda: MessageAction(ActionKind.KEEP))
    review: MessageAction = field(default_factory=lambda: MessageAction(ActionKind.KEEP))

    def __post_init__(self) -> None:
        for name in ("spam", "not_spam", "review"):
            if not isinstance(getattr(self, name), MessageAction):
                raise ConfigError(f"spam.actions.{name} must be a message action")
        if self.not_spam.action is ActionKind.DELETE:
            raise ConfigError("delete is not supported for the not_spam outcome")
        if self.review.action is ActionKind.DELETE:
            raise ConfigError("delete is not supported for the review outcome")


@dataclass(frozen=True, slots=True)
class ImapSettings:
    host: str
    username: str
    port: int = 993
    auth: ImapAuthSettings = field(default_factory=ImapAuthSettings)

    def __post_init__(self) -> None:
        if not isinstance(self.auth, ImapAuthSettings):
            raise ConfigError("imap.auth must be an auth settings table")
        if not self.host.strip():
            raise ConfigError("host must not be empty")
        if not self.username.strip():
            raise ConfigError("username must not be empty")
        if not 1 <= self.port <= 65535:
            raise ConfigError("port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class SpamSettings:
    folders: tuple[str, ...]
    actions: SpamActions = field(default_factory=SpamActions)
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS
    policy: SpamPolicy = field(default_factory=SpamPolicy)
    trusted_authserv_ids: tuple[str, ...] = ()
    trusted_provider_headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.folders, (tuple, list)):
            raise ConfigError("spam.folders must be a non-empty array of folder names")
        folders = tuple(self.folders)
        object.__setattr__(self, "folders", folders)
        if not folders:
            raise ConfigError("spam.folders must not be empty")
        if any(not isinstance(folder, str) for folder in folders):
            raise ConfigError("spam.folders entries must be strings")
        if any(not folder.strip() for folder in folders):
            raise ConfigError("spam.folders entries must not be empty")
        if any(folder != folder.strip() for folder in folders):
            raise ConfigError("spam.folders entries must not have leading or trailing whitespace")
        if len(set(folders)) != len(folders):
            raise ConfigError("spam.folders must not contain duplicates")
        if self.max_message_bytes < 1:
            raise ConfigError("spam.max_message_bytes must be positive")
        if self.max_body_chars < 1:
            raise ConfigError("spam.max_body_chars must be positive")
        for outcome in ("spam", "not_spam", "review"):
            action = getattr(self.actions, outcome)
            if action.action is ActionKind.MOVE and action.destination in folders:
                raise ConfigError(f"spam.actions.{outcome} destination must not be a source folder")


@dataclass(frozen=True, slots=True)
class Settings:
    imap: ImapSettings
    spam: SpamSettings


def default_config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "imapledger" / "config.toml"


def _load_config_payload(path: Path | None = None) -> tuple[Path, dict[str, object]]:
    config_path = path or default_config_path()
    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {config_path}; run `imapledger init`") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read config {config_path}: {exc}") from exc
    return config_path, payload


def _parse_imap_auth_settings(value: object) -> ImapAuthSettings:
    if not isinstance(value, dict):
        raise ConfigError("imap.auth must be a table")
    unknown = set(value) - {"source"}
    if unknown:
        raise ConfigError(f"unknown key in imap.auth: {sorted(unknown)[0]}")
    try:
        source = AuthSource(value.get("source", AuthSource.PROMPT.value))
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(source.value for source in AuthSource)
        raise ConfigError(f"imap.auth.source must be one of: {allowed}") from exc
    return ImapAuthSettings(source)


def _parse_imap_settings(payload: dict[str, object]) -> ImapSettings:
    imap = payload.get("imap")
    if not isinstance(imap, dict):
        raise ConfigError("config requires an [imap] table")
    try:
        return ImapSettings(
            host=str(imap["host"]),
            username=str(imap["username"]),
            port=int(imap.get("port", 993)),
            auth=_parse_imap_auth_settings(imap.get("auth", {})),
        )
    except KeyError as exc:
        raise ConfigError(f"missing config key: {exc.args[0]}") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid config value: {exc}") from exc


def load_imap_settings(path: Path | None = None) -> ImapSettings:
    _, payload = _load_config_payload(path)
    return _parse_imap_settings(payload)


def load_settings(path: Path | None = None) -> Settings:
    _, payload = _load_config_payload(path)

    imap = payload.get("imap")
    spam = payload.get("spam")
    if not isinstance(imap, dict):
        raise ConfigError("config requires an [imap] table")
    if not isinstance(spam, dict):
        raise ConfigError("config requires a [spam] table")
    imap_settings = _parse_imap_settings(payload)
    if "threshold" in spam:
        warnings.warn(
            "spam.threshold is deprecated and ignored; configure named [spam.policy] thresholds instead",
            UserWarning,
            stacklevel=2,
        )

    if "folder" in spam and "folders" in spam:
        raise ConfigError("spam.folder and spam.folders cannot both be configured")
    if "folders" in spam:
        folders = _folder_tuple(spam["folders"])
    elif "folder" in spam:
        folder = spam["folder"]
        if not isinstance(folder, str):
            raise ConfigError("spam.folder must be a string")
        warnings.warn(
            "spam.folder is deprecated; use spam.folders",
            UserWarning,
            stacklevel=2,
        )
        folders = (folder,)
    else:
        raise ConfigError("config requires spam.folders")

    policy_payload = spam.get("policy", {})
    authentication = spam.get("authentication", {})
    provider = spam.get("provider", {})
    if not isinstance(policy_payload, dict):
        raise ConfigError("spam.policy must be a table")
    if not isinstance(authentication, dict):
        raise ConfigError("spam.authentication must be a table")
    if not isinstance(provider, dict):
        raise ConfigError("spam.provider must be a table")

    try:
        return Settings(
            imap=imap_settings,
            spam=SpamSettings(
                folders=folders,
                actions=_parse_spam_actions(spam.get("actions", {}), legacy_defaults="folder" in spam),
                max_message_bytes=int(spam.get("max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES)),
                max_body_chars=int(spam.get("max_body_chars", DEFAULT_MAX_BODY_CHARS)),
                policy=SpamPolicy(
                    legitimate_veto_at=float(policy_payload.get("legitimate_veto_at", 0.80)),
                    phishing_delete_at=float(policy_payload.get("phishing_delete_at", 0.90)),
                    identity_deception_at=float(policy_payload.get("identity_deception_at", 0.90)),
                    unsolicited_bulk_at=float(policy_payload.get("unsolicited_bulk_at", 0.92)),
                    delete_safe_at=float(policy_payload.get("delete_safe_at", 0.88)),
                    provider_junk_support_at=float(policy_payload.get("provider_junk_support_at", 0.80)),
                ),
                trusted_authserv_ids=_string_tuple(
                    authentication.get("trusted_authserv_ids", []), "spam.authentication.trusted_authserv_ids"
                ),
                trusted_provider_headers=_string_tuple(
                    provider.get("trusted_spam_headers", []), "spam.provider.trusted_spam_headers"
                ),
            ),
        )
    except KeyError as exc:
        raise ConfigError(f"missing config key: {exc.args[0]}") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid config value: {exc}") from exc


def _folder_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError("spam.folders must be an array of non-empty strings")
    if any(not isinstance(folder, str) for folder in value):
        raise ConfigError("spam.folders entries must be strings")
    return tuple(value)


def _parse_spam_actions(value: object, *, legacy_defaults: bool = False) -> SpamActions:
    if not isinstance(value, dict):
        raise ConfigError("spam.actions must be a table")
    unknown_outcomes = set(value) - {"spam", "not_spam", "review"}
    if unknown_outcomes:
        raise ConfigError(f"unknown spam action outcome: {sorted(unknown_outcomes)[0]}")
    defaults = SpamActions() if legacy_defaults else SpamActions(spam=MessageAction(ActionKind.KEEP))
    parsed: dict[str, MessageAction] = {}
    for outcome in ("spam", "not_spam", "review"):
        if outcome not in value:
            parsed[outcome] = getattr(defaults, outcome)
            continue
        table = value[outcome]
        if not isinstance(table, dict):
            raise ConfigError(f"spam.actions.{outcome} must be a table")
        unknown_keys = set(table) - {"action", "destination"}
        if unknown_keys:
            raise ConfigError(f"unknown key in spam.actions.{outcome}: {sorted(unknown_keys)[0]}")
        if "action" not in table:
            raise ConfigError(f"spam.actions.{outcome} requires an action")
        raw_action = table["action"]
        if not isinstance(raw_action, str):
            raise ConfigError(f"spam.actions.{outcome}.action must be a string")
        try:
            action = ActionKind(raw_action)
        except ValueError as exc:
            raise ConfigError(f"unknown action for spam.actions.{outcome}: {raw_action!r}") from exc
        if action is ActionKind.MOVE:
            if "destination" not in table:
                raise ConfigError(f"move action for spam.actions.{outcome} requires a destination")
            destination = table["destination"]
            if not isinstance(destination, str):
                raise ConfigError(f"spam.actions.{outcome}.destination must be a string")
        else:
            if "destination" in table:
                raise ConfigError(f"{action.value} action for spam.actions.{outcome} must not have a destination")
            destination = None
        parsed[outcome] = MessageAction(action=action, destination=destination)
    return SpamActions(**parsed)


def render_settings(settings: Settings) -> str:
    thresholds = settings.spam.policy.thresholds()
    lines = [
        "[imap]",
        f'host = "{_toml_string(settings.imap.host)}"',
        f"port = {settings.imap.port}",
        f'username = "{_toml_string(settings.imap.username)}"',
        "",
        "[imap.auth]",
        f'source = "{settings.imap.auth.source.value}"',
        "",
        "[spam]",
        f"folders = {_toml_string_array(settings.spam.folders)}",
        f"max_message_bytes = {settings.spam.max_message_bytes}",
        f"max_body_chars = {settings.spam.max_body_chars}",
    ]
    for outcome in ("spam", "not_spam", "review"):
        action = getattr(settings.spam.actions, outcome)
        lines.extend(("", f"[spam.actions.{outcome}]", f'action = "{action.action.value}"'))
        if action.destination is not None:
            lines.append(f'destination = "{_toml_string(action.destination)}"')
    lines.extend(("", "[spam.policy]"))
    lines.extend(f"{name} = {value}" for name, value in thresholds.items())
    lines.extend(
        (
            "",
            "[spam.authentication]",
            f"trusted_authserv_ids = {_toml_string_array(settings.spam.trusted_authserv_ids)}",
            "",
            "[spam.provider]",
            f"trusted_spam_headers = {_toml_string_array(settings.spam.trusted_provider_headers)}",
            "",
        )
    )
    return "\n".join(lines)


def write_settings(settings: Settings, path: Path | None = None, *, overwrite: bool = False) -> Path:
    config_path = path or default_config_path()
    if config_path.exists() and not overwrite:
        raise ConfigError(f"config already exists: {config_path}; use --force to overwrite")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        atomic_write_text(config_path, render_settings(settings))
    except AtomicWriteError as exc:
        raise ConfigError(f"could not write config {config_path}: {exc}") from exc
    try:
        config_path.chmod(0o600)
    except OSError:
        pass
    return config_path


def _string_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ConfigError(f"{key} must be an array of non-empty strings")
    return tuple(value)


def _toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _toml_string_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(f'"{_toml_string(value)}"' for value in values) + "]"
