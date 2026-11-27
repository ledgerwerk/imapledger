from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text
from vaultconfig.secrets import DEFAULT_MIN_PASSPHRASE_LENGTH

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from .routing_actions import RuleAction

DEFAULT_MAX_MESSAGE_BYTES = 2_000_000
DEFAULT_MAX_BODY_CHARS = 20_000
DEFAULT_CONFIG_STORE_MAX_FILE_BYTES = 1_048_576
MAX_CONFIG_STORE_FILE_BYTES = 10 * 1024 * 1024


class ConfigError(ValueError):
    pass


ActionKind = RuleAction


class AuthSource(str, Enum):
    PROMPT = "prompt"
    KEYRING = "keyring"
    VAULT = "vault"


@dataclass(frozen=True, slots=True)
class ImapAuthSettings:
    source: AuthSource = AuthSource.PROMPT
    vault_path: Path | None = None
    vault_min_passphrase_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH

    def __post_init__(self) -> None:
        minimum = self.vault_min_passphrase_length
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
            raise ConfigError("imap.auth.vault_min_passphrase_length must be a positive integer")
        if not isinstance(self.source, AuthSource):
            try:
                object.__setattr__(self, "source", AuthSource(self.source))
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"unknown IMAP credential source: {self.source!r}") from exc
        if self.vault_path is not None and not isinstance(self.vault_path, Path):
            if not isinstance(self.vault_path, str) or not self.vault_path.strip():
                raise ConfigError("imap.auth.vault_path must be a non-empty path")
            object.__setattr__(self, "vault_path", Path(self.vault_path))


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
class MailSettings:
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_message_bytes, bool)
            or not isinstance(self.max_message_bytes, int)
            or self.max_message_bytes < 1
        ):
            raise ConfigError("mail.max_message_bytes must be a positive integer")
        if isinstance(self.max_body_chars, bool) or not isinstance(self.max_body_chars, int) or self.max_body_chars < 1:
            raise ConfigError("mail.max_body_chars must be a positive integer")


@dataclass(frozen=True, slots=True)
class ConfigStoreSettings:
    folder: str
    max_file_bytes: int = DEFAULT_CONFIG_STORE_MAX_FILE_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.folder, str) or not self.folder:
            raise ConfigError("config_store.folder must be a non-empty string")
        if not self.folder.strip():
            raise ConfigError("config_store.folder must not be empty")
        if self.folder != self.folder.strip():
            raise ConfigError("config_store.folder must not have leading or trailing whitespace")
        if isinstance(self.max_file_bytes, bool) or not isinstance(self.max_file_bytes, int) or self.max_file_bytes < 1:
            raise ConfigError("config_store.max_file_bytes must be a positive integer")
        if self.max_file_bytes > MAX_CONFIG_STORE_FILE_BYTES:
            raise ConfigError("config_store.max_file_bytes must not exceed 10 MiB")


@dataclass(frozen=True, slots=True)
class ConfigStoreContext:
    imap: ImapSettings
    store: ConfigStoreSettings


@dataclass(frozen=True, slots=True)
class Settings:
    imap: ImapSettings
    mail: MailSettings = field(default_factory=MailSettings)
    config_store: ConfigStoreSettings | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mail, MailSettings):
            raise ConfigError("mail must be generic mail settings")
        if self.config_store is not None and not isinstance(self.config_store, ConfigStoreSettings):
            raise ConfigError("config_store must be config store settings")


def default_config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "imapledger" / "config.toml"


def _load_config_payload(
    path: Path | None = None, *, allow_legacy_spam: bool = False
) -> tuple[Path, dict[str, object]]:
    config_path = path or default_config_path()
    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {config_path}; run `imapledger init`") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read config {config_path}: {exc}") from exc
    if "spam" in payload and not allow_legacy_spam:
        raise ConfigError(
            "[spam] configuration was removed. Mail behavior now belongs in rules.toml. "
            "Run `imapledger rule migrate --preview` to inspect a migration, then "
            "`imapledger rule migrate --apply`."
        )
    return config_path, payload


@dataclass(frozen=True, slots=True)
class LegacySpamConfiguration:
    """Parsed legacy values for explicit rule migration only."""

    folders: tuple[str, ...]
    actions: Mapping[str, MessageAction]
    max_message_bytes: int
    max_body_chars: int
    policy: Mapping[str, float]
    trusted_authserv_ids: tuple[str, ...]
    trusted_provider_headers: tuple[str, ...]


def load_legacy_spam_configuration(path: Path | None = None) -> LegacySpamConfiguration | None:
    """Read the removed [spam] table for an explicit migration workflow."""
    _, payload = _load_config_payload(path, allow_legacy_spam=True)
    raw_spam = payload.get("spam")
    if raw_spam is None:
        return None
    if not isinstance(raw_spam, dict):
        raise ConfigError("legacy [spam] must be a table")

    if "folder" in raw_spam and "folders" in raw_spam:
        raise ConfigError("legacy spam.folder and spam.folders cannot both be configured")
    raw_folders = raw_spam.get("folders", [raw_spam["folder"]] if "folder" in raw_spam else [])
    if not isinstance(raw_folders, list) or any(
        not isinstance(folder, str) or not folder.strip() for folder in raw_folders
    ):
        raise ConfigError("legacy spam.folders must be an array of non-empty strings")
    folders = tuple(raw_folders)
    if any(folder != folder.strip() for folder in folders) or len(set(folders)) != len(folders):
        raise ConfigError("legacy spam.folders must contain unique names without surrounding whitespace")

    raw_actions = raw_spam.get("actions", {})
    if not isinstance(raw_actions, dict):
        raise ConfigError("legacy spam.actions must be a table")
    actions: dict[str, MessageAction] = {}
    for outcome, action_table in raw_actions.items():
        if outcome not in {"spam", "not_spam", "review"} or not isinstance(action_table, dict):
            raise ConfigError(f"invalid legacy spam action: {outcome!r}")
        if set(action_table) - {"action", "destination"} or "action" not in action_table:
            raise ConfigError(f"invalid legacy spam.actions.{outcome} table")
        try:
            actions[outcome] = MessageAction(ActionKind(action_table["action"]), action_table.get("destination"))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"invalid legacy spam.actions.{outcome}: {exc}") from exc

    raw_policy = raw_spam.get("policy", {})
    if not isinstance(raw_policy, dict):
        raise ConfigError("legacy spam.policy must be a table")
    policy: dict[str, float] = {}
    policy_keys = {
        "legitimate_veto_at",
        "phishing_delete_at",
        "identity_deception_at",
        "unsolicited_bulk_at",
        "delete_safe_at",
        "provider_junk_support_at",
    }
    if set(raw_policy) - policy_keys:
        raise ConfigError(f"unknown key in legacy spam.policy: {sorted(set(raw_policy) - policy_keys)[0]}")
    for name, value in raw_policy.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ConfigError(f"legacy spam.policy.{name} must be a probability")
        policy[name] = float(value)

    authentication = raw_spam.get("authentication", {})
    provider = raw_spam.get("provider", {})
    if not isinstance(authentication, dict) or not isinstance(provider, dict):
        raise ConfigError("legacy spam.authentication and spam.provider must be tables")
    mail = MailSettings(
        max_message_bytes=raw_spam.get("max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES),
        max_body_chars=raw_spam.get("max_body_chars", DEFAULT_MAX_BODY_CHARS),
    )
    return LegacySpamConfiguration(
        folders=folders,
        actions=actions,
        max_message_bytes=mail.max_message_bytes,
        max_body_chars=mail.max_body_chars,
        policy=policy,
        trusted_authserv_ids=_string_tuple(
            authentication.get("trusted_authserv_ids", []), "spam.authentication.trusted_authserv_ids"
        ),
        trusted_provider_headers=_string_tuple(
            provider.get("trusted_spam_headers", []), "spam.provider.trusted_spam_headers"
        ),
    )


def _parse_imap_auth_settings(value: object) -> ImapAuthSettings:
    if not isinstance(value, dict):
        raise ConfigError("imap.auth must be a table")
    unknown = set(value) - {"source", "vault_path", "vault_min_passphrase_length"}
    if unknown:
        raise ConfigError(f"unknown key in imap.auth: {sorted(unknown)[0]}")
    try:
        source = AuthSource(value.get("source", AuthSource.PROMPT.value))
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(source.value for source in AuthSource)
        raise ConfigError(f"imap.auth.source must be one of: {allowed}") from exc
    vault_path = value.get("vault_path")
    if vault_path is not None and (not isinstance(vault_path, str) or not vault_path.strip()):
        raise ConfigError("imap.auth.vault_path must be a non-empty path")
    return ImapAuthSettings(
        source,
        Path(vault_path) if vault_path is not None else None,
        value.get("vault_min_passphrase_length", DEFAULT_MIN_PASSPHRASE_LENGTH),
    )


def _parse_mail_settings(value: object) -> MailSettings:
    if not isinstance(value, dict):
        raise ConfigError("[mail] must be a table")
    unknown = set(value) - {"max_message_bytes", "max_body_chars"}
    if unknown:
        raise ConfigError(f"unknown key in [mail]: {sorted(unknown)[0]}")
    try:
        return MailSettings(
            max_message_bytes=value.get("max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES),
            max_body_chars=value.get("max_body_chars", DEFAULT_MAX_BODY_CHARS),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid [mail] value: {exc}") from exc


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


def _parse_config_store_settings(value: object) -> ConfigStoreSettings:
    if not isinstance(value, dict):
        raise ConfigError("config_store is not configured; add a [config_store] table to enable remote config commands")
    unknown = set(value) - {"folder", "max_file_bytes"}
    if unknown:
        raise ConfigError(f"unknown key in config_store: {sorted(unknown)[0]}")
    folder = value.get("folder")
    if not isinstance(folder, str):
        raise ConfigError("config_store.folder must be a string")
    max_file_bytes = value.get("max_file_bytes", DEFAULT_CONFIG_STORE_MAX_FILE_BYTES)
    return ConfigStoreSettings(folder=folder, max_file_bytes=max_file_bytes)


def load_config_store_context(path: Path | None = None) -> ConfigStoreContext:
    """Load only the IMAP connection and config-store settings."""
    _, payload = _load_config_payload(path)
    imap = _parse_imap_settings(payload)
    store = _parse_config_store_settings(payload.get("config_store"))
    return ConfigStoreContext(imap=imap, store=store)


def load_optional_config_store_settings(path: Path | None = None) -> ConfigStoreSettings | None:
    """Load the optional store settings without requiring spam configuration or IMAP access."""
    _, payload = _load_config_payload(path)
    if "config_store" not in payload:
        return None
    return _parse_config_store_settings(payload["config_store"])


def load_imap_settings(path: Path | None = None) -> ImapSettings:
    _, payload = _load_config_payload(path)
    return _parse_imap_settings(payload)


def load_settings(path: Path | None = None) -> Settings:
    _, payload = _load_config_payload(path)
    imap_settings = _parse_imap_settings(payload)
    mail_settings = _parse_mail_settings(payload["mail"]) if "mail" in payload else MailSettings()
    config_store_settings = _parse_config_store_settings(payload["config_store"]) if "config_store" in payload else None
    return Settings(imap=imap_settings, mail=mail_settings, config_store=config_store_settings)


def load_legacy_settings_for_migration(
    path: Path | None = None,
) -> tuple[Settings, LegacySpamConfiguration | None]:
    """Read settings while allowing the removed [spam] table for explicit migration only."""
    config_path, payload = _load_config_payload(path, allow_legacy_spam=True)
    legacy = load_legacy_spam_configuration(config_path)
    if "mail" in payload:
        mail_settings = _parse_mail_settings(payload["mail"])
    elif legacy is not None:
        mail_settings = MailSettings(legacy.max_message_bytes, legacy.max_body_chars)
    else:
        mail_settings = MailSettings()
    config_store = _parse_config_store_settings(payload["config_store"]) if "config_store" in payload else None
    settings = Settings(
        imap=_parse_imap_settings(payload),
        mail=mail_settings,
        config_store=config_store,
    )
    return settings, legacy


def render_settings(settings: Settings) -> str:
    lines = [
        "[imap]",
        f'host = "{_toml_string(settings.imap.host)}"',
        f"port = {settings.imap.port}",
        f'username = "{_toml_string(settings.imap.username)}"',
        "",
        "[imap.auth]",
        f'source = "{settings.imap.auth.source.value}"',
        f"vault_min_passphrase_length = {settings.imap.auth.vault_min_passphrase_length}",
    ]
    if settings.imap.auth.vault_path is not None:
        lines.append(f'vault_path = "{_toml_string(str(settings.imap.auth.vault_path))}"')
    if settings.mail != MailSettings():
        lines.extend(
            (
                "",
                "[mail]",
                f"max_message_bytes = {settings.mail.max_message_bytes}",
                f"max_body_chars = {settings.mail.max_body_chars}",
            )
        )
    if settings.config_store is not None:
        lines.extend(
            (
                "",
                "[config_store]",
                f'folder = "{_toml_string(settings.config_store.folder)}"',
                f"max_file_bytes = {settings.config_store.max_file_bytes}",
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


def write_auth_config(
    config_path: Path,
    *,
    source: AuthSource,
    vault_path: Path | None = None,
) -> None:
    """Atomically update auth settings without rewriting unrelated TOML."""
    config_path, _ = _load_config_payload(config_path)
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        raise ConfigError(f"could not read config {config_path}") from None
    newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    table_start = next((index for index, line in enumerate(lines) if line.strip() == "[imap.auth]"), None)
    source_line = f'source = "{source.value}"'
    vault_line = f'vault_path = "{_toml_string(str(vault_path))}"' if vault_path is not None else None

    if table_start is None:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        if lines and lines[-1].strip():
            lines.append(newline)
        lines.extend(("[imap.auth]" + newline, source_line + newline))
        if vault_line is not None:
            lines.append(vault_line + newline)
    else:
        table_end = next(
            (
                index
                for index in range(table_start + 1, len(lines))
                if lines[index].strip().startswith("[") and lines[index].strip().endswith("]")
            ),
            len(lines),
        )
        section = [lines[table_start]]
        source_found = False
        vault_found = False
        for line in lines[table_start + 1 : table_end]:
            key, separator, _ = line.lstrip().partition("=")
            key = key.strip()
            if not separator or key not in {"source", "vault_path"}:
                section.append(line)
                continue
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            if key == "source":
                section.append(source_line + ending)
                source_found = True
            elif vault_line is None:
                section.append(line)
            else:
                section.append(vault_line + ending)
                vault_found = True
        missing = []
        if not source_found:
            missing.append(source_line + newline)
        if vault_line is not None and not vault_found:
            missing.append(vault_line + newline)
        section[1:1] = missing
        lines[table_start:table_end] = section

    try:
        atomic_write_text(config_path, "".join(lines))
    except (AtomicWriteError, OSError):
        raise ConfigError("could not update config credential source") from None
    try:
        config_path.chmod(0o600)
    except OSError:
        pass


def _string_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ConfigError(f"{key} must be an array of non-empty strings")
    return tuple(value)


def _toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _toml_string_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(f'"{_toml_string(value)}"' for value in values) + "]"
