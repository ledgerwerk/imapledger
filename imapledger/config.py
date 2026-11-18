from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
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


@dataclass(frozen=True, slots=True)
class ImapSettings:
    host: str
    username: str
    port: int = 993

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ConfigError("host must not be empty")
        if not self.username.strip():
            raise ConfigError("username must not be empty")
        if not 1 <= self.port <= 65535:
            raise ConfigError("port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class SpamSettings:
    folder: str
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS
    policy: SpamPolicy = field(default_factory=SpamPolicy)
    trusted_authserv_ids: tuple[str, ...] = ()
    trusted_provider_headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.folder.strip():
            raise ConfigError("spam.folder must not be empty")
        if self.max_message_bytes < 1:
            raise ConfigError("spam.max_message_bytes must be positive")
        if self.max_body_chars < 1:
            raise ConfigError("spam.max_body_chars must be positive")


@dataclass(frozen=True, slots=True)
class Settings:
    imap: ImapSettings
    spam: SpamSettings


def default_config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "imapledger" / "config.toml"


def load_settings(path: Path | None = None) -> Settings:
    config_path = path or default_config_path()
    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {config_path}; run `imapledger init`") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read config {config_path}: {exc}") from exc

    imap = payload.get("imap")
    spam = payload.get("spam")
    if not isinstance(imap, dict):
        raise ConfigError("config requires an [imap] table")
    if not isinstance(spam, dict):
        raise ConfigError("config requires a [spam] table")
    if "threshold" in spam:
        warnings.warn(
            "spam.threshold is deprecated and ignored; configure named [spam.policy] thresholds instead",
            UserWarning,
            stacklevel=2,
        )

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
            imap=ImapSettings(
                host=str(imap["host"]),
                username=str(imap["username"]),
                port=int(imap.get("port", 993)),
            ),
            spam=SpamSettings(
                folder=str(spam["folder"]),
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


def write_settings(settings: Settings, path: Path | None = None, *, overwrite: bool = False) -> Path:
    config_path = path or default_config_path()
    if config_path.exists() and not overwrite:
        raise ConfigError(f"config already exists: {config_path}; use --force to overwrite")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    thresholds = settings.spam.policy.thresholds()
    text = (
        "[imap]\n"
        f'host = "{_toml_string(settings.imap.host)}"\n'
        f"port = {settings.imap.port}\n"
        f'username = "{_toml_string(settings.imap.username)}"\n'
        "\n[spam]\n"
        f'folder = "{_toml_string(settings.spam.folder)}"\n'
        f"max_message_bytes = {settings.spam.max_message_bytes}\n"
        f"max_body_chars = {settings.spam.max_body_chars}\n"
        "\n[spam.policy]\n"
        + "".join(f"{name} = {value}\n" for name, value in thresholds.items())
        + "\n[spam.authentication]\n"
        + f"trusted_authserv_ids = {_toml_string_array(settings.spam.trusted_authserv_ids)}\n"
        + "\n[spam.provider]\n"
        + f"trusted_spam_headers = {_toml_string_array(settings.spam.trusted_provider_headers)}\n"
    )
    try:
        atomic_write_text(config_path, text)
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
