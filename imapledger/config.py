from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

DEFAULT_SPAM_THRESHOLD = 0.95
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
    threshold: float = DEFAULT_SPAM_THRESHOLD
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS

    def __post_init__(self) -> None:
        if not self.folder.strip():
            raise ConfigError("spam.folder must not be empty")
        if not 0 <= self.threshold <= 1:
            raise ConfigError("spam.threshold must be between 0 and 1")
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

    try:
        return Settings(
            imap=ImapSettings(
                host=str(imap["host"]),
                username=str(imap["username"]),
                port=int(imap.get("port", 993)),
            ),
            spam=SpamSettings(
                folder=str(spam["folder"]),
                threshold=float(spam.get("threshold", DEFAULT_SPAM_THRESHOLD)),
                max_message_bytes=int(spam.get("max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES)),
                max_body_chars=int(spam.get("max_body_chars", DEFAULT_MAX_BODY_CHARS)),
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
    text = (
        "[imap]\n"
        f'host = "{_toml_string(settings.imap.host)}"\n'
        f"port = {settings.imap.port}\n"
        f'username = "{_toml_string(settings.imap.username)}"\n'
        "\n[spam]\n"
        f'folder = "{_toml_string(settings.spam.folder)}"\n'
        f"threshold = {settings.spam.threshold}\n"
        f"max_message_bytes = {settings.spam.max_message_bytes}\n"
        f"max_body_chars = {settings.spam.max_body_chars}\n"
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


def _toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
