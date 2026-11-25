from __future__ import annotations

from pathlib import Path

import pytest

from imapledger.classification_state import SpamOutcome
from imapledger.config import (
    ActionKind,
    ConfigError,
    ConfigStoreSettings,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    load_settings,
    write_settings,
)
from imapledger.settings_service import SettingsService


def _settings() -> Settings:
    return Settings(
        imap=ImapSettings(host="imap.example.org", username="user@example.org"),
        spam=SpamSettings(
            folders=("INBOX.Junk",),
            actions=SpamActions(
                spam=MessageAction(ActionKind.KEEP),
                not_spam=MessageAction(ActionKind.MOVE, "INBOX.NotSpam"),
                review=MessageAction(ActionKind.KEEP),
            ),
            trusted_authserv_ids=("mx.example.org",),
            trusted_provider_headers=("X-Spam-Flag",),
        ),
        config_store=ConfigStoreSettings("INBOX.Config"),
    )


def test_settings_service_updates_one_policy_and_preserves_unrelated_settings(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = _settings()
    write_settings(original, path)

    result = SettingsService(path).set_spam_action(
        SpamOutcome.SPAM,
        MessageAction(ActionKind.MOVE, "INBOX.Trash"),
    )
    reloaded = load_settings(path)

    assert result.previous_action == MessageAction(ActionKind.KEEP)
    assert reloaded.spam.actions.spam == MessageAction(ActionKind.MOVE, "INBOX.Trash")
    assert reloaded.spam.actions.not_spam == original.spam.actions.not_spam
    assert reloaded.spam.actions.review == original.spam.actions.review
    assert reloaded.spam.folders == original.spam.folders
    assert reloaded.spam.trusted_authserv_ids == original.spam.trusted_authserv_ids
    assert reloaded.spam.trusted_provider_headers == original.spam.trusted_provider_headers
    assert reloaded.config_store == original.config_store
    assert "password" not in path.read_text(encoding="utf-8").lower()


def test_invalid_policy_change_leaves_config_bytes_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    write_settings(_settings(), path)
    before = path.read_bytes()

    with pytest.raises(ConfigError, match="not_spam"):
        SettingsService(path).set_spam_action(
            SpamOutcome.NOT_SPAM,
            MessageAction(ActionKind.DELETE),
        )

    assert path.read_bytes() == before
