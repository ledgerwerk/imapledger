from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .classification_state import SpamOutcome
from .config import MessageAction, Settings, load_settings, replace_spam_action, write_settings


@dataclass(frozen=True, slots=True)
class PolicyMutationResult:
    settings: Settings
    outcome: SpamOutcome
    previous_action: MessageAction
    action: MessageAction


class SettingsService:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> Settings:
        return load_settings(self.path)

    def set_classification_action(self, outcome: SpamOutcome, action: MessageAction) -> PolicyMutationResult:
        current = self.load()
        previous = getattr(current.spam.actions, outcome.value)
        updated = replace_spam_action(current, outcome=outcome, action=action)
        if updated != current:
            write_settings(updated, self.path, overwrite=True)
        return PolicyMutationResult(updated, outcome, previous, action)

    def set_spam_action(self, outcome: SpamOutcome, action: MessageAction) -> PolicyMutationResult:
        return self.set_classification_action(outcome, action)
