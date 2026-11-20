from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class ClassificationStateBackend(str, Enum):
    NONE = "none"
    IMAP_KEYWORDS = "imap-keywords"


class SpamOutcome(str, Enum):
    SPAM = "spam"
    NOT_SPAM = "not_spam"
    REVIEW = "review"


MARKER_VERSION = 1

OUTCOME_KEYWORDS = {
    SpamOutcome.SPAM: "imapledger-v1-spam",
    SpamOutcome.NOT_SPAM: "imapledger-v1-notspam",
    SpamOutcome.REVIEW: "imapledger-v1-review",
}

_KEYWORD_OUTCOMES = {keyword.casefold(): outcome for outcome, keyword in OUTCOME_KEYWORDS.items()}


@dataclass(frozen=True, slots=True)
class PersistedState:
    outcome: SpamOutcome | None
    keywords: frozenset[str]


class ClassificationStateConflict(ValueError):
    def __init__(self, keywords: Iterable[str]) -> None:
        self.keywords = tuple(sorted(keywords))
        super().__init__("multiple imapledger classification state keywords are present")


def keyword_for_outcome(outcome: SpamOutcome) -> str:
    return OUTCOME_KEYWORDS[outcome]


def all_state_keywords() -> tuple[str, ...]:
    return tuple(OUTCOME_KEYWORDS.values())


def _normalize_flag(flag: bytes | str) -> str:
    if isinstance(flag, bytes):
        flag = flag.decode("ascii", errors="replace")
    return flag.casefold()


def outcome_from_flags(flags: Iterable[bytes | str]) -> SpamOutcome | None:
    return validate_state_flags(flags).outcome


def validate_state_flags(flags: Iterable[bytes | str]) -> PersistedState:
    present: dict[SpamOutcome, str] = {}
    for flag in flags:
        outcome = _KEYWORD_OUTCOMES.get(_normalize_flag(flag))
        if outcome is not None:
            present[outcome] = OUTCOME_KEYWORDS[outcome]
    if len(present) > 1:
        raise ClassificationStateConflict(present.values())
    if not present:
        return PersistedState(outcome=None, keywords=frozenset())
    outcome, keyword = next(iter(present.items()))
    return PersistedState(outcome=outcome, keywords=frozenset({keyword}))
