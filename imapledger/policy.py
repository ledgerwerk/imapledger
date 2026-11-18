from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from .classifier import SemanticSpamSignals
from .evidence import MessageEvidence


class SpamVerdict(str, Enum):
    DELETE = "delete"
    KEEP = "keep"
    REVIEW = "review"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    verdict: SpamVerdict
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SpamPolicy:
    legitimate_veto_at: float = 0.80
    phishing_delete_at: float = 0.90
    identity_deception_at: float = 0.90
    unsolicited_bulk_at: float = 0.92
    delete_safe_at: float = 0.88
    provider_junk_support_at: float = 0.80

    def __post_init__(self) -> None:
        for name, threshold in self.thresholds().items():
            invalid = isinstance(threshold, bool) or not isinstance(threshold, (int, float))
            invalid = invalid or not math.isfinite(threshold) or not 0 <= threshold <= 1
            if invalid:
                raise ValueError(f"spam policy {name} must be between 0 and 1")

    def thresholds(self) -> dict[str, float]:
        return {
            "legitimate_veto_at": self.legitimate_veto_at,
            "phishing_delete_at": self.phishing_delete_at,
            "identity_deception_at": self.identity_deception_at,
            "unsolicited_bulk_at": self.unsolicited_bulk_at,
            "delete_safe_at": self.delete_safe_at,
            "provider_junk_support_at": self.provider_junk_support_at,
        }

    def decide(self, signals: SemanticSpamSignals, evidence: MessageEvidence) -> PolicyDecision:
        for name in (
            "unsolicited_bulk",
            "phishing_or_scam",
            "identity_deception",
            "legitimate_expected",
            "delete_safe",
        ):
            value = getattr(signals, name)
            invalid = isinstance(value, bool) or not isinstance(value, (int, float))
            invalid = invalid or not math.isfinite(value) or not 0 <= value <= 1
            if invalid:
                raise ValueError(f"spam signal {name} must be a finite probability")

        if signals.legitimate_expected >= self.legitimate_veto_at:
            return PolicyDecision(SpamVerdict.KEEP, ("strong-legitimate-or-expected",))
        if signals.phishing_or_scam >= self.phishing_delete_at:
            return PolicyDecision(SpamVerdict.DELETE, ("strong-phishing-or-scam",))
        if (
            signals.identity_deception >= self.identity_deception_at
            and signals.delete_safe >= self.provider_junk_support_at
        ):
            return PolicyDecision(SpamVerdict.DELETE, ("identity-deception", "delete-safe-corroboration"))
        if signals.unsolicited_bulk >= self.unsolicited_bulk_at and signals.delete_safe >= self.delete_safe_at:
            return PolicyDecision(SpamVerdict.DELETE, ("unsolicited-bulk", "delete-safe-corroboration"))
        if (
            evidence.provider.trusted_spam
            and signals.delete_safe >= self.provider_junk_support_at
            and signals.legitimate_expected < 0.50
        ):
            return PolicyDecision(SpamVerdict.DELETE, ("trusted-provider-junk", "semantic-support"))
        if evidence.provider.spam_marker or evidence.provider.subject_spam_marker:
            return PolicyDecision(SpamVerdict.REVIEW, ("provider-marker-needs-corroboration",))
        return PolicyDecision(SpamVerdict.REVIEW, ("insufficient-evidence",))
