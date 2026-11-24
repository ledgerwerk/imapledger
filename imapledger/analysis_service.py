from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .classification_state import SpamOutcome
from .classifier import PyJevSpamClassifier, SemanticSpamSignals
from .config import MessageAction, Settings
from .evidence import MessageEvidence, build_message_evidence
from .message import MailMessage
from .policy import SpamVerdict
from .rules import RuleSet


@dataclass(frozen=True, slots=True)
class MessageAnalysis:
    folder: str
    uid: int
    persisted_outcome: SpamOutcome | None
    rule_id: str | None
    outcome: SpamOutcome | None
    verdict: SpamVerdict | None
    signals: SemanticSpamSignals | None
    reasons: tuple[str, ...]
    configured_action: MessageAction | None
    model: str | None = None
    request_id: str | None = None
    evidence: MessageEvidence | None = None
    decision_source: str = "none"


class AnalysisService:
    """Structured one-message analysis with persisted and deterministic fast paths."""

    def __init__(
        self,
        settings: Settings,
        rules: RuleSet,
        *,
        classifier_factory: Any = PyJevSpamClassifier,
    ) -> None:
        self._settings = settings
        self._rules = rules
        self._classifier_factory = classifier_factory

    def analyze(
        self,
        folder: str,
        message: MailMessage,
        *,
        persisted_outcome: SpamOutcome | None = None,
        reclassify: bool = False,
    ) -> MessageAnalysis:
        settings = self._settings
        if persisted_outcome is not None and not reclassify:
            action = getattr(settings.spam.actions, persisted_outcome.value)
            return MessageAnalysis(
                folder=folder,
                uid=message.uid,
                persisted_outcome=persisted_outcome,
                rule_id=None,
                outcome=persisted_outcome,
                verdict=None,
                signals=None,
                reasons=(),
                configured_action=action,
                decision_source="persisted-state",
            )

        rule = self._rules.first_match(folder, message)
        if rule is not None:
            return MessageAnalysis(
                folder=folder,
                uid=message.uid,
                persisted_outcome=persisted_outcome,
                rule_id=rule.id,
                outcome=None,
                verdict=None,
                signals=None,
                reasons=("deterministic-rule-match",),
                configured_action=rule.action,
                evidence=build_message_evidence(
                    message,
                    trusted_authserv_ids=settings.spam.trusted_authserv_ids,
                    trusted_provider_headers=settings.spam.trusted_provider_headers,
                ),
                decision_source="rule",
            )

        with self._classifier_factory(
            trusted_authserv_ids=settings.spam.trusted_authserv_ids,
            trusted_provider_headers=settings.spam.trusted_provider_headers,
        ) as classifier:
            assessment = classifier.assess(message)
        decision = settings.spam.policy.decide(assessment.signals, assessment.evidence)
        outcome = {
            SpamVerdict.DELETE: SpamOutcome.SPAM,
            SpamVerdict.KEEP: SpamOutcome.NOT_SPAM,
            SpamVerdict.REVIEW: SpamOutcome.REVIEW,
        }[decision.verdict]
        return MessageAnalysis(
            folder=folder,
            uid=message.uid,
            persisted_outcome=persisted_outcome,
            rule_id=None,
            outcome=outcome,
            verdict=decision.verdict,
            signals=assessment.signals,
            reasons=decision.reasons,
            configured_action=getattr(settings.spam.actions, outcome.value),
            model=getattr(assessment, "model", None),
            request_id=getattr(assessment, "request_id", None),
            evidence=assessment.evidence,
            decision_source="semantic",
        )
