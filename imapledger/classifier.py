from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .evidence import MailboxContext, MessageEvidence, build_jev_state, build_message_evidence
from .message import MailMessage

if TYPE_CHECKING:
    from pyjev.decisions import BundleDecision


SIGNAL_NAMES = (
    "unsolicited_bulk",
    "phishing_or_scam",
    "identity_deception",
    "legitimate_expected",
    "delete_safe",
)


@dataclass(frozen=True, slots=True)
class SemanticSpamSignals:
    unsolicited_bulk: float
    phishing_or_scam: float
    identity_deception: float
    legitimate_expected: float
    delete_safe: float


@dataclass(frozen=True, slots=True)
class SpamAssessment:
    signals: SemanticSpamSignals
    evidence: MessageEvidence
    model: str | None = None
    request_id: str | None = None


class SpamClassifier(Protocol):
    def assess(self, message: MailMessage) -> SpamAssessment: ...


class PyJevSpamClassifier:
    """Assess spam evidence with one version-controlled pyjev bundle."""

    def __init__(
        self,
        *,
        config: Path | None = None,
        context: MailboxContext | None = None,
        trusted_authserv_ids: tuple[str, ...] = (),
        trusted_provider_headers: tuple[str, ...] = (),
    ) -> None:
        self._config = config or Path(__file__).with_name("decisions.toml")
        self._context = context or MailboxContext()
        self._trusted_authserv_ids = trusted_authserv_ids
        self._trusted_provider_headers = trusted_provider_headers
        self._jev = None
        self._decision: BundleDecision | None = None

    def __enter__(self) -> PyJevSpamClassifier:
        from pyjev import Jev
        from pyjev.decisions import BundleDecision, NoulDecision, load_decision

        decision = load_decision("spam-evidence", config=self._config)
        if not isinstance(decision, BundleDecision):
            raise TypeError("spam-evidence decision must be a BundleDecision")
        if not set(SIGNAL_NAMES).issubset(decision.questions):
            raise ValueError("spam-evidence bundle is missing a required question")
        if any(not isinstance(decision.questions[name], NoulDecision) for name in SIGNAL_NAMES):
            raise TypeError("all spam-evidence questions must be Noul decisions")

        jev = Jev()
        jev.__enter__()
        self._decision = decision
        self._jev = jev
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        jev = self._jev
        self._jev = None
        self._decision = None
        if jev is not None:
            jev.__exit__(exc_type, exc, tb)

    def assess(self, message: MailMessage) -> SpamAssessment:
        if self._jev is None or self._decision is None:
            raise RuntimeError("classifier is not open")
        from pyjev.results import BundleResult, NoulResult

        evidence = build_message_evidence(
            message,
            context=self._context,
            trusted_authserv_ids=self._trusted_authserv_ids,
            trusted_provider_headers=self._trusted_provider_headers,
        )
        state = build_jev_state(evidence, message)
        result = self._jev.evaluate(self._decision, state=state)
        if not isinstance(result, BundleResult):
            raise TypeError("spam-evidence decision returned non-Bundle result")
        if not isinstance(result.answers, dict):
            raise TypeError("spam-evidence bundle returned invalid answers")

        values: dict[str, float] = {}
        for name in SIGNAL_NAMES:
            child = result.answers.get(name)
            if not isinstance(child, NoulResult):
                raise TypeError(f"spam-evidence question {name} returned non-Noul result")
            value = child.value
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"pyjev returned invalid probability for {name}")
            probability = float(value)
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise ValueError(f"pyjev returned probability for {name} outside [0, 1]")
            values[name] = probability

        return SpamAssessment(
            signals=SemanticSpamSignals(**values),
            evidence=evidence,
            model=result.model,
            request_id=result.request_id,
        )
