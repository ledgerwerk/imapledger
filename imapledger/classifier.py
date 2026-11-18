from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .message import MailMessage

if TYPE_CHECKING:
    from pyjev.decisions import NoulDecision


@dataclass(frozen=True, slots=True)
class SpamAssessment:
    probability: float
    model: str | None = None
    request_id: str | None = None


class SpamClassifier(Protocol):
    def assess(self, message: MailMessage) -> SpamAssessment: ...


class PyJevSpamClassifier:
    """Classify spam with a version-controlled pyjev Noul decision."""

    def __init__(self, *, config: Path | None = None) -> None:
        self._config = config or Path(__file__).with_name("decisions.toml")
        self._jev = None
        self._decision: NoulDecision | None = None

    def __enter__(self) -> PyJevSpamClassifier:
        from pyjev import Jev
        from pyjev.decisions import NoulDecision, load_decision

        decision = load_decision("spam", config=self._config)
        if not isinstance(decision, NoulDecision):
            raise TypeError("spam decision must be Noul")

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
        from pyjev import NoulResult

        result = self._jev.evaluate(self._decision, state=message.as_state())
        if not isinstance(result, NoulResult):
            raise TypeError("spam decision returned non-Noul result")
        probability = float(result.value)
        if not 0 <= probability <= 1:
            raise ValueError("pyjev returned spam probability outside [0, 1]")
        return SpamAssessment(
            probability=probability,
            model=result.model,
            request_id=result.request_id,
        )
