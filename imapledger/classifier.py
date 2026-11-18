from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .message import MailMessage


class SpamClassifier(Protocol):
    def probability(self, message: MailMessage) -> float: ...


class PyJevSpamClassifier:
    """Classify spam with a version-controlled pyjev Noul decision."""

    def __init__(self, *, config: Path | None = None) -> None:
        self._config = config or Path(__file__).with_name("decisions.toml")
        self._jev = None

    def __enter__(self) -> PyJevSpamClassifier:
        from pyjev import Jev

        self._jev = Jev()
        self._jev.__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        jev = self._jev
        self._jev = None
        if jev is not None:
            jev.__exit__(exc_type, exc, tb)

    def probability(self, message: MailMessage) -> float:
        if self._jev is None:
            raise RuntimeError("classifier is not open")
        result = self._jev.decide("spam", state=message.as_state(), config=self._config)
        value = float(result.value)
        if not 0 <= value <= 1:
            raise ValueError(f"pyjev returned invalid spam probability: {value}")
        return value
