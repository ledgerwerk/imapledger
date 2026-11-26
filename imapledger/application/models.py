from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OperationEventKind(str, Enum):
    STARTED = "started"
    PREFLIGHT = "preflight"
    ITEM_RESULT = "item_result"
    WARNING = "warning"
    INFO = "info"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class OperationEvent:
    operation_id: str
    kind: OperationEventKind
    message: str | None = None
    current: int | None = None
    total: int | None = None
    payload: object | None = None


@dataclass(frozen=True, slots=True)
class ErrorPresentation:
    code: str
    title: str
    detail: str
    hint: str | None = None
    retryable: bool = False
