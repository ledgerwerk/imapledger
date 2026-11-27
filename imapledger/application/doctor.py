from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..config import Settings
from ..mailbox import ScopedMailbox
from ..preflight import SourcePreflightResult, preflight_source


@dataclass(frozen=True, slots=True)
class DoctorRequest:
    folder: str
    destinations: tuple[str, ...] = ()
    requires_delete: bool = False
    deep_probe: bool = True


class DoctorOperation:
    """Perform a read-only mailbox and action-precondition diagnostic."""

    def __init__(self, settings: Settings, *, mailbox_factory: Callable[..., Any] = ScopedMailbox) -> None:
        self._settings = settings
        self._mailbox_factory = mailbox_factory

    def run(
        self,
        request: DoctorRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> SourcePreflightResult:
        return preflight_source(
            self._settings,
            request.folder,
            password=password,
            destinations=request.destinations,
            requires_delete=request.requires_delete,
            deep_probe=request.deep_probe,
            mailbox_factory=self._mailbox_factory,
            event_callback=event_callback,
        )
