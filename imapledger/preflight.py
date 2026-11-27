from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .mailbox import MailboxProbe


@dataclass(frozen=True, slots=True)
class SourcePreflightResult:
    folder: str
    opened: bool
    probe: MailboxProbe | None
    capabilities: frozenset[bytes]
    missing_capabilities: tuple[bytes, ...]
    destinations: tuple[tuple[str, bool | None], ...]
    errors: tuple[Exception, ...]

    @property
    def ok(self) -> bool:
        return (
            self.opened
            and not self.errors
            and not self.missing_capabilities
            and all(exists is True for _, exists in self.destinations)
        )


def preflight_source(
    settings: Settings,
    folder: str,
    *,
    password: str,
    destinations: tuple[str, ...],
    requires_delete: bool,
    uid_scope: Collection[int] | None = None,
    deep_probe: bool,
    mailbox_factory: Callable[..., Any],
    event_callback: Callable[[str], None] | None = None,
) -> SourcePreflightResult:
    required_capabilities = []
    if destinations:
        required_capabilities.append(b"MOVE")
    if requires_delete:
        required_capabilities.append(b"UIDPLUS")

    opened = False
    probe = None
    capabilities: frozenset[bytes] = frozenset()
    missing_capabilities: tuple[bytes, ...] = ()
    destination_results: list[tuple[str, bool | None]] = []
    errors: list[Exception] = []

    try:
        with mailbox_factory(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            allowed_destinations=destinations,
            allow_delete=requires_delete,
            max_message_bytes=settings.mail.max_message_bytes,
            max_body_chars=settings.mail.max_body_chars,
            uid_scope=uid_scope,
            event_callback=event_callback,
        ) as mailbox:
            opened = True
            capabilities = mailbox.capabilities
            missing_capabilities = tuple(
                capability for capability in required_capabilities if capability not in capabilities
            )
            if deep_probe:
                probe = mailbox.probe()
            for destination in destinations:
                try:
                    exists = mailbox.destination_exists(destination)
                except Exception as exc:
                    errors.append(exc)
                    destination_results.append((destination, None))
                else:
                    destination_results.append((destination, exists))
    except Exception as exc:
        errors.append(exc)

    return SourcePreflightResult(
        folder=folder,
        opened=opened,
        probe=probe,
        capabilities=capabilities,
        missing_capabilities=missing_capabilities,
        destinations=tuple(destination_results),
        errors=tuple(errors),
    )
