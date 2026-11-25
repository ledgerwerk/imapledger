from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any

from .classification_state import ClassificationStateBackend, all_state_keywords
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
    state_backend: ClassificationStateBackend = ClassificationStateBackend.NONE
    state_persistence_required: bool = False
    permanent_flags: frozenset[bytes] = frozenset()
    permanent_flags_known: bool = False
    keyword_persistence: str = "not-configured"
    unsupported_keywords: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            self.opened
            and not self.errors
            and not self.missing_capabilities
            and not (self.state_persistence_required and self.keyword_persistence == "unsupported")
            and all(exists is True for _, exists in self.destinations)
        )


def preflight_source(
    settings: Settings,
    folder: str,
    *,
    password: str,
    destinations: tuple[str, ...],
    requires_delete: bool,
    require_state_persistence: bool = False,
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

    state_backend = settings.spam.state.backend
    state_persistence_required = require_state_persistence
    keyword_persistence = "unknown" if state_backend is ClassificationStateBackend.IMAP_KEYWORDS else "not-configured"
    opened = False
    probe = None
    capabilities: frozenset[bytes] = frozenset()
    missing_capabilities: tuple[bytes, ...] = ()
    destination_results: list[tuple[str, bool | None]] = []
    errors: list[Exception] = []
    permanent_flags: frozenset[bytes] = frozenset()
    permanent_flags_known = False
    unsupported_keywords: tuple[str, ...] = ()

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
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            uid_scope=uid_scope,
            event_callback=event_callback,
        ) as mailbox:
            opened = True
            capabilities = mailbox.capabilities
            missing_capabilities = tuple(
                capability for capability in required_capabilities if capability not in capabilities
            )
            snapshot = mailbox.snapshot()
            permanent_flags = snapshot.permanent_flags
            permanent_flags_known = snapshot.permanent_flags_known
            if state_backend is ClassificationStateBackend.IMAP_KEYWORDS:
                if permanent_flags_known:
                    unsupported_keywords = tuple(
                        keyword for keyword in all_state_keywords() if not snapshot.supports_persistent_keyword(keyword)
                    )
                    keyword_persistence = "unsupported" if unsupported_keywords else "supported"
                else:
                    keyword_persistence = "unknown"
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
        state_backend=state_backend,
        state_persistence_required=state_persistence_required,
        permanent_flags=permanent_flags,
        permanent_flags_known=permanent_flags_known,
        keyword_persistence=keyword_persistence,
        unsupported_keywords=unsupported_keywords,
    )
