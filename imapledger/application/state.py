from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..classification_state import ClassificationStateBackend, SpamOutcome, all_state_keywords, keyword_for_outcome
from ..config import Settings
from ..mailbox import ImapOperationError, MailboxSnapshot, ScopedMailbox


@dataclass(frozen=True, slots=True)
class StateResetRequest:
    folder: str | None = None
    uid: int | None = None
    reset_all: bool = False
    all_folders: bool = False
    apply: bool = False


@dataclass(frozen=True, slots=True)
class StateResetResult:
    folder: str
    markers: tuple[tuple[int, tuple[str, ...]], ...]
    apply: bool

    @property
    def targeted_uids(self) -> tuple[int, ...]:
        return tuple(uid for uid, _ in self.markers)

    @property
    def marker_count(self) -> int:
        return sum(len(keywords) for _, keywords in self.markers)


@dataclass(frozen=True, slots=True)
class StateFolderStatus:
    folder: str
    uidvalidity: int
    backend: ClassificationStateBackend
    keyword_persistence: str
    total: int
    spam: int
    notspam: int
    review: int
    unclassified: int
    conflicts: int


class StateOperation:
    """Inspect and reset only imapledger-owned classification keywords."""

    def __init__(self, settings: Settings, *, mailbox_factory: Callable[..., Any] = ScopedMailbox) -> None:
        self._settings = settings
        self._mailbox_factory = mailbox_factory

    def reset_folders(self, request: StateResetRequest) -> tuple[str, ...]:
        if request.uid is not None and request.reset_all:
            raise ValueError("--uid and --all cannot be combined")
        if request.all_folders and request.folder is not None:
            raise ValueError("--all-folders cannot be combined with --folder")
        if request.all_folders and not request.reset_all:
            raise ValueError("--all-folders requires --all")
        if not request.all_folders and request.folder is None:
            raise ValueError("specify --folder, or use --all-folders --all")
        if request.folder is not None and request.folder not in self._settings.spam.folders:
            raise ValueError(f"source folder is not configured: {request.folder}")
        if request.uid is None and not request.reset_all:
            raise ValueError("an unbounded reset requires --all")
        if request.uid is not None and request.uid < 1:
            raise ValueError("UID must be a positive integer")
        if request.all_folders:
            return self._settings.spam.folders
        return (request.folder,) if request.folder is not None else ()

    def status(
        self,
        folder: str,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> StateFolderStatus:
        if folder not in self._settings.spam.folders:
            raise ValueError(f"source folder is not configured: {folder}")
        with self._mailbox_factory(
            host=self._settings.imap.host,
            port=self._settings.imap.port,
            username=self._settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            max_message_bytes=self._settings.spam.max_message_bytes,
            max_body_chars=self._settings.spam.max_body_chars,
            event_callback=event_callback,
        ) as mailbox:
            snapshot: MailboxSnapshot = mailbox.snapshot()
            keywords = all_state_keywords()
            matches = {keyword: set(mailbox.search_keyword(keyword)) for keyword in keywords}
            unclassified = mailbox.candidate_uids(excluded_keywords=keywords)
        marked = set().union(*matches.values())
        conflicts = sum(sum(uid in matching for matching in matches.values()) > 1 for uid in marked)
        counts = {outcome: len(matches[keyword_for_outcome(outcome)]) for outcome in SpamOutcome}
        return StateFolderStatus(
            folder=folder,
            uidvalidity=snapshot.uidvalidity,
            backend=self._settings.spam.state.backend,
            keyword_persistence=_keyword_persistence(self._settings.spam.state.backend, snapshot),
            total=len(snapshot.uids),
            spam=counts[SpamOutcome.SPAM],
            notspam=counts[SpamOutcome.NOT_SPAM],
            review=counts[SpamOutcome.REVIEW],
            unclassified=len(unclassified),
            conflicts=conflicts,
        )

    def reset_folder(
        self,
        folder: str,
        request: StateResetRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> StateResetResult:
        if folder not in self.reset_folders(request):
            raise ValueError(f"folder is outside the selected reset scope: {folder}")
        with self._mailbox_factory(
            host=self._settings.imap.host,
            port=self._settings.imap.port,
            username=self._settings.imap.username,
            password=password,
            folder=folder,
            writable=request.apply,
            max_message_bytes=self._settings.spam.max_message_bytes,
            max_body_chars=self._settings.spam.max_body_chars,
            event_callback=event_callback,
        ) as mailbox:
            uid_keywords: dict[int, list[str]] = {}
            if request.uid is not None:
                uid_keywords[request.uid] = list(_present_state_keywords(mailbox.get_flags(request.uid)))
            else:
                for keyword in all_state_keywords():
                    for uid in mailbox.search_keyword(keyword):
                        uid_keywords.setdefault(uid, []).append(keyword)
            markers = tuple((uid, tuple(keywords)) for uid, keywords in sorted(uid_keywords.items()))
            if request.apply:
                for uid, keywords in markers:
                    for keyword in keywords:
                        mailbox.remove_keyword(uid, keyword)
                    remaining = _present_state_keywords(mailbox.get_flags(uid))
                    if remaining:
                        raise ImapOperationError(
                            operation="imap_verify_keyword",
                            message="classification state remains after reset",
                            folder=folder,
                            selector=", ".join(remaining),
                            uids=(uid,),
                        )
        return StateResetResult(folder, markers, request.apply)


def _present_state_keywords(flags: Iterable[bytes | str]) -> tuple[str, ...]:
    normalized = {
        flag.decode("ascii", errors="replace").casefold() if isinstance(flag, bytes) else flag.casefold()
        for flag in flags
    }
    return tuple(keyword for keyword in all_state_keywords() if keyword.casefold() in normalized)


def _keyword_persistence(backend: ClassificationStateBackend, snapshot: MailboxSnapshot) -> str:
    if backend is ClassificationStateBackend.NONE:
        return "NOT CONFIGURED"
    if not snapshot.permanent_flags_known:
        return "UNKNOWN"
    if all(snapshot.supports_persistent_keyword(keyword) for keyword in all_state_keywords()):
        return "OK"
    return "UNSUPPORTED"
