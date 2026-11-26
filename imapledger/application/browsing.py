from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..classification_state import SpamOutcome, keyword_for_outcome
from ..config import Settings
from ..mailbox import MessageSort, ScopedMailbox
from ..message import MailSummary


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    folder: str | None = None
    limit: int | None = 50
    offset: int = 0
    sort: MessageSort = MessageSort.NEWEST


@dataclass(frozen=True, slots=True)
class ReviewPage:
    folder: str | None
    limit: int | None
    offset: int
    sort: MessageSort
    total: int
    items: tuple[tuple[str, MailSummary], ...]
    has_previous: bool
    has_next: bool
    errors: tuple[tuple[str, Exception], ...] = ()


class ReviewOperation:
    """List review-marked message headers with the CLI's per-source paging semantics."""

    def __init__(self, settings: Settings, *, mailbox_factory: Callable[..., Any] = ScopedMailbox) -> None:
        self._settings = settings
        self._mailbox_factory = mailbox_factory

    def run(
        self,
        request: ReviewRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> ReviewPage:
        if request.limit is not None and request.limit < 1:
            raise ValueError("limit must be positive")
        if request.offset < 0:
            raise ValueError("offset must be non-negative")
        if not isinstance(request.sort, MessageSort):
            raise ValueError("sort must be a MessageSort")
        if request.folder is not None and request.folder not in self._settings.spam.folders:
            raise ValueError(f"source folder is not configured: {request.folder}")
        folders = (request.folder,) if request.folder is not None else self._settings.spam.folders
        rows: list[tuple[str, MailSummary]] = []
        errors: list[tuple[str, Exception]] = []
        total = 0
        has_next = False
        keyword = keyword_for_outcome(SpamOutcome.REVIEW)
        for folder in folders:
            try:
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
                    uids = sorted(mailbox.search_keyword(keyword), reverse=request.sort is MessageSort.NEWEST)
                    total += len(uids)
                    selected = uids[request.offset :]
                    if request.limit is not None:
                        selected = selected[: request.limit]
                    has_next = has_next or len(uids) > request.offset + len(selected)
                    for uid in selected:
                        message = mailbox.fetch_headers(uid)
                        if message is not None:
                            rows.append((folder, message))
            except Exception as exc:
                errors.append((folder, exc))
        rows.sort(key=lambda row: (row[1].uid, row[0]), reverse=request.sort is MessageSort.NEWEST)
        return ReviewPage(
            folder=request.folder,
            limit=request.limit,
            offset=request.offset,
            sort=request.sort,
            total=total,
            items=tuple(rows),
            has_previous=request.offset > 0,
            has_next=has_next,
            errors=tuple(errors),
        )
