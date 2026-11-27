from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .config import Settings
from .mailbox import (
    BrowserMailbox,
    ClientFactory,
    FolderCatalog,
    FolderClientFactory,
    FolderInfo,
    MailboxItem,
    MessageSort,
)
from .message import MailSummary

_LOG = logging.getLogger(__name__)


def _log_timing(operation: str, started: float, **fields: int) -> None:
    duration_ms = (time.monotonic() - started) * 1000
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    _LOG.debug("%s duration_ms=%.1f %s", operation, duration_ms, details)


@dataclass(frozen=True, slots=True)
class MessagePage:
    folder: str
    uidvalidity: int
    offset: int
    limit: int
    sort: MessageSort
    total: int
    items: tuple[MailSummary, ...]
    has_previous: bool
    has_next: bool


@dataclass(frozen=True, slots=True)
class MessageDetail:
    folder: str
    uidvalidity: int
    item: MailboxItem



class MailService:
    """Read-only folder and message browsing without classifier dependencies."""

    def __init__(
        self,
        settings: Settings,
        password: str,
        *,
        client_factory: ClientFactory | None = None,
        folder_client_factory: FolderClientFactory | None = None,
    ) -> None:
        self._settings = settings
        self._password = password
        self._client_factory = client_factory
        self._folder_client_factory = folder_client_factory

    def close(self) -> None:
        self._password = ""

    def list_folders(self, *, include_counts: bool = True) -> tuple[FolderInfo, ...]:
        started = time.monotonic()
        settings = self._settings
        with FolderCatalog(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            client_factory=self._folder_client_factory,
        ) as catalog:
            folders = catalog.list_folders(include_counts=include_counts)
        _log_timing("ui.folder_list", started, folder_count=len(folders))
        return folders

    def refresh_folder_counts(self, folders: tuple[str, ...]) -> dict[str, tuple[int, int]]:
        settings = self._settings
        with FolderCatalog(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            client_factory=self._folder_client_factory,
        ) as catalog:
            return catalog.folder_counts(folders)

    def list_messages(
        self,
        folder: str,
        *,
        limit: int = 50,
        offset: int = 0,
        sort: MessageSort = MessageSort.NEWEST,
    ) -> MessagePage:
        started = time.monotonic()
        if limit < 1 or offset < 0:
            raise ValueError("limit must be positive and offset must be non-negative")
        if not isinstance(sort, MessageSort):
            raise ValueError("sort must be a MessageSort")
        with self._open_browser(folder) as mailbox:
            items = mailbox.fetch_summary_page(offset=offset, limit=limit, sort=sort)
            total = mailbox.message_count
            uidvalidity = mailbox.uidvalidity
        page = MessagePage(
            folder=folder,
            uidvalidity=uidvalidity,
            offset=offset,
            limit=limit,
            sort=sort,
            total=total,
            items=items,
            has_previous=offset > 0,
            has_next=offset + len(items) < total,
        )
        _log_timing("ui.folder_page", started, message_count=len(page.items), page_size=limit)
        return page

    def get_message(self, folder: str, uid: int) -> MessageDetail:
        started = time.monotonic()
        with self._open_browser(folder) as mailbox:
            item = mailbox.fetch_uid(uid)
            uidvalidity = mailbox.uidvalidity
        detail = MessageDetail(folder=folder, uidvalidity=uidvalidity, item=item)
        _log_timing("ui.message_open", started, message_count=1)
        return detail


    def _open_browser(self, folder: str) -> BrowserMailbox:
        settings = self._settings
        return BrowserMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            folder=folder,
            max_message_bytes=settings.mail.max_message_bytes,
            max_body_chars=settings.mail.max_body_chars,
            client_factory=self._client_factory,
        )
