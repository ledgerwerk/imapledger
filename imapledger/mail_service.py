from __future__ import annotations

from dataclasses import dataclass

from .classification_state import PersistedState, SpamOutcome, keyword_for_outcome
from .config import Settings
from .mailbox import (
    ClientFactory,
    FolderCatalog,
    FolderClientFactory,
    FolderInfo,
    MailboxItem,
    MessageSort,
    ReadOnlyMailbox,
    ScopedMailbox,
)
from .message import MailSummary


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
    persisted_state: PersistedState | None


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

    def list_folders(self) -> tuple[FolderInfo, ...]:
        settings = self._settings
        with FolderCatalog(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            client_factory=self._folder_client_factory,
        ) as catalog:
            return catalog.list_folders()

    def list_messages(
        self,
        folder: str,
        *,
        limit: int = 50,
        offset: int = 0,
        sort: MessageSort = MessageSort.NEWEST,
    ) -> MessagePage:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be positive and offset must be non-negative")
        if not isinstance(sort, MessageSort):
            raise ValueError("sort must be a MessageSort")
        with self._open_mailbox(folder) as mailbox:
            snapshot = mailbox.snapshot()
            uids = mailbox.page_uids(offset=offset, limit=limit, sort=sort)
            items = mailbox.fetch_summaries(uids)
        return MessagePage(
            folder=folder,
            uidvalidity=snapshot.uidvalidity,
            offset=offset,
            limit=limit,
            sort=sort,
            total=len(snapshot.uids),
            items=items,
            has_previous=offset > 0,
            has_next=offset + len(items) < len(snapshot.uids),
        )

    def get_message(self, folder: str, uid: int) -> MessageDetail:
        with self._open_mailbox(folder) as mailbox:
            snapshot = mailbox.snapshot()
            item = mailbox.fetch_uid(uid)
            state = mailbox.classification_state(uid) if item.message is not None else None
        return MessageDetail(folder=folder, uidvalidity=snapshot.uidvalidity, item=item, persisted_state=state)

    def review_messages(self, *, limit: int = 50, offset: int = 0) -> tuple[tuple[str, MailSummary], ...]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be positive and offset must be non-negative")
        rows: list[tuple[str, MailSummary]] = []
        keyword = keyword_for_outcome(SpamOutcome.REVIEW)
        for folder in self._settings.spam.folders:
            with self._open_mailbox(folder) as mailbox:
                uids = sorted(mailbox.search_keyword(keyword), reverse=True)[offset : offset + limit]
                rows.extend((folder, summary) for summary in mailbox.fetch_summaries(uids))
        return tuple(sorted(rows, key=lambda row: (row[1].uid, row[0]), reverse=True))

    def _open_mailbox(self, folder: str) -> ReadOnlyMailbox:
        settings = self._settings
        scoped = ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            folder=folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            client_factory=self._client_factory,
        )
        return ReadOnlyMailbox(scoped)
