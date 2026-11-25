from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .mailbox import ClientFactory, MailboxItem, MessageSelection, MessageSort, ScopedMailbox
from .rules import MailRule, RuleSet


@dataclass(frozen=True, slots=True)
class RuleTestMatch:
    folder: str
    uid: int
    sender: str
    subject: str


@dataclass(frozen=True, slots=True)
class RuleTestResult:
    scanned: int
    matches: tuple[RuleTestMatch, ...]


class RuleTestService:
    def __init__(
        self,
        settings: Settings,
        password: str,
        *,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._settings = settings
        self._password = password
        self._client_factory = client_factory

    def test(self, rule: MailRule, *, limit: int = 50) -> RuleTestResult:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        RuleSet((rule,)).validate_source_folders(self._settings.spam.folders)
        selection = MessageSelection(limit=limit, sort=MessageSort.NEWEST)
        scanned = 0
        matches: list[RuleTestMatch] = []
        for folder in rule.source_folders:
            with ScopedMailbox(
                host=self._settings.imap.host,
                port=self._settings.imap.port,
                username=self._settings.imap.username,
                password=self._password,
                folder=folder,
                writable=False,
                max_message_bytes=self._settings.spam.max_message_bytes,
                max_body_chars=self._settings.spam.max_body_chars,
                client_factory=self._client_factory,
            ) as mailbox:
                for item in mailbox.iter_messages(selection):
                    scanned += 1
                    if item.message is not None and rule.match.matches(item.message):
                        matches.append(_match(folder, item))
        return RuleTestResult(scanned, tuple(matches))


def _match(folder: str, item: MailboxItem) -> RuleTestMatch:
    assert item.message is not None
    return RuleTestMatch(
        folder=folder,
        uid=item.uid,
        sender=item.message.sender,
        subject=item.message.subject,
    )
