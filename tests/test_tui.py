from __future__ import annotations

import asyncio
import time
from pathlib import Path

from imapledger.action_service import ActionReceipt
from imapledger.analysis_service import MessageAnalysis
from imapledger.classification_state import SpamOutcome
from imapledger.config import ActionKind, ImapSettings, MessageAction, Settings, SpamActions, SpamSettings
from imapledger.mail_service import MessageDetail, MessagePage
from imapledger.mailbox import FolderInfo, MailboxItem, MessageSort
from imapledger.message import MailSummary, parse_message
from imapledger.policy import SpamVerdict
from imapledger.rules import RuleSet
from imapledger.tui.app import MailReviewApp

SETTINGS = Settings(
    imap=ImapSettings(host="imap.example.org", username="user@example.org"),
    spam=SpamSettings(
        folders=("Spam",),
        actions=SpamActions(
            spam=MessageAction(ActionKind.KEEP),
            not_spam=MessageAction(ActionKind.KEEP),
            review=MessageAction(ActionKind.KEEP),
        ),
    ),
)
MESSAGE = parse_message(9, b"From: sender@example.org\r\nSubject: Hello\r\n\r\nVisible text", max_body_chars=100)
SUMMARY = MailSummary(9, MESSAGE.sender, MESSAGE.subject, MESSAGE.date, MESSAGE.message_id, 50, frozenset(), None)


class FakeMailService:
    def __init__(self):
        self.closed = False
        self.slow_delay = 0

    def list_folders(self):
        return (FolderInfo("Spam", ".", frozenset(), 1, 1), FolderInfo("INBOX", ".", frozenset(), 1, 0))

    def list_messages(self, folder, *, limit, offset):
        if folder == "Slow":
            time.sleep(self.slow_delay)
        return MessagePage(folder, 42, offset, limit, 1, MessageSort.NEWEST, (SUMMARY,), False, False)

    def review_messages(self, *, limit, offset):
        return (("Spam", SUMMARY),)

    def get_message(self, folder, uid):
        return MessageDetail(folder, 42, MailboxItem(uid, message=MESSAGE), None)

    def close(self):
        self.closed = True


class FakeAnalysisService:
    def analyze(self, folder, message, **kwargs):
        return MessageAnalysis(
            folder=folder,
            uid=message.uid,
            persisted_outcome=kwargs.get("persisted_outcome"),
            rule_id=None,
            outcome=SpamOutcome.REVIEW,
            verdict=SpamVerdict.REVIEW,
            signals=None,
            reasons=("needs-review",),
            configured_action=SETTINGS.spam.actions.review,
            decision_source="semantic",
        )


class FakeActionService:
    def __init__(self):
        self.calls = []
        self.fail = False

    def apply(self, analysis, *, uidvalidity, confirmed_by_user):
        self.calls.append((analysis, uidvalidity, confirmed_by_user))
        return ActionReceipt(
            folder=analysis.folder,
            uidvalidity=uidvalidity,
            uid=analysis.uid,
            requested_action=analysis.configured_action,
            outcome=analysis.outcome.value,
            decision_source=analysis.decision_source,
            applied=not self.fail,
            confirmed=not self.fail,
            detail="fake failure" if self.fail else None,
        )


async def _browse_classify_apply():
    from textual.widgets import Static

    mail = FakeMailService()
    actions = FakeActionService()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=actions,
    )

    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        assert str(app.query_one("#workspace").styles.layout).strip("<>") == "horizontal"
        await app._select_folder("Spam")
        assert len(app._rows) == 1
        await app._open_message("Spam", 9)
        assert "Visible text" in str(app.query_one("#message-detail", Static).render())
        assert app._analysis is None
        await pilot.press("c")
        await pilot.pause()
        assert app._analysis is not None
        await pilot.press("a")
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause()
        assert len(actions.calls) == 1
        assert actions.calls[0][1:] == (42, True)
        assert "confirmed" in str(app.query_one("#activity", Static).render())
        assert "messages loaded" in str(app.query_one("#status", Static).render())
        actions.fail = True
        await app._open_message("Spam", 9)
        await pilot.press("c")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause()
        activity = str(app.query_one("#activity", Static).render())
        assert "not confirmed" in activity
        assert "fake failure" in activity

    assert mail.closed


async def _review_and_narrow():
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=FakeActionService(),
    )

    async with app.run_test(size=(60, 20)) as pilot:
        await pilot.pause()
        assert str(app.query_one("#workspace").styles.layout).strip("<>") == "vertical"
        await app._select_folder("Review")
        assert app._rows == [("Spam", SUMMARY)]
        await pilot.pause()
        assert app.size.width == 60


async def _stale_folder_response_is_ignored():
    mail = FakeMailService()
    mail.slow_delay = 0.05
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=FakeActionService(),
    )

    async with app.run_test(size=(60, 20)) as pilot:
        await pilot.pause()
        slow_request = asyncio.create_task(app._select_folder("Slow"))
        await asyncio.sleep(0.005)
        await app._select_folder("INBOX")
        await slow_request
        assert app._rows[0][0] == "INBOX"


def test_tui_ignores_stale_folder_responses():
    asyncio.run(_stale_folder_response_is_ignored())


def test_tui_browse_read_classify_and_apply_in_activity():
    asyncio.run(_browse_classify_apply())


def test_tui_review_view_and_narrow_terminal_render():
    asyncio.run(_review_and_narrow())
