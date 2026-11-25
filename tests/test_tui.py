from __future__ import annotations

import asyncio
import threading
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
        self.folder_list_modes = []
        self.slow_delay = 0
        self.started = None
        self.release = None
        self.block_folder = None
        self.requested_folders = []
        self.count_total = 1
        self.fail_load = True

    def list_folders(self, *, include_counts=True):
        self.folder_list_modes.append(include_counts)
        return (
            FolderInfo("Spam", ".", frozenset(), self.count_total, 1),
            FolderInfo("INBOX", ".", frozenset(), self.count_total, 0),
        )

    def refresh_folder_counts(self, folders):
        return {folder: (1, 0) for folder in folders}

    def list_messages(self, folder, *, limit, offset):
        self.requested_folders.append(folder)
        if folder == "Fail" and self.fail_load:
            raise RuntimeError("sensitive server error")
        if folder == self.block_folder or folder == "Slow":
            if self.started is not None:
                self.started.set()
                self.release.wait(timeout=5)
            else:
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
        folder_list_calls_before_action = len(mail.folder_list_modes)
        await pilot.click("#apply")
        await pilot.pause()
        assert len(actions.calls) == 1
        assert actions.calls[0][1:] == (42, True)
        assert len(mail.folder_list_modes) == folder_list_calls_before_action
        assert app._rows[0][1].persisted_state is SpamOutcome.REVIEW
        assert "confirmed" in str(app.query_one("#activity", Static).render())
        assert "Action confirmed" in str(app.query_one("#status", Static).render())
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
    mail = FakeMailService()
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
        assert mail.folder_list_modes[0] is False
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


async def _slow_folder_keeps_message_pump_responsive():
    from textual.widgets import Static

    mail = FakeMailService()
    mail.started = threading.Event()
    mail.release = threading.Event()
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
        app.run_worker(app._select_folder("Slow"), group="folder-page", exclusive=True, exit_on_error=False)
        assert await asyncio.to_thread(mail.started.wait, 2)
        await pilot.press("?")
        assert "Keys:" in str(app.query_one("#status", Static).render())
        mail.release.set()
        await pilot.pause(0.1)


def test_slow_folder_worker_keeps_message_pump_responsive():
    asyncio.run(_slow_folder_keeps_message_pump_responsive())


async def _folder_worker_failure_is_recoverable():
    from textual.widgets import DataTable, Static

    mail = FakeMailService()
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
        await app._select_folder("INBOX.Sent")
        assert app._rows == [("INBOX.Sent", SUMMARY)]
        await app._select_folder("Fail")
        status = str(app.query_one("#status", Static).render())
        assert "RuntimeError" in status
        assert "sensitive server error" not in status
        assert app._selected_folder == "Fail"
        assert app._rows == []
        assert app.query_one("#messages", DataTable).row_count == 0
        assert "Press r to retry" in str(app.query_one("#message-detail", Static).render())
        mail.fail_load = False
        await pilot.press("r")
        await pilot.pause(0.1)
        assert app._rows == [("Fail", SUMMARY)]
        await pilot.press("?")
        assert "Keys:" in str(app.query_one("#status", Static).render())


def test_folder_worker_failure_does_not_terminate_tui():
    asyncio.run(_folder_worker_failure_is_recoverable())


def test_tui_resolves_credentials_before_textual_run(monkeypatch):
    from types import SimpleNamespace

    from imapledger.tui import app as tui_module

    def resolve_credential(settings):
        order.append("credential")
        return SimpleNamespace(password="secret")

    order = []

    class Service:
        def __init__(self, *args):
            pass

        def close(self):
            pass

    monkeypatch.setattr(tui_module, "load_settings", lambda path: order.append("settings") or SETTINGS)
    monkeypatch.setattr(tui_module, "load_rules", lambda *args, **kwargs: order.append("rules") or RuleSet())
    monkeypatch.setattr(tui_module, "resolve_credential", resolve_credential)
    monkeypatch.setattr(tui_module, "MailService", Service)
    monkeypatch.setattr(tui_module, "ActionService", Service)
    monkeypatch.setattr(tui_module, "AnalysisService", Service)
    monkeypatch.setattr(MailReviewApp, "run", lambda self: order.append("run"))

    tui_module.run(Path("unused.toml"))

    assert order == ["settings", "rules", "credential", "run"]


async def _folder_activation_clears_stale_rows_and_count_refresh_preserves_state():
    from types import SimpleNamespace

    from textual.widgets import DataTable, Label, ListView, Static

    mail = FakeMailService()
    mail.started = threading.Event()
    mail.release = threading.Event()
    mail.block_folder = "INBOX"
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
        await app._select_folder("INBOX.Sent")
        assert app._rows == [("INBOX.Sent", SUMMARY)]

        view = app.query_one("#folders", ListView)
        inbox_item = app._folder_item_by_name["INBOX"]
        view.index = 1
        view.focus()
        requested_before = list(mail.requested_folders)
        app.on_list_view_selected(SimpleNamespace(list_view=view, item=inbox_item))
        assert app._selected_folder == "INBOX"
        assert app._rows == []
        assert app.query_one("#messages", DataTable).row_count == 0
        assert "Loading INBOX" in str(app.query_one("#status", Static).render())
        assert await asyncio.to_thread(mail.started.wait, 2)

        mail.count_total = 17
        await app._refresh_counts()
        assert app._selected_folder == "INBOX"
        assert app._rows == []
        assert app.query_one("#messages", DataTable).row_count == 0
        assert "Loading INBOX" in str(app.query_one("#status", Static).render())
        assert app._folder_item_by_name["INBOX"] is inbox_item
        assert "17" in str(inbox_item.query_one(Label).render())
        assert view.index == 1
        assert app.focused is view
        assert mail.requested_folders == requested_before + ["INBOX"]

        mail.release.set()
        await pilot.pause(0.1)
        assert app._rows == [("INBOX", SUMMARY)]
        assert "INBOX: 1 messages loaded" in str(app.query_one("#status", Static).render())


def test_folder_activation_and_count_refresh_preserve_loading_state():
    asyncio.run(_folder_activation_clears_stale_rows_and_count_refresh_preserves_state())
