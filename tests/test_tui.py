from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from pathlib import Path

from imapledger.action_service import ActionReceipt
from imapledger.analysis_service import MessageAnalysis
from imapledger.classification_state import SpamOutcome
from imapledger.config import ActionKind, ImapSettings, MessageAction, Settings, SpamActions, SpamSettings
from imapledger.image_analysis import ImageAnalysisReport, ImageAssessment, ImageRecommendation
from imapledger.mail_service import MessageDetail, MessagePage
from imapledger.mailbox import FolderInfo, MailboxItem, MessageSort
from imapledger.message import MailImage, MailSummary, RemoteImageRef, parse_message
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


class FakeImageAnalysisService:
    def __init__(self, *, block_first: bool = False):
        self.calls = []
        self.block_first = block_first
        self.started = threading.Event()
        self.release = threading.Event()

    def analyze(self, message):
        self.calls.append(message.uid)
        if self.block_first and len(self.calls) == 1:
            self.started.set()
            self.release.wait(timeout=3)
        assessment = ImageAssessment(
            index=1,
            role="product_or_offer",
            role_confidence=0.91,
            importance_score=1.2,
            importance_confidence=0.86,
            text_insufficient_probability=0.18,
            actionable_information_probability=0.06,
            interest_dependent_probability=0.92,
            recommendation=ImageRecommendation.OPTIONAL_IF_INTERESTED,
            model="fake-model",
            request_id=f"request-{message.uid}",
        )
        return ImageAnalysisReport(
            embedded_total=message.image_count,
            analyzed=1,
            skipped=0,
            remote_total=message.remote_image_count,
            assessments=(assessment,),
        )


def _message_with_images(uid: int):
    image = MailImage(
        index=1,
        content_type="image/png",
        filename="",
        content_id=f"image-{uid}",
        disposition="inline",
        data=b"fake image bytes",
        size_bytes=16,
        classifiable=True,
    )
    remote = RemoteImageRef(1, f"https://tracking.example/image?token=secret-{uid}", "tracking.example", "shoe")
    return replace(MESSAGE, uid=uid, images=(image,), remote_images=(remote,))


class ImageMailService(FakeMailService):
    def __init__(self, messages):
        super().__init__()
        self.messages = messages
        self.uidvalidity = 42

    def get_message(self, folder, uid):
        return MessageDetail(folder, self.uidvalidity, MailboxItem(uid, message=self.messages[uid]), None)


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
        assert "Visible text" in str(app.query_one("#message-detail").query_one(Static).render())
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

    from imapledger.tui.app import HelpScreen

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
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        mail.release.set()
        await pilot.pause(0.1)


def test_slow_folder_worker_keeps_message_pump_responsive():
    asyncio.run(_slow_folder_keeps_message_pump_responsive())


async def _folder_worker_failure_is_recoverable():
    from textual.widgets import DataTable, Static

    from imapledger.tui.app import HelpScreen

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
        assert "Press r to retry" in str(app.query_one("#message-detail").query_one(Static).render())
        mail.fail_load = False
        await pilot.press("r")
        await pilot.pause(0.1)
        assert app._rows == [("Fail", SUMMARY)]
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")


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


async def _pane_navigation_and_help():
    from textual.widgets import DataTable, ListView

    from imapledger.tui.app import HelpScreen

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
        app._populate_rows((("Spam", SUMMARY), ("INBOX", SUMMARY)))
        folders = app.query_one("#folders", ListView)
        table = app.query_one("#messages", DataTable)
        folders.index = 0
        folders.focus()
        await pilot.press("left")
        assert app.focused is folders
        await pilot.press("right")
        assert app.focused is table
        await pilot.press("right")
        assert app.focused is app.query_one("#message-detail")
        await pilot.press("right")
        assert app.focused is app.query_one("#message-detail")
        await pilot.press("left")
        assert app.focused is table
        await pilot.press("L")
        assert app.focused is app.query_one("#message-detail")
        await pilot.press("H")
        assert app.focused is table
        await pilot.press("tab")
        assert app.focused is app.query_one("#message-detail")
        await pilot.press("tab")
        assert app.focused is folders
        await pilot.press("shift+tab")
        assert app.focused is app.query_one("#message-detail")

        table.focus()
        await pilot.press("j")
        assert table.cursor_row == 1
        await pilot.press("k")
        assert table.cursor_row == 0
        await pilot.press("G")
        assert table.cursor_row == 1
        await pilot.press("g")
        assert table.cursor_row == 0

        folders.focus()
        await pilot.press("j")
        assert folders.index == 1
        await pilot.press("k")
        assert folders.index == 0

        detail = app.query_one("#message-detail")
        detail.update("\n".join(f"line {index}" for index in range(40)))
        detail.focus()
        await pilot.pause()
        await pilot.press("G")
        assert detail.scroll_y > 0
        await pilot.press("g")
        assert detail.scroll_y == 0

        await pilot.press("h")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        assert "privacy-sensitive" in str(app.screen.query_one("#help-scroll").children[0].render())
        assert app.size == (60, 20)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)
        await pilot.press("h")
        await pilot.pause()
        await pilot.press("q")
        assert not isinstance(app.screen, HelpScreen)


def test_tui_focus_navigation_and_help_at_narrow_size():
    asyncio.run(_pane_navigation_and_help())


async def _mouse_focus_uses_current_pane():
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=FakeActionService(),
    )
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        app._populate_rows((("Spam", SUMMARY), ("INBOX", SUMMARY)))
        table = app.query_one("#messages")
        assert await pilot.click("#messages")
        await pilot.pause()
        assert app.focused is table
        await pilot.press("right")
        assert app.focused is app.query_one("#message-detail")
        await pilot.press("left")
        assert app.focused is table


def test_mouse_focus_drives_pane_navigation():
    asyncio.run(_mouse_focus_uses_current_pane())


async def _image_analysis_is_explicit_cached_and_presented_separately():
    from textual.widgets import Static

    mail = ImageMailService({9: _message_with_images(9), 10: _message_with_images(10)})
    image_service = FakeImageAnalysisService()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=FakeActionService(),
        image_analysis_service=image_service,
    )
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        await app._open_message("Spam", 9)
        panel = str(app.query_one("#visual-analysis", Static).render())
        assert "Images: 1 embedded (1 classifiable), 1 remote" in panel
        assert "not run. Press i" in panel
        assert "Remote images were not loaded for privacy" in panel
        assert "secret-9" not in panel
        assert image_service.calls == []

        await pilot.press("i")
        await pilot.pause(0.1)
        assert image_service.calls == [9]
        assert "OPTIONAL IF INTERESTED" in str(app.query_one("#visual-analysis", Static).render())
        assert "Interest-dependent: 0.92" in str(app.query_one("#visual-analysis", Static).render())

        await app._open_message("Spam", 10)
        await app._open_message("Spam", 9)
        await pilot.press("i")
        assert image_service.calls == [9]
        assert "Using cached visual image analysis" in str(app.query_one("#status", Static).render())

        mail.uidvalidity = 43
        await app._open_message("Spam", 9)
        await pilot.press("i")
        await pilot.pause(0.1)
        assert image_service.calls == [9, 9]


def test_image_analysis_is_explicit_cached_and_separate():
    asyncio.run(_image_analysis_is_explicit_cached_and_presented_separately())


async def _stale_image_analysis_does_not_block_or_render_for_new_message():
    from textual.widgets import Static

    from imapledger.tui.app import HelpScreen

    mail = ImageMailService({9: _message_with_images(9), 10: _message_with_images(10)})
    image_service = FakeImageAnalysisService(block_first=True)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=FakeActionService(),
        image_analysis_service=image_service,
    )
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        await app._open_message("Spam", 9)
        await pilot.press("i")
        assert await asyncio.to_thread(image_service.started.wait, 2)

        await pilot.press("h")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await app._open_message("Spam", 10)
        image_service.release.set()
        await pilot.pause(0.1)
        assert app._detail.item.uid == 10
        assert app._image_analysis is None
        assert "request-9" not in str(app.query_one("#visual-analysis", Static).render())

        await pilot.press("i")
        await pilot.pause(0.1)
        assert image_service.calls == [9, 10]
        assert "request-10" not in str(app.query_one("#visual-analysis", Static).render())
        assert "OPTIONAL IF INTERESTED" in str(app.query_one("#visual-analysis", Static).render())


def test_stale_image_analysis_is_ignored_and_worker_is_responsive():
    asyncio.run(_stale_image_analysis_does_not_block_or_render_for_new_message())


async def _remote_image_loading_requires_explicit_confirmation():
    from textual.widgets import Button, Static

    from imapledger.tui.app import RemoteImageConfirmation

    class FakeRemoteImageLoader:
        def __init__(self):
            self.calls = []

        def fetch_all(self, refs):
            refs = tuple(refs)
            self.calls.append(refs)
            return (
                MailImage(
                    index=refs[0].index,
                    content_type="image/png",
                    filename="",
                    content_id="",
                    disposition="remote",
                    data=b"remote bytes",
                    size_bytes=12,
                    classifiable=True,
                ),
            ), ()

    mail = ImageMailService({9: _message_with_images(9)})
    image_service = FakeImageAnalysisService()
    loader = FakeRemoteImageLoader()
    actions = FakeActionService()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        rules=RuleSet(),
        analysis_service=FakeAnalysisService(),
        action_service=actions,
        image_analysis_service=image_service,
        remote_image_loader=loader,
    )
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        await app._open_message("Spam", 9)
        assert loader.calls == []
        await pilot.press("I")
        await pilot.pause()
        assert isinstance(app.screen, RemoteImageConfirmation)
        assert app.screen.query_one("#cancel", Button).has_focus
        await pilot.press("escape")
        await pilot.pause()
        assert loader.calls == []
        assert image_service.calls == []

        await pilot.press("I")
        await pilot.pause()
        await pilot.click("#load")
        await pilot.pause(0.1)
        assert len(loader.calls) == 1
        assert len(loader.calls[0]) == 1
        assert image_service.calls == [9]
        panel = str(app.query_one("#visual-analysis", Static).render())
        assert "Remote image analysis: 1 fetched, 1 analyzed, 0 skipped" in panel
        assert "remote image 1/1" in panel
        assert "secret-9" not in panel
        assert actions.calls == []
        await app._open_message("Spam", 9)
        await pilot.press("I")
        assert len(loader.calls) == 1
        assert "Using cached remote visual analysis" in str(app.query_one("#status", Static).render())


def test_remote_images_require_confirmation_and_cancel_is_default():
    asyncio.run(_remote_image_loading_requires_explicit_confirmation())
