from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from imapledger.action_service import ActionReceipt
from imapledger.analysis_service import MessageAnalysis
from imapledger.application import RuleRunRequest, RuleRunResult
from imapledger.application.clean import CleanResult as RuleRunFolderResult
from imapledger.classification_state import SpamOutcome
from imapledger.config import ActionKind, ImapSettings, MessageAction, Settings, SpamActions, SpamSettings
from imapledger.image_analysis import ImageAnalysisReport, ImageAssessment, ImageRecommendation
from imapledger.mail_service import MessageDetail, MessagePage
from imapledger.mailbox import FolderInfo, MailboxItem, MessageSort
from imapledger.message import MailImage, MailSummary, RemoteImageRef, parse_message
from imapledger.policy import SpamVerdict
from imapledger.preflight import SourcePreflightResult
from imapledger.processing_engine import ProcessedMessage
from imapledger.progress_store import ProgressStore, account_identity_key
from imapledger.routing_action_service import RoutingActionReceipt
from imapledger.routing_config import write_routing_rules
from imapledger.routing_models import RoutingRule, RuleType
from imapledger.routing_models import RuleMatch as RoutingRuleMatch
from imapledger.routing_models import RuleSet as RoutingRuleSet
from imapledger.routing_rule_service import RoutingRuleService
from imapledger.rules import RuleSet
from imapledger.tui.app import (
    ApplyConfirmation,
    DoctorScreen,
    MailReviewApp,
    ProgressErrorsScreen,
    ProgressResetConfirmation,
    ProgressScreen,
    RuleRunApplyConfirmation,
    RuleRunDialog,
    RuleRunJobScreen,
)
from imapledger.tui.rule_screens import RoutingRuleCenterScreen

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
        self.requested_pages = []
        self.page_has_next = False
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

    def list_messages(self, folder, *, limit, offset, sort=MessageSort.NEWEST):
        self.requested_folders.append(folder)
        self.requested_pages.append((folder, limit, offset, sort))
        if folder == "Fail" and self.fail_load:
            raise RuntimeError("sensitive server error")
        if folder == self.block_folder or folder == "Slow":
            if self.started is not None:
                self.started.set()
                self.release.wait(timeout=5)
            else:
                time.sleep(self.slow_delay)
        return MessagePage(folder, 42, offset, limit, 1, sort, (SUMMARY,), offset > 0, self.page_has_next)

    def review_messages(self, *, limit, offset):
        return (("Spam", SUMMARY),)

    def get_message(self, folder, uid):
        return MessageDetail(folder, 42, MailboxItem(uid, message=MESSAGE), None)

    def close(self):
        self.closed = True


class FakeAnalysisService:
    def __init__(self, outcome: SpamOutcome = SpamOutcome.REVIEW) -> None:
        self.settings = SETTINGS
        self.outcome = outcome

    def set_settings(self, settings: Settings) -> None:
        self.settings = settings

    def analyze(self, folder, message, **kwargs):
        verdict = {
            SpamOutcome.SPAM: SpamVerdict.DELETE,
            SpamOutcome.NOT_SPAM: SpamVerdict.KEEP,
            SpamOutcome.REVIEW: SpamVerdict.REVIEW,
        }[self.outcome]
        return MessageAnalysis(
            folder=folder,
            uid=message.uid,
            persisted_outcome=kwargs.get("persisted_outcome"),
            rule_id=None,
            outcome=self.outcome,
            verdict=verdict,
            signals=None,
            reasons=("needs-review",),
            configured_action=getattr(self.settings.spam.actions, self.outcome.value),
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
        self.settings = SETTINGS
        self.fail = False

    def set_settings(self, settings: Settings) -> None:
        self.settings = settings

    def apply(self, analysis, *, uidvalidity, confirmed_by_user):
        self.calls.append((analysis, uidvalidity, confirmed_by_user))
        return ActionReceipt(
            folder=analysis.folder,
            uidvalidity=uidvalidity,
            uid=analysis.uid,
            requested_action=analysis.configured_action,
            outcome=analysis.outcome.value if analysis.outcome else None,
            decision_source=analysis.decision_source,
            applied=not self.fail,
            confirmed=not self.fail,
            detail="fake failure" if self.fail else None,
        )


class FakeRoutingActionService:
    def __init__(self):
        self.calls = []
        self.fail = False

    def apply(self, plan, *, uidvalidity, confirmed_by_user):
        self.calls.append((plan, uidvalidity, confirmed_by_user))
        return RoutingActionReceipt(
            plan,
            uidvalidity,
            applied=not self.fail,
            confirmed=not self.fail,
            detail="fake failure" if self.fail else None,
        )


async def _browse_classify_apply():
    from textual.widgets import Static

    mail = FakeMailService()
    actions = FakeRoutingActionService()
    rules = RoutingRuleSet(
        (
            RoutingRule(
                id="hello",
                enabled=True,
                type=RuleType.HEADER,
                destination="Archive",
                match=RoutingRuleMatch(subject="Hello"),
            ),
        )
    )
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        routing_rules=rules,
        action_service=actions,
    )

    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause(0.2)
        assert str(app.query_one("#workspace").styles.layout).strip("<>") == "horizontal"
        await app._select_folder("Spam")
        await pilot.pause(0.1)
        assert len(app._rows) == 1
        await app._open_message("Spam", 9)
        assert "Visible text" in str(app.query_one("#message-detail").query_one(Static).render())
        assert app._analysis is None
        await pilot.press("c")
        for _ in range(20):
            if app._analysis is not None:
                break
            await pilot.pause(0.05)
        assert app._analysis is not None
        analysis_text = str(app.query_one("#analysis", Static).render())
        assert "First match: hello" in analysis_text
        assert "Action: MOVE to Archive" in analysis_text
        await pilot.press("e")
        await pilot.pause()
        assert "First match: hello" in str(app.query_one("#analysis", Static).render())
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ApplyConfirmation)
        await pilot.click("#apply")
        for _ in range(20):
            if actions.calls:
                break
            await pilot.pause(0.05)
        assert len(actions.calls) == 1
        assert actions.calls[0][1:] == (42, True)
        assert app._rows == []
        assert "Action complete" in str(app.query_one("#status", Static).render())
        assert "confirmed" in str(app.query_one("#activity", Static).render())

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


def test_tui_starts_session_without_resolving_credentials_before_textual_run(monkeypatch):
    from imapledger.tui import app as tui_module

    order = []

    class Session:
        def __init__(self, config):
            self.config = config
            order.append("session")

        def load_local(self):
            order.append("local")

        def close(self):
            order.append("close")

    monkeypatch.setattr(tui_module, "AppSession", Session)
    monkeypatch.setattr(tui_module, "ImageAnalysisService", lambda: object())
    monkeypatch.setattr(tui_module, "RemoteImageLoader", lambda: object())

    class App:
        def __init__(self, *args, **kwargs):
            order.append("app")

        def run(self):
            order.append("run")

    monkeypatch.setattr(tui_module, "MailReviewApp", App)

    tui_module.run(Path("unused.toml"))

    assert order == ["session", "local", "app", "run", "close"]


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


async def _routing_analysis_is_read_only_and_uses_the_unified_rules_screen(tmp_path: Path) -> None:
    from textual.widgets import Static

    rules = RoutingRuleSet(
        (
            RoutingRule(
                id="header-match",
                enabled=True,
                type=RuleType.HEADER,
                destination="Archive",
                match=RoutingRuleMatch(subject="Hello"),
            ),
        )
    )
    rules_path = tmp_path / "routing-rules.toml"
    write_routing_rules(rules, rules_path)
    actions = FakeRoutingActionService()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=rules,
        routing_rule_service=RoutingRuleService(rules_path),
        action_service=actions,
    )

    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause(0.2)
        await app._open_message("INBOX", 9)
        await pilot.press("c")
        await pilot.pause(0.2)
        assert app._analysis is not None
        assert app._analysis.winner_rule_id == "header-match"
        assert actions.calls == []
        rendered = str(app.query_one("#analysis").render())
        assert "header-match" in rendered
        assert "Destination: Archive" in rendered

        plan = app._analysis
        await pilot.press("e")
        await pilot.pause()
        assert app._analysis is plan
        assert "First match: header-match" in str(app.query_one("#analysis").render())
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ApplyConfirmation)
        confirmation = str(app.screen.query_one(Static).render())
        assert "UID: 9" in confirmation
        assert "Source: INBOX" in confirmation
        assert "Destination: Archive" in confirmation
        assert "MOVE this exact message?" in confirmation
        await pilot.press("escape")
        assert actions.calls == []
        await pilot.pause()
        await pilot.press("R")
        await pilot.pause()
        assert isinstance(app.screen, RoutingRuleCenterScreen)
        assert "Rules · 1 rules · 1 enabled" in str(app.screen.query_one("#routing-rule-center").children[0].render())


def test_tui_cannot_remove_builtin_spam_rule(tmp_path: Path) -> None:
    rules = RoutingRuleSet((RoutingRule("spam", True, RuleType.SPAM, "INBOX.Trash", built_in=True),))
    path = tmp_path / "rules.toml"
    write_routing_rules(rules, path)
    service = RoutingRuleService(path)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=rules,
        routing_rule_service=service,
    )

    async def scenario() -> None:
        from textual.widgets import Static

        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("R")
            await pilot.pause()
            assert isinstance(app.screen, RoutingRuleCenterScreen)
            await pilot.click("#remove")
            await pilot.pause(0.1)
            assert service.load() == rules
            assert "built-in Spam rule cannot be removed" in str(app.query_one("#status", Static).render())

    asyncio.run(scenario())


def test_routing_analysis_is_read_only_and_uses_the_unified_rules_screen(tmp_path: Path) -> None:
    asyncio.run(_routing_analysis_is_read_only_and_uses_the_unified_rules_screen(tmp_path))


def test_clean_ten_uses_preview_defaults_and_streams_job_rows(monkeypatch) -> None:
    class FakeRuleRunOperation:
        requests: list[object] = []

        def __init__(self, *_: object) -> None:
            pass

        def preflight(self, request):
            return SimpleNamespace(destinations=("Archive",))

        def run(self, request, *, password, on_result, should_stop):
            self.requests.append(request)
            message = ProcessedMessage(217691, "fallback", destination="Archive")
            on_result(request.folders[0], message, SimpleNamespace())
            report = SimpleNamespace(
                run=SimpleNamespace(id="run-1", scanned_count=0, cursor_uid=None, high_watermark_uid=217691),
                messages=(message,),
                preview=True,
                stopped_by_user=False,
                stopped_on_ambiguous_move=False,
            )
            return RuleRunResult(((request.folders[0], RuleRunFolderResult(report, ())),))

    monkeypatch.setattr("imapledger.tui.app.RuleRunOperation", FakeRuleRunOperation)
    FakeRuleRunOperation.requests.clear()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
        password="test-password",
    )

    async def scenario() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await app._select_folder("INBOX")
            await pilot.press("x")
            await pilot.pause(0.2)
            assert FakeRuleRunOperation.requests
            request = FakeRuleRunOperation.requests[0]
            assert request.folders == ("INBOX",)
            assert request.limit == 10
            assert request.apply is False
            assert request.sort == "oldest"
            assert isinstance(app.screen, RuleRunJobScreen)
            table = app.screen.query_one("#rule-run-job-table")
            assert table.row_count == 1
            assert table.get_row_at(0)[1] == "fallback"
            assert "Preview only" in str(app.screen.query_one("#rule-run-job-error").render())

    asyncio.run(scenario())


def test_clean_worker_remains_responsive_and_cancels_between_results(monkeypatch) -> None:
    started = threading.Event()

    class BlockingRuleRunOperation:
        def __init__(self, *_: object) -> None:
            pass

        def preflight(self, _request):
            return SimpleNamespace(destinations=("Archive",))

        def run(self, _request, *, password, on_result, should_stop):
            started.set()
            while not should_stop():
                time.sleep(0.005)
            report = SimpleNamespace(
                run=SimpleNamespace(id="run-2", scanned_count=0, cursor_uid=None, high_watermark_uid=0),
                messages=(),
                preview=True,
                stopped_by_user=True,
                stopped_on_ambiguous_move=False,
            )
            return RuleRunResult((("INBOX", RuleRunFolderResult(report, ())),))

    monkeypatch.setattr("imapledger.tui.app.RuleRunOperation", BlockingRuleRunOperation)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
        password="test-password",
    )

    async def scenario() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await app._select_folder("INBOX")
            await pilot.press("x")
            assert await asyncio.to_thread(started.wait, 1)
            assert isinstance(app.screen, RuleRunJobScreen)
            await pilot.click("#rule-run-job-cancel")
            await pilot.pause(0.1)
            summary = str(app.screen.query_one("#rule-run-job-summary").render())
            assert "cancelled/stopped by user" in summary

    asyncio.run(scenario())


def test_clean_dialog_defaults_and_updates_cli_equivalent() -> None:
    app = MailReviewApp(Path("unused.toml"))

    async def scenario() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            screen = RuleRunDialog("INBOX")
            app.push_screen(screen)
            await pilot.pause()
            request = screen._request()
            assert request.folders == ("INBOX",)
            assert request.limit == 10
            assert request.apply is False
            assert request.sort == "oldest"
            command = str(screen.query_one("#rule-run-command").render())
            assert "imapledger rule preview --folder INBOX --limit 10 --sort oldest" in command
            await pilot.click("#rule-run-apply")
            await pilot.pause()
            assert "imapledger rule apply" in str(screen.query_one("#rule-run-command").render())
            await pilot.click("#rule-run-cancel")

    asyncio.run(scenario())


def test_clean_apply_preflights_and_confirms_before_writable_run(monkeypatch) -> None:
    class FakeRuleRunOperation:
        run_requests: list[object] = []

        def __init__(self, *_: object) -> None:
            pass

        def preflight(self, _request):
            return SimpleNamespace(destinations=("Archive",))

        def run(self, request, *, password, on_result, should_stop):
            self.run_requests.append(request)
            message = ProcessedMessage(217691, "match", destination="Archive", applied=True, confirmed=True)
            run = SimpleNamespace(
                id="run-3",
                scanned_count=1,
                match_count=1,
                moved_count=1,
                no_match_count=0,
                error_count=0,
            )
            on_result(request.folders[0], message, run)
            report = SimpleNamespace(
                run=SimpleNamespace(id="run-3", scanned_count=1, cursor_uid=217691, high_watermark_uid=217691),
                messages=(message,),
                preview=False,
                stopped_by_user=False,
                stopped_on_ambiguous_move=False,
            )
            return RuleRunResult(((request.folders[0], RuleRunFolderResult(report, ("INBOX", "Archive"))),))

    preflights: list[object] = []

    def fake_preflight(*args, **kwargs):
        preflights.append((args, kwargs))
        return SimpleNamespace(ok=True, opened=True, missing_capabilities=(), destinations=(), errors=())

    monkeypatch.setattr("imapledger.tui.app.RuleRunOperation", FakeRuleRunOperation)
    monkeypatch.setattr("imapledger.tui.app.preflight_source", fake_preflight)
    FakeRuleRunOperation.run_requests.clear()
    mail = FakeMailService()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
        password="test-password",
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            app._begin_rule_run(RuleRunRequest(folders=("INBOX",), limit=10, apply=True))
            await pilot.pause(0.1)
            assert preflights
            assert isinstance(app.screen, RuleRunApplyConfirmation)
            assert not FakeRuleRunOperation.run_requests
            confirmation = str(app.screen.query_one("Static").render())
            assert "Source: INBOX" in confirmation
            assert "Possible destinations: Archive" in confirmation
            assert "best-effort, not transactional" in confirmation
            await pilot.click("#rule-run-confirm-apply")
            await pilot.pause(0.2)
            assert FakeRuleRunOperation.run_requests[0].apply is True
            assert isinstance(app.screen, RuleRunJobScreen)
            assert app.screen.query_one("#rule-run-job-table").row_count == 1
            assert mail.folder_list_modes.count(False) >= 2

    asyncio.run(scenario())


def test_tui_progress_workspace_requires_confirmation_to_reset(monkeypatch, tmp_path) -> None:
    database = tmp_path / "progress.sqlite3"
    monkeypatch.setattr("imapledger.application.progress.default_progress_path", lambda: database)
    store = ProgressStore(database)
    run = store.begin_run(
        account_key=account_identity_key(SETTINGS),
        source_folder="INBOX",
        uidvalidity=42,
        high_watermark_uid=12,
        rules_fingerprint="fingerprint-a",
        mode="full",
        rule_scope=None,
        sort_direction="oldest",
    )
    store.record_result(run.id, uid=9, outcome="error", error_code="RuntimeError")
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
        password="test-password",
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ProgressScreen)
            assert "1 stored error(s)" in str(app.screen.query_one("#progress-errors").render())
            await pilot.click("#progress-view-errors")
            await pilot.pause()
            assert isinstance(app.screen, ProgressErrorsScreen)
            error_row = " ".join(str(cell) for cell in app.screen.query_one("#progress-error-table").get_row_at(0))
            assert "9" in error_row and "RuntimeError" in error_row
            await pilot.click("#progress-errors-close")
            await pilot.pause()
            assert isinstance(app.screen, ProgressScreen)
            await pilot.click("#progress-reset")
            await pilot.pause()
            assert isinstance(app.screen, ProgressResetConfirmation)
            assert "Folder: INBOX" in str(app.screen.query_one("Static").render())
            await pilot.click("#progress-reset-confirm")
            await pilot.pause(0.3)
            assert isinstance(app.screen, ProgressScreen)
            assert "No progress runs" in str(app.screen.query_one("#progress-detail").render())

    asyncio.run(scenario())


def test_tui_doctor_displays_safe_error_types_only(monkeypatch) -> None:
    result = SourcePreflightResult(
        folder="Spam",
        opened=False,
        probe=None,
        capabilities=frozenset(),
        missing_capabilities=(),
        destinations=(),
        errors=(RuntimeError("credential-secret-must-not-render"),),
    )

    class FakeDoctorOperation:
        def __init__(self, *_: object) -> None:
            pass

        def run(self, *_: object, **__: object) -> SourcePreflightResult:
            return result

    monkeypatch.setattr("imapledger.tui.app.DoctorOperation", FakeDoctorOperation)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
        password="test-password",
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await pilot.press("d")
            await pilot.pause(0.2)
            assert isinstance(app.screen, DoctorScreen)
            row = " ".join(str(cell) for cell in app.screen.query_one("#doctor-table").get_row_at(0))
            assert "RuntimeError" in row
            assert "credential-secret-must-not-render" not in row

    asyncio.run(scenario())


def test_tui_mail_controls_page_sort_and_review_filter() -> None:
    from imapledger.application.browsing import ReviewPage

    class FakeReviewOperation:
        def __init__(self) -> None:
            self.requests = []

        def run(self, request, *, password, **kwargs):
            self.requests.append(request)
            return ReviewPage(
                folder=request.folder,
                limit=request.limit,
                offset=request.offset,
                sort=request.sort,
                total=0,
                items=(),
                has_previous=request.offset > 0,
                has_next=False,
            )

    mail = FakeMailService()
    mail.page_has_next = True
    review = FakeReviewOperation()
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=mail,
        review_operation=review,
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await app._select_folder("Spam")
            await pilot.click("#mail-next")
            await pilot.pause(0.1)
            assert app._page_offset == 50
            assert mail.requested_pages[-1][2] == 50
            await pilot.click("#mail-sort")
            await pilot.pause(0.1)
            assert app._page_sort is MessageSort.OLDEST
            assert app._page_offset == 0
            clicked_size = await pilot.click("#mail-size")
            assert clicked_size
            await pilot.pause(0.1)
            assert app._page_limit == 100

            await app._select_folder("Review")
            await pilot.click("#review-filter")
            await pilot.pause(0.1)
            assert review.requests[-1].folder == "Spam"
            assert app._list_folder == "Review"

    asyncio.run(scenario())


def test_tui_explain_without_evaluation_does_not_run_rules() -> None:
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=RoutingRuleSet(),
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await app._open_message("Spam", 9)
            await pilot.press("e")
            await pilot.pause()
            assert app._analysis is None
            assert "No rule evaluation yet" in str(app.query_one("#status").render())
            await pilot.press("a")
            await pilot.pause()
            assert not isinstance(app.screen, ApplyConfirmation)
            assert "Evaluate this message with c first" in str(app.query_one("#status").render())

    asyncio.run(scenario())


def test_tui_state_reset_requires_preview_and_explicit_apply(monkeypatch) -> None:
    from textual.widgets import Input

    from imapledger.application.state import StateFolderStatus, StateResetResult
    from imapledger.classification_state import ClassificationStateBackend
    from imapledger.tui.app import StateResetDialog, StateResetPreviewScreen, StateScreen

    class FakeStateOperation:
        calls = []

        def __init__(self, settings) -> None:
            self.settings = settings

        def status(self, folder, *, password, **kwargs):
            return StateFolderStatus(folder, 42, ClassificationStateBackend.NONE, "NOT CONFIGURED", 3, 1, 1, 1, 0, 0)

        def reset_folders(self, request):
            return (request.folder,) if not request.all_folders else self.settings.spam.folders

        def reset_folder(self, folder, request, *, password, **kwargs):
            self.calls.append((folder, request.uid, request.apply, password))
            return StateResetResult(folder, ((request.uid or 9, ("$imapledger-spam",)),), request.apply)

    monkeypatch.setattr("imapledger.tui.app.StateOperation", FakeStateOperation)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        password="session-secret",
        routing_rules=RoutingRuleSet(),
    )
    FakeStateOperation.calls.clear()

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await pilot.press("S")
            await pilot.pause(0.1)
            assert isinstance(app.screen, StateScreen)
            await pilot.click("#state-reset")
            await pilot.pause()
            assert isinstance(app.screen, StateResetDialog)
            app.screen.query_one("#state-reset-uid", Input).value = "12"
            await pilot.click("#state-reset-apply")
            await pilot.click("#state-reset-preview")
            await pilot.pause(0.2)
            assert isinstance(app.screen, StateResetPreviewScreen)
            assert "Exact UID: 12" in str(app.screen.query_one("Static").render())
            await pilot.click("#state-reset-confirm")
            await pilot.pause(0.3)
            assert isinstance(app.screen, StateScreen)

    asyncio.run(scenario())
    assert FakeStateOperation.calls == [
        ("Spam", 12, False, "session-secret"),
        ("Spam", 12, True, "session-secret"),
    ]


def test_tui_rule_migration_previews_before_writing(tmp_path: Path) -> None:
    from imapledger.tui.rule_screens import RuleMigrationPreviewScreen

    config_path = tmp_path / "config.toml"
    rules_path = tmp_path / "rules.toml"
    source = (
        '[rules]\nschema = 1\n\n[[rules.rule]]\nid = "learned"\n'
        'enabled = true\nsource_folders = ["Spam"]\naction = "move"\n'
        'destination = "Archive"\nmatch = { from_domain = "example.net" }\n'
    )
    rules_path.write_text(source, encoding="utf-8")
    app = MailReviewApp(
        config_path,
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rule_service=RoutingRuleService(rules_path),
        routing_rules=RoutingRuleSet(),
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            await pilot.press("R")
            await pilot.pause()
            assert isinstance(app.screen, RoutingRuleCenterScreen)
            await pilot.click("#migrate")
            await pilot.pause(0.2)
            assert isinstance(app.screen, RuleMigrationPreviewScreen)
            assert "learned" in str(app.screen.query_one("Static").render())
            assert rules_path.read_text(encoding="utf-8") == source
            await pilot.click("#rule-migration-apply")
            await pilot.pause(0.3)
            assert "schema = 3" in rules_path.read_text(encoding="utf-8")
            assert isinstance(app.screen, RoutingRuleCenterScreen)

    asyncio.run(scenario())


def test_tui_rule_learning_requires_preview_then_explicit_save(tmp_path: Path, monkeypatch) -> None:
    from imapledger.application.rules import RuleLearningPreview
    from imapledger.routing_config import rules_content_fingerprint
    from imapledger.rule_candidates import build_rule_candidates
    from imapledger.tui.rule_screens import RuleLearnPreviewScreen, RuleLearnTargetScreen

    path = tmp_path / "rules.toml"
    semantic_rule = RoutingRule(
        id="semantic-receipts",
        enabled=True,
        type=RuleType.SEMANTIC,
        destination="Receipts",
        description="Purchase receipts",
    )
    rules = RoutingRuleSet((semantic_rule,))
    write_routing_rules(rules, path)
    service = RoutingRuleService(path)
    candidate = next(item for item in build_rule_candidates(MESSAGE) if item.id == "from_address_exact")

    def fake_propose(self, message, *, folder, target_rule_id, existing_rules):
        assert message.uid == 9
        return RuleLearningPreview(
            target_rule_id=target_rule_id,
            base_rules_fingerprint=rules_content_fingerprint(existing_rules),
            source_folder=folder,
            uid=message.uid,
            semantic_fit=0.96,
            selected_candidate=candidate,
            candidate_confidence=0.98,
            safe_probability=0.99,
            proposed_matcher=candidate.match,
            status="auto",
            model="test-model",
            request_id="test-request",
        )

    monkeypatch.setattr("imapledger.application.rules.RuleLearningOperation.propose", fake_propose)
    app = MailReviewApp(
        Path("unused.toml"),
        mail_service=FakeMailService(),
        settings=SETTINGS,
        routing_rules=rules,
        routing_rule_service=service,
    )

    async def scenario() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause(0.2)
            await app._open_message("Spam", 9)
            await pilot.press("l")
            await pilot.pause()
            assert isinstance(app.screen, RuleLearnTargetScreen)
            await pilot.click("#learn-preview")
            await pilot.pause(0.2)
            assert isinstance(app.screen, RuleLearnPreviewScreen)
            assert "semantic-receipts" in str(app.screen.query_one("Static").render())
            assert service.load().rules[0].match_any == ()
            assert not app.screen.query_one("#learn-save").disabled
            assert await pilot.click("#learn-save")
            await pilot.pause(0.3)
            assert isinstance(app.screen, RoutingRuleCenterScreen), str(app.query_one("#status").render())
            assert service.load().rules[0].match_any == (candidate.match,)
            assert isinstance(app.screen, RoutingRuleCenterScreen)

    asyncio.run(scenario())
