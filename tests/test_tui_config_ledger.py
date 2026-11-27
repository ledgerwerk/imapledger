from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, Checkbox, Input, Select, Static

from imapledger.application.operation_registry import OPERATION_SPECS, OperationContext
from imapledger.config_ledger import ConfigPullPreview, ConfigToolStatus, ConfigToolSummary, ConfigVersionRecord
from imapledger.config_snapshot import ConfigSnapshotMeta
from imapledger.tui.app import MailReviewApp
from imapledger.tui.command_center import CommandCenterScreen
from imapledger.tui.config_ledger_screens import (
    ConfigLedgerScreen,
    ConfigPullDialog,
    ConfigPullPreviewScreen,
    ConfigPushConfirmation,
    ConfigPushDialog,
    ConfigPushRequest,
)


class _ScreenHost(App[None]):
    def compose(self) -> ComposeResult:
        yield Static("test host")


def test_command_center_shows_actionable_disabled_reasons() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        screen = CommandCenterScreen(OPERATION_SPECS, OperationContext())

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen._update_selection("rule.preview")

            detail = str(screen.query_one("#command-center-detail", Static).render())
            assert "Unavailable: load a valid configuration" in detail
            assert screen.query_one("#command-center-open", Button).disabled

    asyncio.run(scenario())


def test_disconnected_tui_opens_global_command_center(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = MailReviewApp(tmp_path / "config.toml")

        async with app.run_test() as pilot:
            await pilot.press(":")
            await pilot.pause()
            assert isinstance(app.screen, CommandCenterScreen)
            assert not app.screen.query_one("#command-center-open", Button).disabled

    asyncio.run(scenario())


def test_config_ledger_conflict_keeps_version_history_available() -> None:
    async def scenario() -> None:
        summary = ConfigToolSummary(
            tool="example",
            versions=3,
            status=ConfigToolStatus.CONFLICT,
            current=None,
            default_path=None,
            heads=2,
            details=("multiple current heads",),
        )
        app = _ScreenHost()
        screen = ConfigLedgerScreen((summary,), store_folder="Config Ledger")

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen._select_tool("example")

            assert not screen.query_one("#ledger-versions", Button).disabled
            assert screen.query_one("#ledger-view", Button).disabled
            detail = str(screen.query_one("#config-ledger-detail", Static).render())
            assert "no unique current head" in detail

    asyncio.run(scenario())


def test_config_push_requires_explicit_review_and_confirmation() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        request_path = Path("/tmp/config.toml")
        result: list[ConfigPushRequest | None] = []
        screen = ConfigPushDialog("example")

        async with app.run_test() as pilot:
            app.push_screen(screen, result.append)
            await pilot.pause()
            assert not screen.query_one("#config-push-sensitive", Checkbox).value
            assert not screen.query_one("#config-push-conflict", Checkbox).value
            screen.query_one("#config-push-path", Input).value = str(request_path)
            await pilot.click("#config-push-review")
            await pilot.pause()

            assert result == [
                ConfigPushRequest(
                    tool="example",
                    path=request_path,
                    allow_sensitive_plaintext=False,
                    resolve_conflict=False,
                )
            ]
            confirmation = ConfigPushConfirmation(result[0], "Config Ledger")
            app.push_screen(confirmation)
            await pilot.pause()
            assert "Sensitive plaintext detection remains fail-closed." in str(confirmation.query_one(Static).render())

    asyncio.run(scenario())


def test_config_pull_preview_requires_a_second_explicit_write_action(tmp_path: Path) -> None:
    async def scenario() -> None:
        preview = ConfigPullPreview(
            tool="example",
            version_id="version-1",
            target=tmp_path / "settings.toml",
            content_sha256="a" * 64,
            target_exists=True,
            target_sha256="b" * 64,
            already_up_to_date=False,
            diff="-old\n+new\n",
        )
        app = _ScreenHost()
        screen = ConfigPullPreviewScreen(preview)

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()

            assert not screen.query_one("#config-pull-apply", Button).disabled
            text = str(screen.query_one("#config-pull-preview-text", Static).render())
            warning = str(screen.query_one("#config-pull-warning", Static).render())
            assert "-old" in text
            assert "+new" in text
            assert "Preview diff may reveal sensitive values" in warning

    asyncio.run(scenario())


def test_config_push_review_and_confirmation_work_without_mouse(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        screen = ConfigPushDialog("example")
        requests: list[ConfigPushRequest | None] = []

        async with app.run_test() as pilot:
            app.push_screen(screen, requests.append)
            await pilot.pause()
            assert app.focused is screen.query_one("#config-push-path", Input)
            screen.query_one("#config-push-path", Input).value = str(tmp_path / "settings.toml")
            await pilot.press("tab", "tab", "tab")
            assert app.focused is screen.query_one("#config-push-review", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert requests[0] is not None

            confirmation = ConfigPushConfirmation(requests[0], "Config Ledger")
            result: list[bool] = []
            app.push_screen(confirmation, result.append)
            await pilot.pause()
            cancel = confirmation.query_one("#config-push-confirm-cancel", Button)
            assert app.focused is cancel
            await pilot.press("tab")
            assert app.focused is confirmation.query_one("#config-push-confirm", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert result == [True]

    asyncio.run(scenario())


def test_config_pull_select_preview_and_explicit_write_are_keyboard_operable(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        records = tuple(
            ConfigVersionRecord(
                ConfigSnapshotMeta(
                    tool="example",
                    version_id=version_id,
                    parent_version_ids=(),
                    created_at=datetime(2025, 1, day, tzinfo=timezone.utc),
                    default_path="settings.toml",
                    filename="settings.toml",
                    content_sha256=version_id[-1] * 64,
                    size_bytes=1,
                ),
                current=index == 0,
                head=index == 1,
            )
            for index, (version_id, day) in enumerate((("version-1", 1), ("version-2", 2)))
        )
        dialog = ConfigPullDialog("example", records)
        requests: list[object] = []

        async with app.run_test() as pilot:
            app.push_screen(dialog, requests.append)
            await pilot.pause()
            version = dialog.query_one("#config-pull-version", Select)
            assert app.focused is version
            await pilot.press("enter", "down", "enter")
            await pilot.pause()
            assert version.value == "version-2"
            await pilot.press("tab")
            target = dialog.query_one("#config-pull-target", Input)
            assert app.focused is target
            target.value = str(tmp_path / "settings.toml")
            await pilot.press("tab")
            assert app.focused is dialog.query_one("#config-pull-preview", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert requests[0].version_id == "version-2"
            assert requests[0].target == str(tmp_path / "settings.toml")

            preview = ConfigPullPreview(
                tool="example",
                version_id="version-2",
                target=tmp_path / "settings.toml",
                content_sha256="a" * 64,
                target_exists=False,
                target_sha256=None,
                already_up_to_date=False,
                diff="",
            )
            cancel_preview = ConfigPullPreviewScreen(preview)
            cancelled: list[bool] = []
            app.push_screen(cancel_preview, cancelled.append)
            await pilot.pause()
            assert app.focused is cancel_preview.query_one("#config-pull-cancel", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert cancelled == [False]

            write_preview = ConfigPullPreviewScreen(preview)
            written: list[bool] = []
            app.push_screen(write_preview, written.append)
            await pilot.pause()
            await pilot.press("tab")
            assert app.focused is write_preview.query_one(VerticalScroll)
            await pilot.press("tab")
            assert app.focused is write_preview.query_one("#config-pull-apply", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert written == [True]

    asyncio.run(scenario())
