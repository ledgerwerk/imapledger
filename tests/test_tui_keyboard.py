from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Button, DataTable, Input, Select, Static, TextArea

from imapledger.application import RuleRunRequest
from imapledger.application.operation_registry import OPERATION_SPECS, OperationContext
from imapledger.config import AuthSource, ImapSettings, Settings
from imapledger.config_ledger import ConfigToolStatus, ConfigToolSummary, ConfigVersionRecord
from imapledger.config_snapshot import ConfigSnapshotMeta
from imapledger.progress_store import ProgressRun
from imapledger.routing_actions import RuleAction
from imapledger.routing_models import RoutingRule, RuleSet, RuleType
from imapledger.tui.app import (
    MailReviewApp,
    ProgressResetConfirmation,
    ProgressScreen,
    RuleRunApplyConfirmation,
    RuleRunDialog,
    RuleRunJobScreen,
)
from imapledger.tui.command_center import CommandCenterScreen
from imapledger.tui.config_ledger_screens import (
    ConfigLedgerScreen,
    ConfigPullDialog,
    ConfigPushConfirmation,
    ConfigPushDialog,
    ConfigPushRequest,
    ConfigVersionsScreen,
)
from imapledger.tui.rule_screens import (
    RoutingRuleCenterScreen,
    RoutingRuleEditorScreen,
    RuleLearnTargetScreen,
    RuleRecipeCatalogScreen,
    RuleRemovalConfirmation,
)
from imapledger.tui.system_screens import (
    ConnectDialog,
    CredentialDeleteDialog,
    CredentialSetDialog,
    ReloadConfirmation,
    SetupDialog,
    VaultPassphraseDialog,
)


class _ScreenHost(App[None]):
    def compose(self) -> ComposeResult:
        yield Static("test host")


def test_rule_run_sort_is_a_keyboard_select_and_updates_request_and_preview() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        dialog = RuleRunDialog("INBOX")
        results: list[RuleRunRequest | None] = []

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(dialog, results.append)
            await pilot.pause()

            assert dialog.query_one("#rule-run-rule", Input).has_focus
            await pilot.press("tab")
            assert dialog.query_one("#rule-run-limit", Input).has_focus
            await pilot.press("tab")

            sort = dialog.query_one("#rule-run-sort", Select)
            assert sort.value == "oldest"
            assert not any(isinstance(widget, Input) for widget in dialog.query("#rule-run-sort"))
            assert "--sort oldest" in str(dialog.query_one("#rule-run-command", Static).render())
            assert sort.has_focus

            await pilot.press("enter")
            await pilot.press("down")
            await pilot.press("enter")
            await pilot.pause()
            assert sort.value == "newest"
            assert "--sort newest" in str(dialog.query_one("#rule-run-command", Static).render())

            for _ in range(4):
                await pilot.press("tab")
            assert dialog.query_one("#rule-run-start", Button).has_focus
            await pilot.press("enter")
            await pilot.pause()

        assert len(results) == 1
        assert results[0] is not None
        assert results[0].sort == "newest"

    asyncio.run(scenario())


def test_modal_focus_stays_inside_real_app(tmp_path) -> None:
    async def scenario() -> None:
        app = MailReviewApp(tmp_path / "config.toml")
        dialog = RuleRunDialog("INBOX")

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(dialog)
            await pilot.pause()

            rule = dialog.query_one("#rule-run-rule", Input)
            limit = dialog.query_one("#rule-run-limit", Input)
            sort = dialog.query_one("#rule-run-sort", Select)

            assert app.focused is rule
            await pilot.press("tab")
            assert app.focused is limit
            await pilot.press("shift+tab")
            assert app.focused is rule
            await pilot.press("tab", "tab")
            assert app.focused is sort
            await pilot.press("left", "right")
            assert app.focused is sort
            assert sort.value == "oldest"

    asyncio.run(scenario())


def test_confirmation_screens_start_safe_and_enter_cancels(tmp_path) -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        rule = RoutingRule(
            id="spam",
            enabled=True,
            type=RuleType.SEMANTIC,
            action=RuleAction.KEEP,
            match_at=0.9,
            description="Messages about canned meat",
        )
        push_request = ConfigPushRequest("example", tmp_path / "config.toml", False, False)
        confirmations = (
            (RuleRunApplyConfirmation(RuleRunRequest(folders=("INBOX",), apply=True), ()), "#rule-run-confirm-cancel"),
            (ProgressResetConfirmation("INBOX", 1), "#progress-reset-cancel"),
            (RuleRemovalConfirmation(rule), "#rule-removal-cancel"),
            (ReloadConfirmation("Reload the active session?"), "#reload-cancel"),
            (ConfigPushConfirmation(push_request, "Config Ledger"), "#config-push-confirm-cancel"),
        )

        async with app.run_test(size=(110, 36)) as pilot:
            for screen, safe_button in confirmations:
                result: list[object] = []
                app.push_screen(screen, result.append)
                await pilot.pause()
                assert app.focused is screen.query_one(safe_button, Button)
                await pilot.press("enter")
                await pilot.pause()
                assert result == [False]

    asyncio.run(scenario())


def test_secret_dialog_escape_clears_values() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        settings = Settings(imap=ImapSettings(host="imap.example.org", username="user"))
        dialogs = (
            (
                CredentialSetDialog(settings),
                ("#credential-password", "#credential-passphrase", "#credential-passphrase-confirm"),
            ),
            (
                VaultPassphraseDialog(12),
                ("#vault-old-passphrase", "#vault-new-passphrase", "#vault-confirm-passphrase"),
            ),
            (CredentialDeleteDialog(AuthSource.VAULT), ("#credential-delete-passphrase",)),
        )

        async with app.run_test(size=(110, 36)) as pilot:
            for screen, selectors in dialogs:
                result: list[object] = []
                app.push_screen(screen, result.append)
                await pilot.pause()
                fields = tuple(screen.query_one(selector, Input) for selector in selectors)
                for field in fields:
                    field.value = "secret"
                await pilot.press("escape")
                await pilot.pause()
                assert result == [None]
                assert all(not field.value for field in fields)

    asyncio.run(scenario())


def test_hidden_rule_editor_fields_and_disabled_credential_fields_are_skipped() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        rule = RoutingRule(
            id="spam",
            enabled=True,
            type=RuleType.SEMANTIC,
            action=RuleAction.KEEP,
            match_at=0.9,
            description="Messages about canned meat",
        )
        editor = RoutingRuleEditorScreen(rule, ("INBOX",), RuleSet((rule,)), existing_id="spam")

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(editor)
            await pilot.pause()
            hidden_selectors = ("#header-fields Input", "#recipe-fields Select", "#destination-fields Select")
            for _ in range(20):
                await pilot.press("tab")
                assert all(not widget.has_focus for selector in hidden_selectors for widget in editor.query(selector))

            await pilot.press("escape")
            await pilot.pause()
            credentials = CredentialSetDialog(Settings(imap=ImapSettings(host="imap.example.org", username="user")))
            app.push_screen(credentials)
            await pilot.pause()
            passphrase_fields = (
                credentials.query_one("#credential-passphrase", Input),
                credentials.query_one("#credential-passphrase-confirm", Input),
            )
            assert all(field.disabled for field in passphrase_fields)
            for _ in range(8):
                await pilot.press("tab")
                assert all(not field.has_focus for field in passphrase_fields)

    asyncio.run(scenario())


def test_rule_description_enter_inserts_newline_and_tab_navigates() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        editor = RoutingRuleEditorScreen(None, ("INBOX",), RuleSet())

        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(editor)
            await pilot.pause()
            description = editor.query_one("#routing-rule-description", TextArea)
            description.text = "Line one"
            description.focus()
            description.move_cursor((0, len("Line one")))

            await pilot.press("enter", "x")
            assert description.text == "Line one\nx"

            await pilot.press("tab")
            assert editor.query_one("#routing-rule-threshold", Input).has_focus
            assert "\t" not in description.text

            await pilot.press("shift+tab")
            assert description.has_focus
            assert "\t" not in description.text

    asyncio.run(scenario())


def test_running_rule_job_requires_safe_keyboard_close() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        screen = RuleRunJobScreen(RuleRunRequest(folders=("INBOX",)))
        result: list[None] = []

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(screen, result.append)
            await pilot.pause()
            assert app.focused is screen.query_one("#rule-run-job-table")

            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is screen
            assert not result

            await pilot.press("tab")
            assert app.focused is screen.query_one("#rule-run-job-cancel", Button)
            screen.finish_stopped()
            await pilot.pause()
            close = screen.query_one("#rule-run-job-close", Button)
            assert not close.disabled
            assert app.focused is close
            await pilot.press("enter")
            await pilot.pause()

        assert result == [None]

    asyncio.run(scenario())


def test_main_pane_h_l_navigation_still_works_without_a_modal(tmp_path) -> None:
    async def scenario() -> None:
        app = MailReviewApp(tmp_path / "config.toml")

        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            messages = app.query_one("#messages", DataTable)
            detail = app.query_one("#message-detail")
            messages.focus()
            await pilot.press("L")
            assert app.focused is detail
            await pilot.press("H")
            assert app.focused is messages

    asyncio.run(scenario())


def test_forms_focus_the_first_useful_control() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        settings = Settings(imap=ImapSettings(host="imap.example.org", username="user"))
        rule = RoutingRule(
            id="spam",
            enabled=True,
            type=RuleType.SEMANTIC,
            action=RuleAction.KEEP,
            match_at=0.9,
            description="Messages about canned meat",
        )
        meta = ConfigSnapshotMeta(
            tool="example",
            version_id="version-1",
            parent_version_ids=(),
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            default_path="settings.toml",
            filename="settings.toml",
            content_sha256="a" * 64,
            size_bytes=1,
        )
        version = ConfigVersionRecord(meta, current=True, head=True)
        forms = (
            (SetupDialog(Path("/tmp/config.toml"), None), "#setup-path"),
            (ConnectDialog(AuthSource.PROMPT), "#connect-secret"),
            (ConnectDialog(AuthSource.KEYRING), "#connect-confirm"),
            (CredentialSetDialog(settings), "#credential-storage"),
            (VaultPassphraseDialog(12), "#vault-old-passphrase"),
            (ConfigPushDialog("example"), "#config-push-path"),
            (ConfigPushDialog(""), "#config-push-tool"),
            (ConfigPullDialog("example", (version,)), "#config-pull-version"),
            (RoutingRuleEditorScreen(None, ("INBOX",), RuleSet(), rules_path=None), "#routing-rule-id"),
            (RuleLearnTargetScreen("INBOX", 1, RuleSet((rule,))), "#learn-target-rule"),
        )

        async with app.run_test(size=(110, 36)) as pilot:
            for screen, selector in forms:
                app.push_screen(screen)
                await pilot.pause()
                assert app.focused is screen.query_one(selector)
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(scenario())


def test_browser_screens_support_arrow_enter_tab_and_escape() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        first_rule = RoutingRule(
            id="first",
            enabled=True,
            type=RuleType.SEMANTIC,
            action=RuleAction.KEEP,
            match_at=0.9,
            description="First rule",
        )
        second_rule = RoutingRule(
            id="second",
            enabled=True,
            type=RuleType.SEMANTIC,
            action=RuleAction.KEEP,
            match_at=0.9,
            description="Second rule",
        )

        async with app.run_test(size=(110, 36)) as pilot:
            center = RoutingRuleCenterScreen(RuleSet((first_rule, second_rule)), ())
            center_result: list[object] = []
            app.push_screen(center, center_result.append)
            await pilot.pause()
            rule_list = center.query_one("#routing-rule-list")
            assert app.focused is rule_list
            await pilot.press("down", "enter")
            await pilot.pause()
            assert center_result == [("edit", "second")]

            recipes = RuleRecipeCatalogScreen()
            recipe_result: list[object] = []
            app.push_screen(recipes, recipe_result.append)
            await pilot.pause()
            assert app.focused is recipes.query_one("#rule-recipe-search", Input)
            await pilot.press("tab", "tab")
            recipe_list = recipes.query_one("#rule-recipe-list")
            assert app.focused is recipe_list
            await pilot.press("down")
            selected_recipe = recipes._selected_recipe_id()
            await pilot.press("enter")
            await pilot.pause()
            assert recipe_result == [selected_recipe]

            summary = ConfigToolSummary(
                tool="example",
                versions=1,
                status=ConfigToolStatus.OK,
                current="version-1",
                default_path="settings.toml",
                heads=1,
            )
            ledger = ConfigLedgerScreen((summary,), store_folder="Config Ledger")
            ledger_result: list[object] = []
            app.push_screen(ledger, ledger_result.append)
            await pilot.pause()
            ledger_table = ledger.query_one("#config-ledger-table", DataTable)
            assert app.focused is ledger_table
            await pilot.press("enter")
            await pilot.pause()
            assert ledger_result == [("versions", "example")]

            meta = ConfigSnapshotMeta(
                tool="example",
                version_id="version-1",
                parent_version_ids=(),
                created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
                default_path="settings.toml",
                filename="settings.toml",
                content_sha256="a" * 64,
                size_bytes=1,
            )
            versions = ConfigVersionsScreen("example", (ConfigVersionRecord(meta, current=True, head=True),))
            version_result: list[object] = []
            app.push_screen(versions, version_result.append)
            await pilot.pause()
            assert app.focused is versions.query_one("#config-versions-table", DataTable)
            await pilot.press("enter")
            await pilot.pause()
            assert version_result == [("view", "example", "version-1")]

            command_center = CommandCenterScreen(
                OPERATION_SPECS,
                OperationContext(
                    config=True,
                    credential=True,
                    connected=True,
                    selected_folder=True,
                    selected_message=True,
                    routing_rules=True,
                    config_store=True,
                ),
            )
            command_result: list[object] = []
            app.push_screen(command_center, command_result.append)
            await pilot.pause()
            assert app.focused is command_center.query_one("#command-center-search", Input)
            await pilot.press("tab")
            assert app.focused is command_center.query_one("#command-center-table", DataTable)
            command_id = command_center._selected_id
            await pilot.press("enter")
            await pilot.pause()
            assert command_result == [command_id]

            runs = (
                ProgressRun(
                    id="run-1",
                    account_key="account",
                    source_folder="INBOX",
                    uidvalidity=1,
                    high_watermark_uid=10,
                    lower_bound_uid=0,
                    rules_fingerprint="rules",
                    mode="full",
                    rule_scope=None,
                    sort_direction="oldest",
                    status="completed",
                    cursor_uid=None,
                    started_at="2025-01-01T00:00:00Z",
                    updated_at="2025-01-01T00:00:00Z",
                    completed_at=None,
                    scanned_count=0,
                    match_count=0,
                    moved_count=0,
                    no_match_count=0,
                    error_count=0,
                ),
                ProgressRun(
                    id="run-2",
                    account_key="account",
                    source_folder="Archive",
                    uidvalidity=1,
                    high_watermark_uid=10,
                    lower_bound_uid=0,
                    rules_fingerprint="rules",
                    mode="full",
                    rule_scope=None,
                    sort_direction="newest",
                    status="completed",
                    cursor_uid=None,
                    started_at="2025-01-01T00:00:00Z",
                    updated_at="2025-01-01T00:00:00Z",
                    completed_at=None,
                    scanned_count=0,
                    match_count=0,
                    moved_count=0,
                    no_match_count=0,
                    error_count=0,
                ),
            )
            progress = ProgressScreen(runs, {}, Path("/tmp/progress.sqlite3"))
            progress_result: list[object] = []
            app.push_screen(progress, progress_result.append)
            await pilot.pause()
            table = progress.query_one("#progress-runs", DataTable)
            assert app.focused is table
            await pilot.press("down")
            assert table.cursor_row == 1
            await pilot.press("enter")
            assert progress.selected is runs[1]
            await pilot.press("escape")
            await pilot.pause()
            assert progress_result == [None]

    asyncio.run(scenario())


def test_credential_storage_form_is_keyboard_operable() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        settings = Settings(imap=ImapSettings(host="imap.example.org", username="user"))
        dialog = CredentialSetDialog(settings)
        result: list[object] = []

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(dialog, result.append)
            await pilot.pause()
            storage = dialog.query_one("#credential-storage", Select)
            assert app.focused is storage
            await pilot.press("enter", "down", "down", "enter")
            await pilot.pause()
            assert storage.value == "vault"

            await pilot.press("tab")
            password = dialog.query_one("#credential-password", Input)
            assert app.focused is password
            password.value = "imap-secret"
            await pilot.press("tab")
            passphrase = dialog.query_one("#credential-passphrase", Input)
            assert app.focused is passphrase
            passphrase.value = "vault-secret"
            await pilot.press("tab")
            confirmation = dialog.query_one("#credential-passphrase-confirm", Input)
            assert app.focused is confirmation
            confirmation.value = "vault-secret"
            await pilot.press("tab", "tab")
            assert app.focused is dialog.query_one("#credential-set-save", Button)
            await pilot.press("enter")
            await pilot.pause()

        assert len(result) == 1
        assert result[0].storage == "vault"
        assert result[0].password == "imap-secret"
        assert result[0].passphrase == "vault-secret"

    asyncio.run(scenario())
