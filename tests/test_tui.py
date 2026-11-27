from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Input, Select, Static, TextArea

from imapledger.config import ImapSettings, Settings
from imapledger.routing_actions import RuleAction
from imapledger.routing_config import render_routing_rules
from imapledger.routing_models import RoutingRule, RuleSet, RuleType
from imapledger.rule_recipes import materialize_recipe
from imapledger.tui.rule_screens import (
    RoutingRuleCenterScreen,
    RoutingRuleEditorScreen,
    RuleRecipeCatalogScreen,
    RuleRemovalConfirmation,
    RuleTomlPreviewScreen,
)
from imapledger.tui.system_screens import SetupDialog, SetupRequest


class _ScreenHost(App[None]):
    def compose(self) -> ComposeResult:
        yield Static("test host")


def test_setup_dialog_only_edits_connection_configuration(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        path = tmp_path / "config.toml"
        dialog = SetupDialog(path, None)
        results: list[SetupRequest | None] = []

        async with app.run_test(size=(110, 32)) as pilot:
            app.push_screen(dialog, results.append)
            await pilot.pause()
            assert not list(dialog.query("#setup-source-folders"))
            assert not list(dialog.query("#setup-spam-action"))
            assert not list(dialog.query("#setup-not-spam-action"))
            assert not list(dialog.query("#setup-spam-destination"))
            dialog.query_one("#setup-host", Input).value = "imap.example.org"
            dialog.query_one("#setup-username", Input).value = "user@example.org"
            await pilot.click("#setup-save")
            await pilot.pause()

        assert len(results) == 1
        assert results[0] is not None
        assert results[0].config_path == path
        assert results[0].settings == Settings(imap=ImapSettings(host="imap.example.org", username="user@example.org"))

    asyncio.run(scenario())


def test_empty_rules_workbench_is_safe_and_offers_recipes() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        screen = RoutingRuleCenterScreen(RuleSet(), ())
        results: list[tuple[str, str | None] | None] = []

        async with app.run_test(size=(110, 32)) as pilot:
            app.push_screen(screen, results.append)
            await pilot.pause()
            assert "No rules yet" in str(screen.query_one("#routing-rule-empty", Static).render())
            await pilot.click("#recipes")
            await pilot.pause()

        assert results == [("recipes", None)]

    asyncio.run(scenario())


def test_spam_named_rule_is_editable_and_removal_is_non_destructive() -> None:
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
        rules = RuleSet((rule,))
        editor = RoutingRuleEditorScreen(rule, (), rules, existing_id="spam")
        saved: list[RoutingRule | None] = []

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(editor, saved.append)
            await pilot.pause()
            assert editor.query_one("#routing-rule-id", Input).value == "spam"
            assert not editor.query_one("#routing-rule-id", Input).disabled
            assert editor.query_one("#routing-rule-type", Select).value == "semantic"
            await pilot.click("#save")
            await pilot.pause()

        assert saved == [rule]

        app = _ScreenHost()
        center = RoutingRuleCenterScreen(rules, ())
        center_result: list[tuple[str, str | None] | None] = []
        async with app.run_test(size=(110, 32)) as pilot:
            app.push_screen(center, center_result.append)
            await pilot.pause()
            assert center._selected_rule_id() == "spam"
            await pilot.click("#remove")
            await pilot.pause()
        assert center_result == [("remove", "spam")]

        app = _ScreenHost()
        confirmation = RuleRemovalConfirmation(rule)
        removed: list[bool | None] = []
        async with app.run_test(size=(90, 20)) as pilot:
            app.push_screen(confirmation, removed.append)
            await pilot.pause()
            text = str(confirmation.query_one(Static).render())
            assert "changes rules.toml only" in text
            assert "does not move or delete mail" in text
            await pilot.click("#rule-removal-confirm")
            await pilot.pause()
        assert removed == [True]

    asyncio.run(scenario())


def test_recipe_catalog_search_and_category_filter() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        screen = RuleRecipeCatalogScreen()
        selected: list[str | None] = []
        async with app.run_test(size=(110, 32)) as pilot:
            app.push_screen(screen, selected.append)
            await pilot.pause()
            assert len(screen.recipes) == 4
            screen.query_one("#rule-recipe-search", Input).value = "newsletter"
            await pilot.pause()
            assert [recipe.id for recipe in screen.recipes] == ["newsletter"]
            assert "newsletter" in str(screen.query_one("#rule-recipe-description", Static).render()).lower()
            screen.query_one("#rule-recipe-search", Input).value = ""
            screen.query_one("#rule-recipe-category", Select).value = "Safety"
            await pilot.pause()
            assert [recipe.id for recipe in screen.recipes] == ["spam"]
            await pilot.click("#rule-recipe-use")
            await pilot.pause()

        assert selected == ["spam"]

    asyncio.run(scenario())


def test_recipe_editor_exposes_generic_actions_scope_and_advanced_options() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        rule = materialize_recipe("spam", rule_id="spam", action=RuleAction.KEEP)
        editor = RoutingRuleEditorScreen(rule, ("INBOX.Trash",), RuleSet((rule,)), existing_id="spam")
        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(editor)
            await pilot.pause()
            action = editor.query_one("#routing-rule-action", Select)
            assert action.value == "keep"
            assert not editor.query_one("#destination-fields", Vertical).display
            assert editor.query_one("#routing-rule-scope", Input).value == ""
            assert editor.query_one("#recipe-options-spam", Vertical).display
            action.value = "move"
            await pilot.pause()
            assert editor.query_one("#destination-fields", Vertical).display
            action.value = "keep"
            await pilot.pause()
            action.value = "delete"
            await pilot.pause()
            assert not editor.query_one("#destination-fields", Vertical).display
            assert editor.query_one("#delete-warning", Static).display

    asyncio.run(scenario())


def test_semantic_rule_editor_uses_multiline_text_area(advertising_description: str) -> None:
    rule = RoutingRule(
        id="advertising",
        enabled=True,
        type=RuleType.SEMANTIC,
        action=RuleAction.KEEP,
        match_at=0.9,
        description=advertising_description,
    )

    async def scenario() -> None:
        app = _ScreenHost()
        editor = RoutingRuleEditorScreen(rule, ("INBOX",), RuleSet((rule,)), existing_id="advertising")
        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(editor)
            await pilot.pause()

            description = editor.query_one("#routing-rule-description", TextArea)
            assert description.text == advertising_description
            assert description.soft_wrap is True
            assert description.show_line_numbers is False
            assert description.size.height >= 12
            assert not isinstance(description, Input)

    asyncio.run(scenario())


def test_semantic_rule_editor_saves_multiline_description_without_flattening(advertising_description: str) -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        editor = RoutingRuleEditorScreen(None, ("INBOX",), RuleSet())
        saved: list[RoutingRule | None] = []

        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(editor, saved.append)
            await pilot.pause()
            editor.query_one("#routing-rule-id", Input).value = "advertising"
            editor.query_one("#routing-rule-description", TextArea).text = f"\n{advertising_description}\n  "
            editor.query_one("#routing-rule-action", Select).value = RuleAction.KEEP.value
            await pilot.click("#save")
            await pilot.pause()

        assert len(saved) == 1
        assert saved[0] is not None
        assert saved[0].description == advertising_description

    asyncio.run(scenario())


def test_rules_toml_preview_shows_an_ordinary_spam_recipe() -> None:
    rule = materialize_recipe("spam", rule_id="spam", action=RuleAction.KEEP)
    rules = RuleSet((rule,))
    assert "[[rules.rule]]" in render_routing_rules(rules)

    async def scenario() -> None:
        app = _ScreenHost()
        screen = RuleTomlPreviewScreen(None, rules)
        async with app.run_test(size=(110, 30)) as pilot:
            app.push_screen(screen)
            await pilot.pause()
            text = str(screen.query_one("#rule-toml-preview-text", Static).render())
            assert 'id = "spam"' in text
            assert 'recipe = "spam"' in text
            assert 'action = "keep"' in text

    asyncio.run(scenario())


def test_rules_workbench_and_removal_are_keyboard_operable() -> None:
    async def scenario() -> None:
        app = _ScreenHost()
        rules = RuleSet(
            (
                RoutingRule(
                    id="first",
                    enabled=True,
                    type=RuleType.SEMANTIC,
                    action=RuleAction.KEEP,
                    match_at=0.9,
                    description="First rule",
                ),
                RoutingRule(
                    id="second",
                    enabled=True,
                    type=RuleType.SEMANTIC,
                    action=RuleAction.KEEP,
                    match_at=0.9,
                    description="Second rule",
                ),
            )
        )
        center = RoutingRuleCenterScreen(rules, ())
        center_result: list[object] = []

        async with app.run_test(size=(110, 36)) as pilot:
            app.push_screen(center, center_result.append)
            await pilot.pause()
            assert app.focused is center.query_one("#routing-rule-list")
            await pilot.press("down", "enter")
            await pilot.pause()
            assert center_result == [("edit", "second")]

            confirmation = RuleRemovalConfirmation(rules.rules[1])
            cancelled: list[object] = []
            app.push_screen(confirmation, cancelled.append)
            await pilot.pause()
            cancel = confirmation.query_one("#rule-removal-cancel", Button)
            assert app.focused is cancel
            await pilot.press("enter")
            await pilot.pause()
            assert cancelled == [False]

            confirmation = RuleRemovalConfirmation(rules.rules[1])
            removed: list[object] = []
            app.push_screen(confirmation, removed.append)
            await pilot.pause()
            await pilot.press("tab")
            assert app.focused is confirmation.query_one("#rule-removal-confirm", Button)
            await pilot.press("enter")
            await pilot.pause()
            assert removed == [True]

    asyncio.run(scenario())
