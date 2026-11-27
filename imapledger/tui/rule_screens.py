from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Label, ListItem, ListView, Select, Static

from ..application.rules import RuleLearningPreview, RuleMigrationPreview
from ..routing_actions import RuleAction
from ..routing_config import RULE_SCHEMA, render_routing_rules
from ..routing_models import RoutingRule, RuleType
from ..routing_models import RuleSet as RoutingRuleSet
from ..rule_recipes import get_runtime_recipe, list_recipes
from ..rules import MATCH_FIELDS, RuleMatch, describe_match, validate_rule_id
from .modal import KeyboardModalScreen


class RuleTestResultScreen(KeyboardModalScreen[None]):
    BINDINGS = [("escape", "close", "Close"), ("q", "close", "Close")]

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def compose(self) -> ComposeResult:
        yield Static(self.text, markup=False)
        yield Button("Close", id="close")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class RoutingRuleCenterScreen(KeyboardModalScreen[tuple[str, str | None]]):
    BINDINGS = [
        ("escape", "close", "Close"),
        ("n", "new_rule", "New"),
        ("e", "edit_rule", "Edit"),
        ("space", "toggle_rule", "Enable/disable"),
        ("[", "move_up", "Move up"),
        ("]", "move_down", "Move down"),
        ("d", "remove_rule", "Delete"),
        ("t", "test_rule", "Test selected"),
        ("T", "test_all", "Evaluate all"),
        ("m", "migrate_rules", "Migrate legacy"),
        ("r", "browse_recipes", "Browse recipes"),
    ]
    CSS = """
    RoutingRuleCenterScreen { align: center middle; }
    #routing-rule-center { width: 96%; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #routing-rule-list { height: 1fr; }
    #routing-rule-center Horizontal { height: 3; }
    #routing-rule-center Button { margin-right: 1; }
    """

    def __init__(self, rules: RoutingRuleSet, folders: tuple[str, ...]) -> None:
        super().__init__()
        self.rules = rules
        self.folders = folders

    def compose(self) -> ComposeResult:
        enabled = sum(rule.enabled for rule in self.rules.rules)
        with Vertical(id="routing-rule-center"):
            yield Static(f"Rules · {len(self.rules.rules)} rules · {enabled} enabled", markup=False)
            yield ListView(
                *[
                    ListItem(Label(self._rule_label(index, rule)))
                    for index, rule in enumerate(self.rules.rules, start=1)
                ],
                id="routing-rule-list",
            )
            if not self.rules.rules:
                yield Static(
                    "No rules yet. Browse recipes to create a rule, or start with a semantic or header rule.",
                    id="routing-rule-empty",
                    markup=False,
                )
            yield Static(
                "No match keeps mail in its current folder. Priority is top to bottom; the first match wins.",
                markup=False,
            )
            with Horizontal():
                yield Button("New rule", id="new")
                yield Button("Browse recipes", id="recipes")
                yield Button("Edit", id="edit")
                yield Button("Enable/disable", id="toggle")
                yield Button("Move up", id="up")
                yield Button("Move down", id="down")
            with Horizontal():
                yield Button("Test selected", id="test")
                yield Button("Evaluate all", id="test-all")
                yield Button("Migrate legacy rules…", id="migrate")
                yield Button("Delete rule", id="remove")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        super().on_mount()
        if self.rules.rules:
            self.query_one("#routing-rule-list", ListView).index = 0
        self.query_one("#routing-rule-list", ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "routing-rule-list":
            self.dismiss(("edit", self._selected_rule_id()))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id or "close"
        self.dismiss((action, self._selected_rule_id()))

    def action_new_rule(self) -> None:
        self.dismiss(("new", None))

    def action_edit_rule(self) -> None:
        self.dismiss(("edit", self._selected_rule_id()))

    def action_toggle_rule(self) -> None:
        self.dismiss(("toggle", self._selected_rule_id()))

    def action_move_up(self) -> None:
        self.dismiss(("up", self._selected_rule_id()))

    def action_move_down(self) -> None:
        self.dismiss(("down", self._selected_rule_id()))

    def action_remove_rule(self) -> None:
        self.dismiss(("remove", self._selected_rule_id()))

    def action_test_rule(self) -> None:
        self.dismiss(("test", self._selected_rule_id()))

    def action_test_all(self) -> None:
        self.dismiss(("test-all", None))

    def action_browse_recipes(self) -> None:
        self.dismiss(("recipes", None))

    def action_migrate_rules(self) -> None:
        self.dismiss(("migrate", None))

    def action_close(self) -> None:
        self.dismiss(("close", None))

    def _selected_rule_id(self) -> str | None:
        view = self.query_one("#routing-rule-list", ListView)
        if view.index is None or not 0 <= view.index < len(self.rules.rules):
            return None
        return self.rules.rules[view.index].id

    @staticmethod
    def _rule_label(index: int, rule: RoutingRule) -> str:
        status = "enabled" if rule.enabled else "disabled"
        if rule.type is RuleType.SEMANTIC:
            threshold = f" (threshold {rule.match_at:g})" if rule.match_at is not None else ""
            detail = f"{rule.description}{threshold}"
        elif rule.recipe is not None:
            detail = f"recipe={rule.recipe}"
        else:
            detail = " OR ".join(describe_match(match) for match in rule.match_any)
        action = rule.action.value.upper()
        if rule.destination is not None:
            action += f" -> {rule.destination}"
        scope = ", ".join(rule.source_folders) if rule.source_folders else "all folders"
        return f"{index:>2} {status:<8} {rule.id:<20} {rule.type.value:<9} {action:<24} [{scope}] {detail}"


class RoutingRuleEditorScreen(KeyboardModalScreen[RoutingRule | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    RoutingRuleEditorScreen { align: center middle; }
    #routing-rule-editor-box { width: 94%; height: 94%; border: round $accent; padding: 1 2; background: $surface; }
    #routing-rule-editor { height: 1fr; }
    #routing-rule-editor-box Horizontal { height: 3; align-horizontal: right; }
    #routing-rule-editor-box Button { margin-left: 1; }
    """

    def __init__(
        self,
        rule: RoutingRule | None,
        folders: tuple[str, ...],
        rules: RoutingRuleSet,
        *,
        existing_id: str | None = None,
        rules_path: Path | None = None,
    ) -> None:
        super().__init__()
        self.rule = rule
        self.folders = tuple(dict.fromkeys((*folders, *((rule.destination,) if rule and rule.destination else ()))))
        self.rules = rules
        self.existing_id = existing_id
        self.rules_path = rules_path
        self.runtime_recipes = tuple(spec for spec in list_recipes() if spec.runtime_recipe is not None)

    def compose(self) -> ComposeResult:
        rule = self.rule
        recipe_id = (
            rule.recipe
            if rule is not None and rule.recipe is not None
            else (self.runtime_recipes[0].runtime_recipe if self.runtime_recipes else None)
        )
        recipe_specs = tuple(spec for spec in self.runtime_recipes if spec.runtime_recipe is not None)
        with Vertical(id="routing-rule-editor-box"):
            with VerticalScroll(id="routing-rule-editor"):
                yield Static("Edit rule" if self.existing_id else "New rule", markup=False)
                yield Label("Rule ID")
                yield Input(rule.id if rule else "", placeholder="newsletter", id="routing-rule-id")
                yield Checkbox("Enabled", value=rule.enabled if rule else True, id="routing-rule-enabled")
                yield Label("Rule type")
                yield Select(
                    [(item.value.title(), item.value) for item in RuleType],
                    value=rule.type.value if rule else RuleType.SEMANTIC.value,
                    allow_blank=False,
                    id="routing-rule-type",
                )
                with Vertical(id="semantic-fields"):
                    yield Label("What mail should this rule match?")
                    yield Input(
                        rule.description or "" if rule else "",
                        placeholder="Rule description",
                        id="routing-rule-description",
                    )
                    yield Label("Semantic match threshold")
                    yield Input(
                        str(rule.match_at if rule and rule.match_at is not None else self.rules.default_match_at),
                        id="routing-rule-threshold",
                    )
                with Vertical(id="header-fields"):
                    yield Static("Header matcher fields, combined with AND", markup=False)
                    match = rule.match_any[0].as_dict() if rule is not None and rule.match_any else {}
                    for field in MATCH_FIELDS:
                        yield Input(match.get(field, ""), placeholder=field, id=f"routing-match-{field}")
                with Vertical(id="recipe-fields"):
                    yield Label("Recipe")
                    yield Select(
                        [(f"{spec.title} · {spec.category}", spec.runtime_recipe) for spec in recipe_specs],
                        value=recipe_id or Select.NULL,
                        allow_blank=False,
                        id="routing-rule-recipe",
                    )
                    yield Checkbox(
                        "Show advanced recipe options",
                        value=bool(rule and rule.options),
                        id="recipe-advanced",
                    )
                    for spec in recipe_specs:
                        runtime = get_runtime_recipe(spec.runtime_recipe or "")
                        current_options = rule.options if rule and rule.recipe == spec.runtime_recipe else {}
                        with Vertical(id=f"recipe-options-{spec.runtime_recipe}"):
                            for option in runtime.spec.options_schema:
                                yield Label(f"{option.title}: {option.description}")
                                value = current_options.get(option.key, option.default)
                                yield Input(str(value), id=f"recipe-option-{spec.runtime_recipe}-{option.key}")
                yield Label("Source folder scope (comma-separated, blank means all folders)")
                yield Input(", ".join(rule.source_folders) if rule else "", id="routing-rule-scope")
                yield Label("Action")
                yield Select(
                    [(action.value.title(), action.value) for action in RuleAction],
                    value=rule.action.value if rule else RuleAction.MOVE.value,
                    allow_blank=False,
                    id="routing-rule-action",
                )
                with Vertical(id="destination-fields"):
                    yield Label("Move destination")
                    yield Select(
                        [(folder, folder) for folder in self.folders],
                        value=rule.destination
                        if rule and rule.destination
                        else (self.folders[0] if self.folders else Select.NULL),
                        prompt="Choose an existing folder",
                        allow_blank=True,
                        id="routing-rule-destination",
                    )
                yield Static(
                    "Delete actions require explicit authorization during apply.",
                    id="delete-warning",
                    markup=False,
                )
                yield Static("", id="routing-rule-error", markup=False)
            with Horizontal():
                yield Button("Preview TOML", id="preview-toml")
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        super().on_mount()
        self._update_type_fields()

        self.query_one("#routing-rule-id", Input).focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id in {"routing-rule-type", "routing-rule-action", "routing-rule-recipe"}:
            self._update_type_fields()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "recipe-advanced":
            self._update_type_fields()

    def _update_type_fields(self) -> None:
        selected = self.query_one("#routing-rule-type", Select).value
        if not isinstance(selected, str):
            return
        rule_type = RuleType(selected)
        self.query_one("#semantic-fields", Vertical).display = rule_type is RuleType.SEMANTIC
        self.query_one("#header-fields", Vertical).display = rule_type is RuleType.HEADER
        recipe_fields = self.query_one("#recipe-fields", Vertical)
        recipe_fields.display = rule_type is RuleType.RECIPE
        action_value = self.query_one("#routing-rule-action", Select).value
        action = RuleAction(action_value) if isinstance(action_value, str) else RuleAction.MOVE
        self.query_one("#destination-fields", Vertical).display = action is RuleAction.MOVE
        self.query_one("#delete-warning", Static).display = action is RuleAction.DELETE
        advanced = self.query_one("#recipe-advanced", Checkbox).value
        recipe_id = self.query_one("#routing-rule-recipe", Select).value
        for spec in self.runtime_recipes:
            if spec.runtime_recipe is not None:
                self.query_one(f"#recipe-options-{spec.runtime_recipe}", Vertical).display = (
                    rule_type is RuleType.RECIPE and advanced and recipe_id == spec.runtime_recipe
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            rule = self._read_rule()
            if event.button.id == "preview-toml":
                self.app.push_screen(RuleTomlPreviewScreen(self.rules_path, self._candidate_rules(rule)))
                return
        except (ValueError, TypeError) as exc:
            self.query_one("#routing-rule-error", Static).update(str(exc))
            return
        self.dismiss(rule)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _read_rule(self) -> RoutingRule:
        rule_id = validate_rule_id(self.query_one("#routing-rule-id", Input).value.strip())
        type_value = self.query_one("#routing-rule-type", Select).value
        if not isinstance(type_value, str):
            raise ValueError("Choose a rule type.")
        rule_type = RuleType(type_value)
        action_value = self.query_one("#routing-rule-action", Select).value
        if not isinstance(action_value, str):
            raise ValueError("Choose a rule action.")
        action = RuleAction(action_value)
        destination = None
        if action is RuleAction.MOVE:
            selected_destination = self.query_one("#routing-rule-destination", Select).value
            if not isinstance(selected_destination, str):
                raise ValueError("Choose an existing destination folder for MOVE.")
            destination = selected_destination
        source_text = self.query_one("#routing-rule-scope", Input).value
        source_folders = tuple(folder.strip() for folder in source_text.split(",") if folder.strip())
        if len(source_folders) != len(set(source_folders)):
            raise ValueError("Source folder scope must not contain duplicates.")

        description = None
        match_at = None
        match = None
        match_any: tuple[RuleMatch, ...] = ()
        recipe = None
        options: dict[str, object] = {}
        if rule_type is RuleType.SEMANTIC:
            description = self.query_one("#routing-rule-description", Input).value.strip() or None
            if description is None:
                raise ValueError("A semantic rule requires a description.")
            threshold_text = self.query_one("#routing-rule-threshold", Input).value.strip()
            match_at = float(threshold_text)
            if self.rule is not None and self.rule.type is RuleType.SEMANTIC:
                match_any = self.rule.match_any
        elif rule_type is RuleType.HEADER:
            values = {
                field: widget.value.strip()
                for field in MATCH_FIELDS
                if (widget := self.query_one(f"#routing-match-{field}", Input)).value.strip()
            }
            match = RuleMatch(**values)
            match_any = (match,)
            if self.rule is not None and self.rule.type is RuleType.HEADER:
                match_any = (*match_any, *self.rule.match_any[1:])
        else:
            recipe_value = self.query_one("#routing-rule-recipe", Select).value
            if not isinstance(recipe_value, str):
                raise ValueError("Choose a recipe from the shared catalog.")
            runtime = get_runtime_recipe(recipe_value)
            recipe = recipe_value
            for option in runtime.spec.options_schema:
                text = self.query_one(f"#recipe-option-{recipe_value}-{option.key}", Input).value.strip()
                options[option.key] = float(text)
            options = dict(runtime.validate_options(options))
            if self.rule is not None and self.rule.type is RuleType.RECIPE:
                match_any = self.rule.match_any

        return RoutingRule(
            id=rule_id,
            enabled=self.query_one("#routing-rule-enabled", Checkbox).value,
            type=rule_type,
            action=action,
            destination=destination,
            description=description,
            match_at=match_at,
            match=match,
            source_folders=source_folders,
            match_any=match_any,
            recipe=recipe,
            options=options,
        )

    def _candidate_rules(self, candidate: RoutingRule) -> RoutingRuleSet:
        rules = list(self.rules.rules)
        if self.existing_id is None:
            rules.append(candidate)
        else:
            try:
                index = next(index for index, rule in enumerate(rules) if rule.id == self.existing_id)
            except StopIteration as exc:
                raise ValueError("The rule changed while the editor was open. Reopen the workbench.") from exc
            rules[index] = candidate
        return RoutingRuleSet(
            tuple(rules),
            fallback_destination=self.rules.fallback_destination,
            default_match_at=self.rules.default_match_at,
            evidence=self.rules.evidence,
        )


class RuleLearnTargetScreen(KeyboardModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    RuleLearnTargetScreen { align: center middle; }
    #learn-target-box { width: 72; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #learn-target-buttons { height: 3; align-horizontal: right; }
    #learn-target-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, uid: int, rules: RoutingRuleSet) -> None:
        super().__init__()
        self.folder = folder
        self.uid = uid
        self.rules = tuple(rule for rule in rules.rules if rule.type is RuleType.SEMANTIC)

    def compose(self) -> ComposeResult:
        options = [(f"{rule.id} · {rule.description}", rule.id) for rule in self.rules]
        with Vertical(id="learn-target-box"):
            yield Static(f"Learn this mail from {self.folder} UID {self.uid}", markup=False)
            yield Label("Strengthen an existing semantic rule")
            yield Select(
                options,
                value=self.rules[0].id if self.rules else Select.NULL,
                allow_blank=not self.rules,
                id="learn-target-rule",
            )
            yield Static("Learning only adds a deterministic matcher. The example message is not moved.", markup=False)
            with Horizontal(id="learn-target-buttons"):
                yield Button("Preview matcher", id="learn-preview", disabled=not bool(self.rules), variant="primary")
                yield Button("Cancel", id="learn-cancel")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#learn-target-rule", Select).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "learn-cancel":
            self.dismiss(None)
            return
        rule_id = self.query_one("#learn-target-rule", Select).value
        self.dismiss(rule_id if isinstance(rule_id, str) else None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RuleLearnPreviewScreen(KeyboardModalScreen[bool]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    RuleLearnPreviewScreen { align: center middle; }
    #learn-preview-box { width: 82; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #learn-preview-buttons { height: 3; align-horizontal: right; }
    #learn-preview-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, uid: int, preview: RuleLearningPreview) -> None:
        super().__init__()
        self.folder = folder
        self.uid = uid
        self.preview = preview

    def compose(self) -> ComposeResult:
        preview = self.preview
        lines = [
            f"Source: {self.folder} UID {self.uid}",
            f"Target rule: {preview.target_rule_id}",
            f"Proposal status: {preview.status}",
        ]
        if preview.semantic_fit is not None:
            lines.append(f"Semantic fit: {preview.semantic_fit:.2f}")
        if preview.selected_candidate is not None:
            lines.extend(
                (
                    f"Candidate: {preview.selected_candidate.description}",
                    f"Matcher: {describe_match(preview.selected_candidate.match)}",
                )
            )
        if preview.candidate_confidence is not None:
            lines.append(f"Candidate confidence: {preview.candidate_confidence:.2f}")
        if preview.safe_probability is not None:
            lines.append(f"Generalization safety: {preview.safe_probability:.2f}")
        if preview.conflict_rule_id is not None:
            lines.append(f"Conflict: the same matcher is attached to higher-priority rule {preview.conflict_rule_id}.")
        saveable = preview.status == "auto" and preview.proposed_matcher is not None
        if not saveable:
            lines.append("No matcher can be saved from this proposal.")
        with Vertical(id="learn-preview-box"):
            yield Static("\n".join(lines), markup=False)
            with Horizontal(id="learn-preview-buttons"):
                yield Button("Save matcher", id="learn-save", disabled=not saveable, variant="primary")
                yield Button("Close", id="learn-close")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#learn-close", Button).focus()

    def action_close(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "learn-save")


class RuleRecipeCatalogScreen(KeyboardModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Close")]
    CSS = """
    RuleRecipeCatalogScreen { align: center middle; }
    #rule-recipe-catalog { width: 94%; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #rule-recipe-list { height: 1fr; }
    #rule-recipe-buttons { height: 3; align-horizontal: right; }
    #rule-recipe-buttons Button { margin-left: 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.recipes = list_recipes()

    def compose(self) -> ComposeResult:
        categories = ("All", *sorted({recipe.category for recipe in self.recipes}))
        with Vertical(id="rule-recipe-catalog"):
            yield Static("Browse rule recipes", markup=False)
            with Horizontal():
                yield Input(placeholder="Search recipes", id="rule-recipe-search")
                yield Select([(category, category) for category in categories], value="All", id="rule-recipe-category")
            yield ListView(id="rule-recipe-list")
            yield Static("Select a recipe to view its description.", id="rule-recipe-description", markup=False)
            with Horizontal(id="rule-recipe-buttons"):
                yield Button("Use recipe", id="rule-recipe-use", disabled=True, variant="primary")
                yield Button("Cancel", id="rule-recipe-cancel")

    def on_mount(self) -> None:
        super().on_mount()
        self._refresh()
        self.query_one("#rule-recipe-search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "rule-recipe-search":
            self._refresh()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "rule-recipe-category":
            self._refresh()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id == "rule-recipe-list":
            self._show_selected_description()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "rule-recipe-list":
            self.dismiss(self._selected_recipe_id())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "rule-recipe-cancel":
            self.dismiss(None)
        else:
            self.dismiss(self._selected_recipe_id())

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _refresh(self) -> None:
        if not self.is_mounted:
            return
        category = self.query_one("#rule-recipe-category", Select).value
        search = self.query_one("#rule-recipe-search", Input).value.strip()
        self.recipes = list_recipes(category=category if isinstance(category, str) else None, search=search)
        view = self.query_one("#rule-recipe-list", ListView)
        view.clear()
        for recipe in self.recipes:
            view.append(ListItem(Label(f"{recipe.title} · {recipe.category} · {recipe.summary}")))
        view.index = 0 if self.recipes else None
        self.query_one("#rule-recipe-use", Button).disabled = not bool(self.recipes)
        self._show_selected_description()

    def _selected_recipe_id(self) -> str | None:
        view = self.query_one("#rule-recipe-list", ListView)
        if view.index is None or not 0 <= view.index < len(self.recipes):
            return None
        return self.recipes[view.index].id

    def _show_selected_description(self) -> None:
        recipe_id = self._selected_recipe_id()
        recipe = next((item for item in self.recipes if item.id == recipe_id), None)
        text = (
            f"{recipe.description}\n\nDefault rule ID: {recipe.default_rule_id}" if recipe else "No matching recipes."
        )
        self.query_one("#rule-recipe-description", Static).update(text)


class RuleTomlPreviewScreen(KeyboardModalScreen[None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    RuleTomlPreviewScreen { align: center middle; }
    #rule-toml-preview { width: 92%; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #rule-toml-preview-text { height: 1fr; }
    """

    def __init__(self, path: Path | None, rules: RoutingRuleSet) -> None:
        super().__init__()
        self.path = path
        self.text = render_routing_rules(rules)

    def compose(self) -> ComposeResult:
        with Vertical(id="rule-toml-preview"):
            yield Static(f"TOML preview: {self.path or 'rules.toml'}", markup=False)
            with VerticalScroll():
                yield Static(self.text, id="rule-toml-preview-text", markup=False)
            yield Button("Close", id="rule-toml-preview-close")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#rule-toml-preview-close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class RuleRemovalConfirmation(KeyboardModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, rule: RoutingRule) -> None:
        super().__init__()
        self.rule = rule

    def compose(self) -> ComposeResult:
        with Vertical(id="rule-removal-confirmation"):
            yield Static(
                f"Remove rule {self.rule.id}? This changes rules.toml only and does not move or delete mail.",
                markup=False,
            )
            with Horizontal():
                yield Button("Cancel", id="rule-removal-cancel")
                yield Button("Remove rule", id="rule-removal-confirm", variant="error")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#rule-removal-cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "rule-removal-confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class RuleMigrationPreviewScreen(KeyboardModalScreen[tuple[bool, bool]]):
    BINDINGS = [("escape", "cancel", "Close")]
    CSS = """
    RuleMigrationPreviewScreen { align: center middle; }
    #rule-migration-box { width: 88; height: 82%; border: round $warning; padding: 1 2; background: $surface; }
    #rule-migration-buttons { height: 3; align-horizontal: right; }
    #rule-migration-buttons Button { margin-left: 1; }
    """

    def __init__(self, path: Path, preview: RuleMigrationPreview) -> None:
        super().__init__()
        self.path = path
        self.preview = preview
        self.requires_delete_authorization = any(
            rule.action is RuleAction.DELETE for rule in preview.result.rules.rules
        )

    def compose(self) -> ComposeResult:
        result = self.preview.result
        lines = [
            f"Rules file: {self.path}",
            f"Schema: {result.source_schema} to {RULE_SCHEMA}",
            f"Converted rules: {len(result.rules.rules)}",
        ]
        lines.extend(
            f"{rule.id}: {rule.type.value} {rule.action.value} -> {rule.destination or '(none)'}; "
            f"matchers: {' OR '.join(describe_match(match) for match in rule.match_any) or '(none)'}"
            for rule in result.rules.rules
        )
        lines.extend(result.warnings)
        lines.append(f"No match keeps mail in place. Applying writes schema-{RULE_SCHEMA} rules to this file.")
        if self.requires_delete_authorization:
            lines.append("The conversion includes DELETE actions. Explicit authorization is required to apply it.")
        with Vertical(id="rule-migration-box"):
            yield Static("\n".join(lines), markup=False)
            if self.requires_delete_authorization:
                yield Checkbox("Authorize migration of DELETE rules", id="rule-migration-allow-delete")
            with Horizontal(id="rule-migration-buttons"):
                yield Button(
                    "Apply migration",
                    id="rule-migration-apply",
                    variant="warning",
                    disabled=self.requires_delete_authorization,
                )
                yield Button("Close", id="rule-migration-close")

    def on_mount(self) -> None:
        super().on_mount()
        self.query_one("#rule-migration-close", Button).focus()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "rule-migration-allow-delete":
            self.query_one("#rule-migration-apply", Button).disabled = not event.checkbox.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "rule-migration-apply":
            self.dismiss((False, False))
            return
        allow_delete = (
            self.requires_delete_authorization and self.query_one("#rule-migration-allow-delete", Checkbox).value
        )
        self.dismiss((True, allow_delete))

    def action_cancel(self) -> None:
        self.dismiss((False, False))
