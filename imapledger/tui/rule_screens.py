from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, ListItem, ListView, Select, Static

from ..application.rules import RuleLearningPreview, RuleMigrationPreview
from ..classification_state import SpamOutcome
from ..config import ActionKind, MessageAction, Settings
from ..routing_models import RoutingRule, RuleType
from ..routing_models import RuleSet as RoutingRuleSet
from ..rule_candidates import build_rule_candidates
from ..rules import MATCH_FIELDS, MailRule, RuleMatch, RuleSet, describe_match, generate_rule_id, validate_rule_id


class RuleCenterScreen(ModalScreen[tuple[str, str | None]]):
    BINDINGS = [
        ("escape", "cancel", "Close"),
        ("n", "new_rule", "New"),
        ("e", "edit_rule", "Edit"),
        ("space", "toggle_rule", "Enable/Disable"),
        ("t", "test_rule", "Test"),
        ("d", "remove_rule", "Remove"),
        ("[", "move_up", "Move up"),
        ("]", "move_down", "Move down"),
    ]
    CSS = """
    RuleCenterScreen { align: center middle; }
    #rule-center { width: 95%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #rule-list { height: 1fr; }
    #rule-center Horizontal { height: 3; }
    #rule-center Button { margin-right: 1; }
    """

    def __init__(self, rules: RuleSet) -> None:
        super().__init__()
        self.rules = rules

    def compose(self) -> ComposeResult:
        enabled = sum(rule.enabled for rule in self.rules.rules)
        with Vertical(id="rule-center"):
            yield Static(f"Routing Filters · {len(self.rules.rules)} filters · {enabled} enabled", markup=False)
            yield ListView(
                *[
                    ListItem(Label(f"{index}. {'✓' if rule.enabled else '✗'} {rule.id}  {describe_match(rule.match)}"))
                    for index, rule in enumerate(self.rules.rules, start=1)
                ],
                id="rule-list",
            )
            yield Static("Routing filters are evaluated top to bottom; first match wins.", markup=False)
            with Horizontal():
                yield Button("New", id="new")
                yield Button("Edit", id="edit")
                yield Button("Enable/Disable", id="toggle")
                yield Button("Move up", id="up")
            with Horizontal():
                yield Button("Move down", id="down")
                yield Button("Test", id="test")
                yield Button("Remove", id="remove")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        if self.rules.rules:
            self.query_one("#rule-list", ListView).index = 0
        self.query_one("#rule-list", ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.dismiss(("detail", self._selected_rule_id()))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id or "close"
        if action in {"new", "edit", "toggle", "up", "down", "test", "remove"}:
            self.dismiss((action, self._selected_rule_id()))
        else:
            self.dismiss(("close", None))

    def action_new_rule(self) -> None:
        self.dismiss(("new", None))

    def action_edit_rule(self) -> None:
        self.dismiss(("edit", self._selected_rule_id()))

    def action_toggle_rule(self) -> None:
        self.dismiss(("toggle", self._selected_rule_id()))

    def action_test_rule(self) -> None:
        self.dismiss(("test", self._selected_rule_id()))

    def action_remove_rule(self) -> None:
        self.dismiss(("remove", self._selected_rule_id()))

    def action_move_up(self) -> None:
        self.dismiss(("up", self._selected_rule_id()))

    def action_move_down(self) -> None:
        self.dismiss(("down", self._selected_rule_id()))

    def action_cancel(self) -> None:
        self.dismiss(("close", None))

    def _selected_rule_id(self) -> str | None:
        list_view = self.query_one("#rule-list", ListView)
        if list_view.index is None or not 0 <= list_view.index < len(self.rules.rules):
            return None
        return self.rules.rules[list_view.index].id


class RuleEditorScreen(ModalScreen[tuple[MailRule, bool] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    RuleEditorScreen { align: center middle; }
    #rule-editor-box { width: 90%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #rule-editor { height: 1fr; }
    #rule-editor-box Horizontal { height: 3; align-horizontal: right; }
    #rule-editor-box Button { margin-left: 1; }
    """

    def __init__(
        self,
        *,
        rule: MailRule | None,
        message: Any | None,
        current_folder: str | None,
        existing_ids: tuple[str, ...],
        source_folders: tuple[str, ...],
    ) -> None:
        super().__init__()
        self.rule = rule
        self.message = message
        self.current_folder = current_folder
        self.existing_ids = existing_ids
        self.source_folders = source_folders

    def compose(self) -> ComposeResult:
        existing = self.rule
        match = existing.match if existing else None
        match_values = match.as_dict() if match is not None else _default_match(self.message) if self.message else {}
        suggested_id = (
            existing.id
            if existing
            else (generate_rule_id(RuleMatch(**match_values), self.existing_ids) if match_values else "")
        )
        source = (
            existing.source_folders
            if existing
            else ((self.current_folder,) if self.current_folder in self.source_folders else ())
        )
        action = existing.action if existing else MessageAction(ActionKind.KEEP)
        with Vertical(id="rule-editor-box"):
            with VerticalScroll(id="rule-editor"):
                yield Static("Edit routing filter" if existing else "New routing filter", markup=False)
                yield Label("Filter ID")
                yield Input(suggested_id, placeholder="lowercase-id", id="rule-id")
                yield Label("Source folders (comma-separated, configured spam.folders only)")
                yield Input(", ".join(source), id="rule-sources")
                yield Label("Match fields, combined with AND")
                for field in MATCH_FIELDS:
                    yield Input(match_values.get(field, ""), placeholder=field, id=f"match-{field}")
                yield Static(
                    "All populated fields are combined with AND. "
                    "Broad domain and subject-only matches need explicit acknowledgement.",
                    id="rule-warning",
                    markup=False,
                )
                yield Checkbox("I understand this matcher is broad/fragile", id="broad-ack")
                yield Label("Filter action: keep or move")
                yield Input(action.action.value, id="rule-action")
                yield Label("Destination for move")
                yield Input(action.destination or "", placeholder="existing folder name", id="rule-destination")
            with Horizontal():
                yield Button("Save only", id="save")
                if self.message is not None:
                    yield Button("Save & apply current", id="save-apply")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            rule = self._read_rule()
        except ValueError as exc:
            self.query_one("#rule-warning", Static).update(str(exc))
            return
        self.dismiss((rule, event.button.id == "save-apply"))

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _read_rule(self) -> MailRule:
        rule_id = validate_rule_id(self.query_one("#rule-id", Input).value.strip())
        sources = tuple(
            folder.strip() for folder in self.query_one("#rule-sources", Input).value.split(",") if folder.strip()
        )
        if not sources:
            raise ValueError("At least one configured source folder is required.")
        outside = set(sources) - set(self.source_folders)
        if outside:
            raise ValueError(f"Source folder is outside spam.folders: {sorted(outside)[0]}")
        values = {
            field: widget.value.strip()
            for field in MATCH_FIELDS
            if (widget := self.query_one(f"#match-{field}", Input)).value.strip()
        }
        match = RuleMatch(**values)
        if set(values) in ({"from_domain"}, {"return_path_domain"}, {"subject"}, {"subject_prefix"}):
            if not self.query_one("#broad-ack", Checkbox).value:
                raise ValueError("Acknowledge the broad/fragile matcher warning before saving.")
        action_name = self.query_one("#rule-action", Input).value.strip().lower()
        if action_name not in {"keep", "move"}:
            raise ValueError("Routing filter action must be keep or move.")
        destination = self.query_one("#rule-destination", Input).value.strip() or None
        action = MessageAction(ActionKind(action_name), destination)
        return MailRule(rule_id, True if self.rule is None else self.rule.enabled, sources, action, match)


def _default_match(message: Any) -> dict[str, str]:
    candidates = {candidate.id: candidate for candidate in build_rule_candidates(message)}
    for candidate_id in ("from_address_exact", "list_id_exact", "return_path_address_exact"):
        candidate = candidates.get(candidate_id)
        if candidate is not None:
            return candidate.match.as_dict()
    return {}


class RuleDeleteConfirmation(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, rule: MailRule) -> None:
        super().__init__()
        self.rule = rule

    def compose(self) -> ComposeResult:
        with Vertical(id="rule-remove-confirmation"):
            yield Static(f"Remove routing filter {self.rule.id}?\n{describe_match(self.rule.match)}", markup=False)
            yield Button("Cancel", id="cancel")
            yield Button("Remove", id="remove", variant="error")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "remove")

    def action_cancel(self) -> None:
        self.dismiss(False)


class RuleDetailScreen(ModalScreen[None]):
    BINDINGS = [("escape", "close", "Close"), ("q", "close", "Close")]

    def __init__(self, rule: MailRule, priority: int, total: int, *, matches_current: bool, winning: bool) -> None:
        super().__init__()
        self.rule = rule
        self.priority = priority
        self.total = total
        self.matches_current = matches_current
        self.winning = winning

    def compose(self) -> ComposeResult:
        rule = self.rule
        action = rule.action.action.value.upper()
        if rule.action.destination:
            action += f" -> {rule.action.destination}"
        yield Static(
            f"Routing Filter\n  ID: {rule.id}\n  Enabled: {'yes' if rule.enabled else 'no'}\n"
            f"  Priority: {self.priority} / {self.total}\n\nSources\n  {', '.join(rule.source_folders)}\n\n"
            f"Match\n  {describe_match(rule.match)}\n\nAction\n  {action}\n\n"
            f"Matches selected message: {'yes' if self.matches_current else 'no'}\n"
            f"Winning rule: {'yes' if self.winning else 'no'}",
            markup=False,
        )

    def action_close(self) -> None:
        self.dismiss()


class ClassificationRulesScreen(ModalScreen[SpamOutcome | None]):
    BINDINGS = [("escape", "cancel", "Close")]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        with Vertical(id="classification-rules"):
            yield Static("Classification Rules", markup=False)
            yield Static(
                "These rules define what happens after classification.\n"
                "They apply to explicitly classified messages in any mailbox folder.",
                markup=False,
            )
            yield Static("Category       Action     Destination", markup=False)
            for outcome in SpamOutcome:
                action = getattr(self.settings.spam.actions, outcome.value)
                yield Button(
                    f"{outcome.value.upper():12} {action.action.value.upper():9} {action.destination or '-'}  Edit",
                    id=outcome.value,
                )
            folders = ", ".join(self.settings.spam.folders)
            yield Static(f"Automatic clean folders:\n  {folders}", markup=False)
            yield Static("The automatic clean folder list controls batch processing only.", markup=False)
            yield Button("Close", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            self.dismiss(SpamOutcome(event.button.id))
        except ValueError:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ClassificationRuleEditorScreen(ModalScreen[tuple[MessageAction, bool] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, outcome: SpamOutcome, action: MessageAction, destinations: tuple[str, ...]) -> None:
        super().__init__()
        self.outcome = outcome
        self.action = action
        self.destinations = destinations

    def compose(self) -> ComposeResult:
        action = self.action
        options = [("KEEP", ActionKind.KEEP.value), ("MOVE", ActionKind.MOVE.value)]
        if self.outcome is SpamOutcome.SPAM:
            options.append(("DELETE", ActionKind.DELETE.value))
        destination_options = [(folder, folder) for folder in self.destinations]
        destination_value = action.destination if action.destination in self.destinations else Select.NULL
        yield Static("Edit classification rule", markup=False)
        yield Static(f"When category is: {self.outcome.value.upper()}", markup=False)
        yield Label("Action")
        yield Select(options, value=action.action.value, allow_blank=False, id="outcome-action")
        yield Label("Destination for MOVE")
        yield Select(
            destination_options,
            prompt="Choose an existing folder",
            value=destination_value,
            allow_blank=True,
            id="outcome-destination",
        )
        yield Static(
            "Applies to any explicitly classified message, regardless of current folder.\n"
            "Batch clean remains limited to configured automatic clean folders.",
            markup=False,
        )
        yield Static(
            "DELETE changes the global action for future SPAM classifications. "
            "Saving the rule does not delete existing mail.",
            id="delete-policy-warning",
            markup=False,
        )
        yield Button("Save", id="save")
        if self.outcome is SpamOutcome.SPAM:
            yield Button("Save DELETE rule", id="save-delete", variant="error")
        yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            selected_action = self.query_one("#outcome-action", Select).value
            if selected_action is Select.NULL:
                raise ValueError("Choose a classification action.")
            kind = ActionKind(selected_action)
            if kind is ActionKind.DELETE and self.outcome is not SpamOutcome.SPAM:
                raise ValueError("DELETE is supported only for the SPAM category.")
            selected_destination = self.query_one("#outcome-destination", Select).value
            destination = selected_destination if isinstance(selected_destination, str) else None
            action = MessageAction(kind, destination if kind is ActionKind.MOVE else None)
            if kind is ActionKind.DELETE and event.button.id != "save-delete":
                raise ValueError("Use the explicit global DELETE confirmation action to save this rule.")
            if kind is not ActionKind.DELETE and event.button.id == "save-delete":
                raise ValueError("The DELETE confirmation is available only for a DELETE rule.")
        except ValueError as exc:
            self.query_one("#delete-policy-warning", Static).update(str(exc))
            return
        self.dismiss((action, event.button.id == "save-delete"))

    def action_cancel(self) -> None:
        self.dismiss(None)


class DeletePolicyConfirmation(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="delete-policy-confirmation"):
            yield Static(
                "This changes the global action for future messages classified SPAM in any folder. "
                "It is not limited to the current sender or message. Continue with DELETE?",
                markup=False,
            )
            yield Button("Cancel", id="cancel")
            yield Button("Save global DELETE action", id="confirm", variant="error")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class RuleTestResultScreen(ModalScreen[None]):
    BINDINGS = [("escape", "close", "Close"), ("q", "close", "Close")]

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def compose(self) -> ComposeResult:
        yield Static(self.text, markup=False)
        yield Button("Close", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class RoutingRuleCenterScreen(ModalScreen[tuple[str, str | None]]):
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
            yield Static(
                f"Fallback: {self.rules.fallback_destination or '(not configured)'}\n"
                "Priority is top to bottom. First matching rule wins.",
                markup=False,
            )
            yield Input(self.rules.fallback_destination or "", placeholder="INBOX.Processed", id="routing-fallback")
            with Horizontal():
                yield Button("New", id="new")
                yield Button("Edit", id="edit")
                yield Button("Enable/disable", id="toggle")
                yield Button("Move up", id="up")
                yield Button("Move down", id="down")
            with Horizontal():
                yield Button("Test selected", id="test")
                yield Button("Evaluate all", id="test-all")
                yield Button("Migrate legacy rules…", id="migrate")
                yield Button("Delete", id="remove")
                yield Button("Save fallback", id="fallback")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        if self.rules.rules:
            self.query_one("#routing-rule-list", ListView).index = 0
        self.query_one("#routing-rule-list", ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "routing-rule-list":
            self.dismiss(("edit", self._selected_rule_id()))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id or "close"
        if action == "fallback":
            value = self.query_one("#routing-fallback", Input).value.strip() or None
            self.dismiss((action, value))
        else:
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
        status = "yes" if rule.enabled else "no"
        match = (
            f">= {rule.match_at:g}"
            if rule.type is RuleType.SEMANTIC and rule.match_at is not None
            else "policy"
            if rule.type is RuleType.SPAM
            else describe_match(rule.match)
            if rule.match is not None
            else ""
        )
        return f"{index:>2}  {status:<3}  {rule.id:<20} {rule.type.value:<9} {rule.destination:<28} {match}"


class RoutingRuleEditorScreen(ModalScreen[RoutingRule | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    RoutingRuleEditorScreen { align: center middle; }
    #routing-rule-editor-box { width: 90%; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #routing-rule-editor { height: 1fr; }
    #routing-rule-editor-box Horizontal { height: 3; align-horizontal: right; }
    #routing-rule-editor-box Button { margin-left: 1; }
    """

    def __init__(self, rule: RoutingRule | None, folders: tuple[str, ...]) -> None:
        super().__init__()
        self.rule = rule
        self.folders = tuple(dict.fromkeys((*folders, *((rule.destination,) if rule else ()))))

    def compose(self) -> ComposeResult:
        rule = self.rule
        match = rule.match.as_dict() if rule is not None and rule.match is not None else {}
        with Vertical(id="routing-rule-editor-box"):
            with VerticalScroll(id="routing-rule-editor"):
                yield Static("Edit rule" if rule else "New rule", markup=False)
                yield Label("ID")
                yield Input(rule.id if rule else "", placeholder="newsletter", id="routing-rule-id")
                yield Checkbox("Enabled", value=rule.enabled if rule else True, id="routing-rule-enabled")
                yield Label("Type")
                yield Select(
                    [(item.value.title(), item.value) for item in RuleType],
                    value=rule.type.value if rule else RuleType.SEMANTIC.value,
                    allow_blank=False,
                    id="routing-rule-type",
                )
                yield Label("Destination")
                yield Select(
                    [(folder, folder) for folder in self.folders],
                    value=rule.destination if rule else (self.folders[0] if self.folders else Select.NULL),
                    prompt="Choose an existing folder",
                    allow_blank=False,
                    id="routing-rule-destination",
                )
                yield Label("Category description, required for semantic rules")
                yield Input(
                    rule.description or "" if rule else "",
                    placeholder="Define the category",
                    id="routing-rule-description",
                )
                yield Label("Match threshold, semantic rules only")
                yield Input(
                    str(rule.match_at if rule and rule.match_at is not None else 0.90),
                    id="routing-rule-threshold",
                )
                yield Static("Header matcher fields, combined with AND", markup=False)
                for field in MATCH_FIELDS:
                    yield Input(match.get(field, ""), placeholder=field, id=f"routing-match-{field}")
                yield Static(
                    "Spam uses the built-in conservative spam evidence policy. All rules route with MOVE.",
                    markup=False,
                )
                yield Static("", id="routing-rule-error", markup=False)
            with Horizontal():
                yield Button("Save", id="save")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            self.dismiss(self._read_rule())
        except (ValueError, TypeError) as exc:
            self.query_one("#routing-rule-error", Static).update(str(exc))

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _read_rule(self) -> RoutingRule:
        rule_id = validate_rule_id(self.query_one("#routing-rule-id", Input).value.strip())
        selected_type = self.query_one("#routing-rule-type", Select).value
        if not isinstance(selected_type, str):
            raise ValueError("Choose a rule type.")
        rule_type = RuleType(selected_type)
        selected_destination = self.query_one("#routing-rule-destination", Select).value
        if not isinstance(selected_destination, str):
            raise ValueError("Choose an existing destination folder.")
        description = self.query_one("#routing-rule-description", Input).value.strip() or None
        threshold_text = self.query_one("#routing-rule-threshold", Input).value.strip()
        match_at = float(threshold_text) if rule_type is RuleType.SEMANTIC else None
        values = {
            field: widget.value.strip()
            for field in MATCH_FIELDS
            if (widget := self.query_one(f"#routing-match-{field}", Input)).value.strip()
        }
        match = RuleMatch(**values) if rule_type is RuleType.HEADER else None
        return RoutingRule(
            id=rule_id,
            enabled=self.query_one("#routing-rule-enabled", Checkbox).value,
            type=rule_type,
            destination=selected_destination,
            description=description,
            match_at=match_at,
            match=match,
            source_folders=self.rule.source_folders if self.rule else (),
        )


class RuleLearnDialog(ModalScreen[tuple[str, str | None] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    RuleLearnDialog { align: center middle; }
    #learn-rule-box { width: 72; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #learn-rule-buttons { height: 3; align-horizontal: right; }
    #learn-rule-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, uid: int, destinations: tuple[str, ...]) -> None:
        super().__init__()
        self.folder = folder
        self.uid = uid
        self.destinations = destinations

    def compose(self) -> ComposeResult:
        options = [(folder, folder) for folder in self.destinations]
        with Vertical(id="learn-rule-box"):
            yield Static(f"Learn a routing rule from {self.folder} UID {self.uid}", markup=False)
            yield Label("Move destination")
            yield Select(
                options,
                value=self.destinations[0] if self.destinations else Select.BLANK,
                id="learn-destination",
            )
            yield Label("Optional rule ID")
            yield Input(placeholder="generated from the selected matcher", id="learn-rule-id")
            yield Static("A proposal is read-only. Only an automatically safe proposal can be saved.", markup=False)
            with Horizontal(id="learn-rule-buttons"):
                yield Button("Preview proposal", id="learn-preview", disabled=not bool(self.destinations))
                yield Button("Cancel", id="learn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "learn-cancel":
            self.dismiss(None)
            return
        destination = self.query_one("#learn-destination", Select).value
        if not isinstance(destination, str):
            return
        try:
            name = self.query_one("#learn-rule-id", Input).value.strip() or None
            if name is not None:
                validate_rule_id(name)
        except ValueError as exc:
            self.query_one("#learn-rule-id", Input).placeholder = str(exc)
            return
        self.dismiss((destination, name))

    def action_cancel(self) -> None:
        self.dismiss(None)


class RuleLearnPreviewScreen(ModalScreen[bool]):
    CSS = """
    RuleLearnPreviewScreen { align: center middle; }
    #learn-preview-box { width: 82; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #learn-preview-buttons { height: 3; align-horizontal: right; }
    #learn-preview-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, uid: int, destination: str, preview: RuleLearningPreview) -> None:
        super().__init__()
        self.folder = folder
        self.uid = uid
        self.destination = destination
        self.preview = preview

    def compose(self) -> ComposeResult:
        proposal = self.preview.proposal
        lines = [f"Source: {self.folder} UID {self.uid}", f"Status: {proposal.status}"]
        if proposal.candidate is not None:
            lines.extend(
                (
                    f"Candidate: {proposal.candidate.description}",
                    f"Match: {describe_match(proposal.candidate.match)}",
                )
            )
        if proposal.candidate_confidence is not None:
            lines.append(f"Jev confidence: {proposal.candidate_confidence:.2f}")
        if proposal.safe_probability is not None:
            lines.append(f"Generalization safety: {proposal.safe_probability:.2f}")
        if self.preview.rule is not None:
            lines.extend((f"Proposed rule: {self.preview.rule.id}", f"Action: move to {self.destination}"))
        else:
            lines.append("No rule can be saved. This proposal did not meet the safe automatic thresholds.")
        with Vertical(id="learn-preview-box"):
            yield Static("\n".join(lines), markup=False)
            with Horizontal(id="learn-preview-buttons"):
                yield Button("Save rule", id="learn-save", disabled=self.preview.rule is None)
                yield Button("Close", id="learn-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "learn-save")


class RuleMigrationPreviewScreen(ModalScreen[bool]):
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

    def compose(self) -> ComposeResult:
        result = self.preview.result
        lines = [
            f"Rules file: {self.path}",
            f"Schema: {result.source_schema} to 2",
            f"Converted rules: {len(result.rules.rules)}",
            f"Fallback: {result.rules.fallback_destination or '(not configured)'}",
        ]
        lines.extend(
            f"{rule.id}: {rule.destination} from "
            f"{', '.join(rule.source_folders) or 'all configured sources'}; "
            f"match {describe_match(rule.match) if rule.match else '(none)'}"
            for rule in result.rules.rules
        )
        lines.extend(result.warnings)
        lines.append("Preview only. Applying writes the converted schema-2 rules to this file.")
        with Vertical(id="rule-migration-box"):
            yield Static("\n".join(lines), markup=False)
            with Horizontal(id="rule-migration-buttons"):
                yield Button("Apply migration", id="rule-migration-apply", variant="warning")
                yield Button("Close", id="rule-migration-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "rule-migration-apply")
