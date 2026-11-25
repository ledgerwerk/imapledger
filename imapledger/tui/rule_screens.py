from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, ListItem, ListView, Static

from ..classification_state import SpamOutcome
from ..config import ActionKind, MessageAction, Settings
from ..rule_candidates import build_rule_candidates
from ..rules import MATCH_FIELDS, MailRule, RuleMatch, RuleSet, describe_match, generate_rule_id, validate_rule_id


class ActionCenterScreen(ModalScreen[str]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        description: str,
        *,
        scope_warning: str | None = None,
        keep_label: str = "Apply KEEP / persist classification",
    ) -> None:
        super().__init__()
        self.description = description
        self.scope_warning = scope_warning
        self.keep_label = keep_label

    def compose(self) -> ComposeResult:
        with Vertical(id="action-center"):
            yield Static("Message action", markup=False)
            yield Static(self.description, markup=False)
            if self.scope_warning:
                yield Static(self.scope_warning, markup=False)
            if self.scope_warning is None:
                yield Button(self.keep_label, id="keep")
            yield Button("Create routing rule from this message", id="create-rule")
            yield Button("Change SPAM outcome policy", id="policy")
            yield Button("Open rule manager", id="rules")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id or "cancel")

    def action_cancel(self) -> None:
        self.dismiss("cancel")


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
            yield Static(f"Rules · {len(self.rules.rules)} rules · {enabled} enabled", markup=False)
            yield ListView(
                *[
                    ListItem(Label(f"{index}. {'✓' if rule.enabled else '✗'} {rule.id}  {describe_match(rule.match)}"))
                    for index, rule in enumerate(self.rules.rules, start=1)
                ],
                id="rule-list",
            )
            yield Static("Rules are evaluated top to bottom; first match wins.", markup=False)
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
                yield Static("Edit routing rule" if existing else "New routing rule", markup=False)
                yield Label("Rule ID")
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
                yield Label("Action: keep or move")
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
            raise ValueError("Routing rule action must be keep or move.")
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
            yield Static(f"Remove rule {self.rule.id}?\n{describe_match(self.rule.match)}", markup=False)
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
            f"Rule\n  ID: {rule.id}\n  Enabled: {'yes' if rule.enabled else 'no'}\n"
            f"  Priority: {self.priority} / {self.total}\n\nSources\n  {', '.join(rule.source_folders)}\n\n"
            f"Match\n  {describe_match(rule.match)}\n\nAction\n  {action}\n\n"
            f"Matches selected message: {'yes' if self.matches_current else 'no'}\n"
            f"Winning rule: {'yes' if self.winning else 'no'}",
            markup=False,
        )

    def action_close(self) -> None:
        self.dismiss()


class OutcomePolicyScreen(ModalScreen[SpamOutcome | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    def compose(self) -> ComposeResult:
        with Vertical(id="outcome-policy"):
            yield Static(
                "What should happen after semantic classification?\n"
                "Routing rules are separate and run before classification.",
                markup=False,
            )
            for outcome in SpamOutcome:
                action = getattr(self.settings.spam.actions, outcome.value)
                label = action.action.value.upper()
                if action.destination:
                    label += f" -> {action.destination}"
                yield Button(f"{outcome.value.upper()}  {label}  [Edit]", id=outcome.value)
            yield Button("Close", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        try:
            self.dismiss(SpamOutcome(event.button.id))
        except ValueError:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class OutcomeActionEditorScreen(ModalScreen[tuple[MessageAction, bool] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, outcome: SpamOutcome, action: MessageAction, destinations: tuple[str, ...]) -> None:
        super().__init__()
        self.outcome = outcome
        self.action = action
        self.destinations = destinations

    def compose(self) -> ComposeResult:
        action = self.action
        yield Static(f"{self.outcome.value.upper()} outcome action", markup=False)
        yield Static("Actions: keep, move" + (", delete" if self.outcome is SpamOutcome.SPAM else ""), markup=False)
        yield Input(action.action.value, id="outcome-action")
        yield Static("Available destination folders: " + ", ".join(self.destinations), markup=False)
        yield Input(action.destination or "", placeholder="existing destination folder", id="outcome-destination")
        yield Static(
            "DELETE changes the policy for every future SPAM classification in configured source folders. "
            "It is not limited to this sender or message.",
            id="delete-policy-warning",
            markup=False,
        )
        yield Button("Save policy", id="save")
        if self.outcome is SpamOutcome.SPAM:
            yield Button("Confirm global DELETE policy", id="save-delete", variant="error")
        yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            kind = ActionKind(self.query_one("#outcome-action", Input).value.strip().lower())
            if kind is ActionKind.DELETE and self.outcome is not SpamOutcome.SPAM:
                raise ValueError("DELETE is supported only for the SPAM outcome.")
            destination = self.query_one("#outcome-destination", Input).value.strip() or None
            action = MessageAction(kind, destination)
            if kind is ActionKind.DELETE and event.button.id != "save-delete":
                raise ValueError("Use the explicit global DELETE confirmation action to save this policy.")
            if kind is not ActionKind.DELETE and event.button.id == "save-delete":
                raise ValueError("The global DELETE confirmation is available only for DELETE.")
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
                "This changes the policy for every future message classified SPAM in configured source folders. "
                "It is not limited to the current sender or message. Continue with DELETE?",
                markup=False,
            )
            yield Button("Cancel", id="cancel")
            yield Button("Apply global DELETE policy", id="confirm", variant="error")

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
