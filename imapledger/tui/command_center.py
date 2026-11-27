from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Static

from ..application.operation_registry import OperationContext, OperationSpec
from .modal import KeyboardModalScreen


class CommandCenterScreen(KeyboardModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Close"), ("enter", "open_selected", "Open")]
    CSS = """
    CommandCenterScreen { align: center middle; }
    #command-center-box { width: 96%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #command-center-search { height: 3; }
    #command-center-table { height: 1fr; }
    #command-center-detail { height: 3; }
    #command-center-buttons { height: 3; align-horizontal: right; }
    #command-center-buttons Button { margin-left: 1; }
    """

    def __init__(self, specs: tuple[OperationSpec, ...], context: OperationContext) -> None:
        super().__init__()
        self.specs = tuple(spec for spec in specs if spec.tui_partner is not None)
        self.context = context
        self._visible: dict[str, OperationSpec] = {}
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="command-center-box"):
            yield Static("Command Center", markup=False)
            yield Input(placeholder="Search operations", id="command-center-search")
            yield DataTable(id="command-center-table", cursor_type="row")
            yield Static(
                "Select an operation to see availability and its TUI partner.",
                id="command-center-detail",
                markup=False,
            )
            with Horizontal(id="command-center-buttons"):
                yield Button("Open operation", id="command-center-open", disabled=True, variant="primary")
                yield Button("Close", id="command-center-close")

    def on_mount(self) -> None:
        super().on_mount()
        table = self.query_one("#command-center-table", DataTable)
        table.add_columns("Operation", "Availability", "CLI", "TUI partner")
        self._refresh_rows("")
        self.query_one("#command-center-search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "command-center-search":
            self._refresh_rows(event.value)

    def _refresh_rows(self, query: str) -> None:
        table = self.query_one("#command-center-table", DataTable)
        table.clear()
        self._visible = {}
        selected = self._selected_id
        normalized = query.casefold().strip()
        for spec in self.specs:
            searchable = " ".join((spec.title, spec.group, " ".join(spec.cli_path), spec.tui_partner or ""))
            if normalized and normalized not in searchable.casefold():
                continue
            reason = spec.unavailable_reason(self.context)
            availability = "available" if reason is None else f"disabled: {reason}"
            table.add_row(spec.title, availability, " ".join(spec.cli_path), spec.tui_partner or "", key=spec.id)
            self._visible[spec.id] = spec
        if selected not in self._visible:
            self._selected_id = None
        if self._visible:
            first = next(iter(self._visible))
            if self._selected_id is None:
                self._selected_id = first
            table.move_cursor(row=list(self._visible).index(self._selected_id))
            self._update_selection(self._selected_id)
        else:
            self._selected_id = None
            self.query_one("#command-center-detail", Static).update("No matching operations.")
            self.query_one("#command-center-open", Button).disabled = True

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        operation_id = event.row_key.value if event.row_key is not None else None
        if isinstance(operation_id, str):
            self._update_selection(operation_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        operation_id = event.row_key.value if event.row_key is not None else None
        if isinstance(operation_id, str):
            self._update_selection(operation_id)
            self.action_open_selected()

    def _update_selection(self, operation_id: str) -> None:
        spec = self._visible.get(operation_id)
        if spec is None:
            return
        self._selected_id = operation_id
        reason = spec.unavailable_reason(self.context)
        state = "Available" if reason is None else f"Unavailable: {reason}"
        self.query_one("#command-center-detail", Static).update(
            f"{state}\nCLI: {' '.join(spec.cli_path)} · {spec.mutability.value} · TUI: {spec.tui_partner}"
        )
        self.query_one("#command-center-open", Button).disabled = reason is not None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "command-center-close":
            self.dismiss(None)
        elif event.button.id == "command-center-open":
            self.action_open_selected()

    def action_open_selected(self) -> None:
        if self._selected_id is None:
            return
        spec = self._visible.get(self._selected_id)
        if spec is None:
            return
        if spec.unavailable_reason(self.context) is not None:
            self._update_selection(spec.id)
            return
        self.dismiss(spec.id)

    def action_cancel(self) -> None:
        self.dismiss(None)
