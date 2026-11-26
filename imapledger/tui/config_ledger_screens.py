from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static

from ..config_ledger import ConfigPullPreview, ConfigToolSummary, ConfigVersionRecord


@dataclass(frozen=True, slots=True)
class ConfigPushRequest:
    tool: str
    path: Path
    allow_sensitive_plaintext: bool
    resolve_conflict: bool


@dataclass(frozen=True, slots=True)
class ConfigPullRequest:
    tool: str
    version_id: str
    target: str | None


class ConfigLedgerScreen(ModalScreen[tuple[str, str] | None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    ConfigLedgerScreen { align: center middle; }
    #config-ledger-box { width: 96%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #config-ledger-table { height: 1fr; }
    #config-ledger-buttons { height: auto; }
    #config-ledger-buttons Button { margin-right: 1; margin-bottom: 1; }
    """

    def __init__(self, summaries: tuple[ConfigToolSummary, ...], *, store_folder: str) -> None:
        super().__init__()
        self.summaries = summaries
        self.store_folder = store_folder
        self._by_tool = {summary.tool: summary for summary in summaries}
        self._selected_tool: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="config-ledger-box"):
            yield Static(f"Config Ledger · IMAP folder {self.store_folder}", markup=False)
            yield Static(
                "Snapshots are stored as email. Push rejects likely plaintext secrets unless explicitly acknowledged.",
                markup=False,
            )
            yield DataTable(id="config-ledger-table", cursor_type="row")
            yield Static(
                "Select a tool or enter a tool name to push a new snapshot.",
                id="config-ledger-detail",
                markup=False,
            )
            with Horizontal(id="config-ledger-buttons"):
                yield Button("Versions", id="ledger-versions", disabled=True)
                yield Button("View", id="ledger-view", disabled=True)
                yield Button("Diff", id="ledger-diff", disabled=True)
                yield Button("Pull…", id="ledger-pull", disabled=True)
                yield Button("Push…", id="ledger-push")
                yield Button("Close", id="ledger-close")

    def on_mount(self) -> None:
        table = self.query_one("#config-ledger-table", DataTable)
        table.add_columns("Tool", "Versions", "Status", "Current", "Default path")
        for summary in self.summaries:
            table.add_row(
                summary.tool,
                str(summary.versions),
                summary.status.value,
                summary.current or "",
                summary.default_path or "",
                key=summary.tool,
            )
        if self.summaries:
            table.move_cursor(row=0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        tool = event.row_key.value if event.row_key is not None else None
        if isinstance(tool, str):
            self._select_tool(tool)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tool = event.row_key.value if event.row_key is not None else None
        if isinstance(tool, str):
            self.dismiss(("versions", tool))

    def _select_tool(self, tool: str) -> None:
        summary = self._by_tool.get(tool)
        if summary is None:
            return
        self._selected_tool = tool
        details = (
            f"{summary.status.value} · {summary.versions} version(s) · {summary.current or 'no unique current head'}"
        )
        if summary.details:
            details += "\n" + "; ".join(summary.details)
        self.query_one("#config-ledger-detail", Static).update(details)
        self.query_one("#ledger-versions", Button).disabled = summary.versions == 0
        for selector in ("#ledger-view", "#ledger-diff", "#ledger-pull"):
            self.query_one(selector, Button).disabled = not bool(summary.current)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "ledger-close":
            self.dismiss(None)
            return
        if button_id == "ledger-push":
            tool = self._selected_tool or ""
            self.dismiss(("push", tool))
            return
        if self._selected_tool is None:
            return
        action = {
            "ledger-versions": "versions",
            "ledger-view": "view",
            "ledger-diff": "diff",
            "ledger-pull": "pull",
        }.get(button_id)
        if action is not None:
            self.dismiss((action, self._selected_tool))

    def action_close(self) -> None:
        self.dismiss(None)


class ConfigVersionsScreen(ModalScreen[tuple[str, str, str] | None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    ConfigVersionsScreen { align: center middle; }
    #config-versions-box { width: 96%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #config-versions-table { height: 1fr; }
    #config-versions-buttons { height: 3; align-horizontal: right; }
    #config-versions-buttons Button { margin-left: 1; }
    """

    def __init__(self, tool: str, versions: tuple[ConfigVersionRecord, ...]) -> None:
        super().__init__()
        self.tool = tool
        self.versions = versions
        self._selected_version: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="config-versions-box"):
            yield Static(f"Config Ledger versions: {self.tool}", markup=False)
            yield DataTable(id="config-versions-table", cursor_type="row")
            yield Static("Select a snapshot version.", id="config-versions-detail", markup=False)
            with Horizontal(id="config-versions-buttons"):
                yield Button("View", id="version-view", disabled=True)
                yield Button("Diff…", id="version-diff", disabled=True)
                yield Button("Pull…", id="version-pull", disabled=True)
                yield Button("Close", id="version-close")

    def on_mount(self) -> None:
        table = self.query_one("#config-versions-table", DataTable)
        table.add_columns("Current", "Version", "Created", "SHA256", "Size", "Default path", "Parents")
        for record in self.versions:
            meta = record.meta
            marker = "CURRENT" if record.current else "HEAD" if record.head else ""
            table.add_row(
                marker,
                meta.version_id,
                meta.created_at.isoformat(),
                meta.content_sha256[:12],
                str(meta.size_bytes),
                meta.default_path,
                ", ".join(meta.parent_version_ids),
                key=meta.version_id,
            )
        if self.versions:
            table.move_cursor(row=0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        version_id = event.row_key.value if event.row_key is not None else None
        if isinstance(version_id, str):
            self._select_version(version_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        version_id = event.row_key.value if event.row_key is not None else None
        if isinstance(version_id, str):
            self.dismiss(("view", self.tool, version_id))

    def _select_version(self, version_id: str) -> None:
        record = next((item for item in self.versions if item.meta.version_id == version_id), None)
        if record is None:
            return
        self._selected_version = version_id
        meta = record.meta
        detail = (
            f"{'Current' if record.current else 'Head' if record.head else 'Historical'} · "
            f"{meta.size_bytes} bytes · SHA256 {meta.content_sha256}"
        )
        self.query_one("#config-versions-detail", Static).update(detail)
        for selector in ("#version-view", "#version-diff", "#version-pull"):
            self.query_one(selector, Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "version-close":
            self.dismiss(None)
        elif self._selected_version is not None:
            action = {
                "version-view": "view",
                "version-diff": "diff",
                "version-pull": "pull",
            }.get(event.button.id)
            if action is not None:
                self.dismiss((action, self.tool, self._selected_version))

    def action_close(self) -> None:
        self.dismiss(None)


class ConfigPushDialog(ModalScreen[ConfigPushRequest | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConfigPushDialog { align: center middle; }
    #config-push-box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #config-push-buttons { height: 3; align-horizontal: right; }
    #config-push-buttons Button { margin-left: 1; }
    """

    def __init__(self, tool: str) -> None:
        super().__init__()
        self.tool = tool

    def compose(self) -> ComposeResult:
        with Vertical(id="config-push-box"):
            yield Static("Push a local configuration snapshot to the configured IMAP folder.", markup=False)
            yield Label("Tool name")
            yield Input(value=self.tool, placeholder="tool", id="config-push-tool")
            yield Label("Local configuration file")
            yield Input(placeholder="/path/to/config.toml", id="config-push-path")
            yield Checkbox(
                "Allow detected sensitive values to be stored as readable email",
                id="config-push-sensitive",
            )
            yield Checkbox("Resolve conflicting current heads", id="config-push-conflict")
            yield Static("Push creates a remote snapshot. It does not modify the local file.", markup=False)
            yield Static("", id="config-push-error", markup=False)
            with Horizontal(id="config-push-buttons"):
                yield Button("Review push…", id="config-push-review", variant="primary")
                yield Button("Cancel", id="config-push-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "config-push-cancel":
            self.dismiss(None)
            return
        tool = self.query_one("#config-push-tool", Input).value.strip()
        path = self.query_one("#config-push-path", Input).value.strip()
        if not tool or not path:
            self.query_one("#config-push-error", Static).update("Tool name and local file path are required.")
            return
        request = ConfigPushRequest(
            tool=tool,
            path=Path(path).expanduser(),
            allow_sensitive_plaintext=self.query_one("#config-push-sensitive", Checkbox).value,
            resolve_conflict=self.query_one("#config-push-conflict", Checkbox).value,
        )
        self.dismiss(request)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfigPushConfirmation(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConfigPushConfirmation { align: center middle; }
    #config-push-confirm-box { width: 76; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #config-push-confirm-buttons { height: 3; align-horizontal: right; }
    #config-push-confirm-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: ConfigPushRequest, store_folder: str) -> None:
        super().__init__()
        self.request = request
        self.store_folder = store_folder

    def compose(self) -> ComposeResult:
        sensitive = (
            "Sensitive plaintext was explicitly allowed."
            if self.request.allow_sensitive_plaintext
            else "Sensitive plaintext detection remains fail-closed."
        )
        with Vertical(id="config-push-confirm-box"):
            yield Static(
                f"Create a Config Ledger snapshot?\n\nTool: {self.request.tool}\n"
                f"Local file: {self.request.path}\nIMAP folder: {self.store_folder}\n"
                f"Resolve conflicting heads: {self.request.resolve_conflict}\n\n{sensitive}",
                markup=False,
            )
            with Horizontal(id="config-push-confirm-buttons"):
                yield Button("Push snapshot", id="config-push-confirm", variant="warning")
                yield Button("Cancel", id="config-push-confirm-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "config-push-confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class ConfigPullDialog(ModalScreen[ConfigPullRequest | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConfigPullDialog { align: center middle; }
    #config-pull-box { width: 82; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #config-pull-buttons { height: 3; align-horizontal: right; }
    #config-pull-buttons Button { margin-left: 1; }
    """

    def __init__(
        self,
        tool: str,
        versions: tuple[ConfigVersionRecord, ...],
        selected_version: str | None = None,
    ) -> None:
        super().__init__()
        self.tool = tool
        self.versions = versions
        self.selected_version = selected_version

    def compose(self) -> ComposeResult:
        options = [
            (
                f"{item.meta.version_id} · {'current' if item.current else 'head' if item.head else 'historical'}",
                item.meta.version_id,
            )
            for item in self.versions
        ]
        default = self.selected_version or next(
            (item.meta.version_id for item in self.versions if item.current),
            None,
        )
        if default is None and options:
            default = options[0][1]
        with Vertical(id="config-pull-box"):
            yield Static(f"Pull a snapshot for {self.tool}", markup=False)
            yield Label("Version")
            yield Select(options, value=default, allow_blank=False, id="config-pull-version")
            yield Label("Target path, blank uses the stored default")
            yield Input(id="config-pull-target")
            yield Static("Existing targets are diffed and require an explicit overwrite confirmation.", markup=False)
            yield Static("", id="config-pull-error", markup=False)
            with Horizontal(id="config-pull-buttons"):
                yield Button("Preview pull…", id="config-pull-preview", variant="primary", disabled=not bool(options))
                yield Button("Cancel", id="config-pull-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "config-pull-cancel":
            self.dismiss(None)
            return
        version = self.query_one("#config-pull-version", Select).value
        if not isinstance(version, str):
            self.query_one("#config-pull-error", Static).update("Choose a snapshot version.")
            return
        target = self.query_one("#config-pull-target", Input).value.strip() or None
        self.dismiss(ConfigPullRequest(self.tool, version, target))

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfigPullPreviewScreen(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    ConfigPullPreviewScreen { align: center middle; }
    #config-pull-preview-box { width: 96%; height: 90%; border: round $warning; padding: 1 2; background: $surface; }
    #config-pull-preview-text { height: 1fr; }
    #config-pull-preview-buttons { height: 3; align-horizontal: right; }
    #config-pull-preview-buttons Button { margin-left: 1; }
    """

    def __init__(self, preview: ConfigPullPreview) -> None:
        super().__init__()
        self.preview = preview

    def compose(self) -> ComposeResult:
        preview = self.preview
        status = (
            "Already up to date"
            if preview.already_up_to_date
            else "Overwrite existing file"
            if preview.target_exists
            else "Create new file"
        )
        details = (
            f"Action: {status}\nTarget: {preview.target}\nVersion: {preview.version_id}\n"
            f"Snapshot SHA256: {preview.content_sha256}"
        )
        with Vertical(id="config-pull-preview-box"):
            yield Static(details, markup=False)
            yield Static(
                "Preview diff may reveal sensitive values. Review only in a trusted terminal.",
                id="config-pull-warning",
                markup=False,
            )
            with VerticalScroll():
                yield Static(preview.diff or "No local diff is available.", id="config-pull-preview-text", markup=False)
            with Horizontal(id="config-pull-preview-buttons"):
                yield Button(
                    "Write snapshot",
                    id="config-pull-apply",
                    disabled=preview.already_up_to_date,
                    variant="warning",
                )
                yield Button("Cancel", id="config-pull-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "config-pull-apply")

    def action_cancel(self) -> None:
        self.dismiss(False)


class ConfigTextScreen(ModalScreen[None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    ConfigTextScreen { align: center middle; }
    #config-text-box { width: 96%; height: 90%; border: round $accent; padding: 1 2; background: $surface; }
    #config-text-body { height: 1fr; }
    """

    def __init__(self, title: str, body: str, *, warning: str | None = None) -> None:
        super().__init__()
        self.title = title
        self.body = body
        self.warning = warning

    def compose(self) -> ComposeResult:
        with Vertical(id="config-text-box"):
            yield Static(self.title, markup=False)
            if self.warning:
                yield Static(self.warning, markup=False)
            with VerticalScroll():
                yield Static(self.body or "No differences.", id="config-text-body", markup=False)
            yield Button("Close", id="config-text-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)
