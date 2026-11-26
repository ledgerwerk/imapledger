from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static

from ..application.legacy_clean import LegacyCleanRequest
from ..cleaner import MessageResult
from ..mailbox import MessageSort
from ..preflight import SourcePreflightResult


class LegacyCleanDialog(ModalScreen[LegacyCleanRequest | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    LegacyCleanDialog { align: center middle; }
    #legacy-clean-box { width: 88; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #legacy-clean-buttons { height: 3; align-horizontal: right; }
    #legacy-clean-buttons Button { margin-left: 1; }
    """

    def __init__(self, source_folders: tuple[str, ...]) -> None:
        super().__init__()
        self.source_folders = source_folders

    def compose(self) -> ComposeResult:
        with Vertical(id="legacy-clean-box"):
            yield Static("Advanced / Legacy Clean", markup=False)
            yield Static(
                "Deprecated category-based classification. Scope is every configured spam.folders source.",
                markup=False,
            )
            yield Static(
                "Source folders: " + ", ".join(self.source_folders),
                id="legacy-clean-scope",
                markup=False,
            )
            yield Label("Message limit, blank for all selected messages")
            yield Input(placeholder="10", id="legacy-clean-limit")
            yield Label("Offset after sorting")
            yield Input(value="0", id="legacy-clean-offset")
            yield Label("Sort order")
            yield Select(
                [("Newest first", MessageSort.NEWEST.value), ("Oldest first", MessageSort.OLDEST.value)],
                value=MessageSort.NEWEST.value,
                allow_blank=False,
                id="legacy-clean-sort",
            )
            yield Checkbox("Reclassify messages with stored classification state", id="legacy-clean-reclassify")
            yield Checkbox("Apply configured category actions", id="legacy-clean-apply")
            yield Static(
                "Preview is the default. Apply is preflighted and requires a second confirmation.",
                markup=False,
            )
            yield Static("", id="legacy-clean-error", markup=False)
            with Horizontal(id="legacy-clean-buttons"):
                yield Button("Review scope…", id="legacy-clean-review", variant="primary")
                yield Button("Cancel", id="legacy-clean-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "legacy-clean-cancel":
            self.dismiss(None)
            return
        error = self.query_one("#legacy-clean-error", Static)
        try:
            limit_text = self.query_one("#legacy-clean-limit", Input).value.strip()
            limit = int(limit_text) if limit_text else None
            offset = int(self.query_one("#legacy-clean-offset", Input).value.strip())
            sort_value = self.query_one("#legacy-clean-sort", Select).value
            if not isinstance(sort_value, str):
                raise ValueError("Choose a sort order.")
            request = LegacyCleanRequest(
                apply=self.query_one("#legacy-clean-apply", Checkbox).value,
                limit=limit,
                offset=offset,
                sort=MessageSort(sort_value),
                reclassify=self.query_one("#legacy-clean-reclassify", Checkbox).value,
            )
        except (ValueError, TypeError) as exc:
            error.update(str(exc) or "Enter a valid limit and offset.")
            return
        self.dismiss(request)

    def action_cancel(self) -> None:
        self.dismiss(None)


class LegacyCleanPreflightScreen(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    LegacyCleanPreflightScreen { align: center middle; }
    #legacy-clean-preflight-box { width: 96%; height: 86%; border: round $warning; padding: 1 2; background: $surface; }
    #legacy-clean-preflight-table { height: 1fr; }
    #legacy-clean-preflight-buttons { height: 3; align-horizontal: right; }
    #legacy-clean-preflight-buttons Button { margin-left: 1; }
    """

    def __init__(self, results: tuple[SourcePreflightResult, ...]) -> None:
        super().__init__()
        self.results = results
        self.ok = bool(results) and all(result.ok for result in results)

    def compose(self) -> ComposeResult:
        with Vertical(id="legacy-clean-preflight-box"):
            yield Static("Legacy Clean apply preflight", markup=False)
            yield Static("Every configured source must pass. No classification or mutation has started.", markup=False)
            yield DataTable(id="legacy-clean-preflight-table")
            with Horizontal(id="legacy-clean-preflight-buttons"):
                yield Button(
                    "Continue to apply confirmation…",
                    id="legacy-clean-preflight-continue",
                    disabled=not self.ok,
                )
                yield Button("Cancel", id="legacy-clean-preflight-cancel")

    def on_mount(self) -> None:
        table = self.query_one("#legacy-clean-preflight-table", DataTable)
        table.add_columns("Folder", "Status", "Missing capabilities", "Destinations", "State persistence", "Errors")
        for result in self.results:
            missing = (
                ", ".join(item.decode("ascii", errors="replace") for item in result.missing_capabilities) or "none"
            )
            destinations = (
                ", ".join(
                    f"{name}:{'OK' if exists else 'MISSING' if exists is False else 'UNKNOWN'}"
                    for name, exists in result.destinations
                )
                or "none"
            )
            errors = ", ".join(type(error).__name__ for error in result.errors) or "none"
            table.add_row(
                result.folder,
                "OK" if result.ok else "FAILED",
                missing,
                destinations,
                result.keyword_persistence,
                errors,
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "legacy-clean-preflight-continue")

    def action_cancel(self) -> None:
        self.dismiss(False)


class LegacyCleanApplyConfirmation(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    CSS = """
    LegacyCleanApplyConfirmation { align: center middle; }
    #legacy-clean-confirm-box { width: 88; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #legacy-clean-confirm-buttons { height: 3; align-horizontal: right; }
    #legacy-clean-confirm-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: LegacyCleanRequest, source_folders: tuple[str, ...]) -> None:
        super().__init__()
        self.request = request
        self.source_folders = source_folders

    def compose(self) -> ComposeResult:
        request = self.request
        with Vertical(id="legacy-clean-confirm-box"):
            yield Static(
                "Apply deprecated category actions to all listed folders?\n\n"
                f"Folders: {', '.join(self.source_folders)}\n"
                f"Limit: {request.limit if request.limit is not None else 'all'}\n"
                f"Offset: {request.offset}\nSort: {request.sort.value}\n"
                f"Reclassify stored state: {request.reclassify}\n\n"
                "Actions follow the configured spam, not-spam, and review policies.",
                markup=False,
            )
            with Horizontal(id="legacy-clean-confirm-buttons"):
                yield Button("Apply legacy clean", id="legacy-clean-confirm-apply", variant="warning")
                yield Button("Cancel", id="legacy-clean-confirm-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "legacy-clean-confirm-apply")

    def action_cancel(self) -> None:
        self.dismiss(False)


class LegacyCleanJobScreen(ModalScreen[None]):
    BINDINGS = [("escape", "close", "Close")]
    CSS = """
    LegacyCleanJobScreen { align: center middle; }
    #legacy-clean-job-box { width: 98%; height: 92%; border: round $accent; padding: 1 2; background: $surface; }
    #legacy-clean-job-summary { height: 2; }
    #legacy-clean-job-scope { height: 2; }
    #legacy-clean-job-table { height: 1fr; }
    #legacy-clean-job-error { height: 1; color: $error; }
    #legacy-clean-job-buttons { height: 3; align-horizontal: right; }
    #legacy-clean-job-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: LegacyCleanRequest, source_folders: tuple[str, ...]) -> None:
        super().__init__()
        self.request = request
        self.source_folders = source_folders
        self._rows: list[tuple[str, str, str, str, str, str, str]] = []
        self._table_ready = False
        self._complete = False
        self._pending_finish: tuple[int, Exception | None, tuple[SourcePreflightResult, ...]] | None = None
        self._latest_progress = "waiting for configured source folders"

    def compose(self) -> ComposeResult:
        mode = "APPLY" if self.request.apply else "PREVIEW"
        with Vertical(id="legacy-clean-job-box"):
            yield Static(
                f"Scope: {', '.join(self.source_folders)} · limit {self.request.limit or 'all'} · "
                f"offset {self.request.offset} · sort {self.request.sort.value} · "
                f"reclassify {self.request.reclassify}",
                id="legacy-clean-job-scope",
                markup=False,
            )
            yield Static(
                f"Legacy Clean {mode} · {self._latest_progress}",
                id="legacy-clean-job-summary",
                markup=False,
            )
            yield DataTable(id="legacy-clean-job-table")
            yield Static("", id="legacy-clean-job-error", markup=False)
            with Horizontal(id="legacy-clean-job-buttons"):
                yield Button("Close", id="legacy-clean-job-close", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#legacy-clean-job-table", DataTable).add_columns(
            "Folder", "UID", "Status", "Outcome", "Rule", "Action", "State"
        )
        self._table_ready = True
        for row in self._rows:
            self._append_row(row)
        self._update_summary()
        if self._pending_finish is not None:
            report_count, failure, preflight_results = self._pending_finish
            self._pending_finish = None
            self.finish(
                report_count=report_count,
                failure=failure,
                preflight_results=preflight_results,
            )

    def append_result(self, folder: str, result: MessageResult, position: int, total: int) -> None:
        action = result.action.action.value.upper()
        if result.action.destination:
            action += f" → {result.action.destination}"
        row = (
            folder,
            str(result.uid),
            result.status.upper(),
            result.outcome.value.upper() if result.outcome is not None else "-",
            result.matched_rule_id or "-",
            action,
            result.state_source,
        )
        self._rows.append(row)
        self._latest_progress = f"{folder} {position}/{total}"
        if self._table_ready:
            self._append_row(row)
            self._update_summary()

    def _append_row(self, row: tuple[str, str, str, str, str, str, str]) -> None:
        self.query_one("#legacy-clean-job-table", DataTable).add_row(*row)

    def _update_summary(self) -> None:
        errors = sum(row[2] == "ERROR" for row in self._rows)
        self.query_one("#legacy-clean-job-summary", Static).update(
            f"Legacy Clean {'APPLY' if self.request.apply else 'PREVIEW'} · "
            f"{self._latest_progress} · {len(self._rows)} result(s) · {errors} error(s)"
        )

    def finish(
        self,
        *,
        report_count: int,
        failure: Exception | None,
        preflight_results: tuple[SourcePreflightResult, ...] = (),
    ) -> None:
        if not self._table_ready:
            self._pending_finish = (report_count, failure, preflight_results)
            return
        self._complete = True
        errors = sum(row[2] == "ERROR" for row in self._rows)
        state = "stopped" if failure is not None else "complete"
        summary = self.query_one("#legacy-clean-job-summary", Static)
        summary.update(
            f"Legacy Clean {state} · {report_count} folder report(s) · {len(self._rows)} message(s) · {errors} error(s)"
        )
        if preflight_results:
            failed = [result for result in preflight_results if not result.ok]
            details = []
            for result in failed:
                reasons = [item.decode("ascii", errors="replace") for item in result.missing_capabilities]
                if result.state_persistence_required and result.keyword_persistence != "supported":
                    reasons.append(f"classification state persistence {result.keyword_persistence}")
                    if result.unsupported_keywords:
                        reasons.append(f"unsupported keywords: {', '.join(result.unsupported_keywords)}")
                reasons.extend(f"destination {name} missing" for name, exists in result.destinations if exists is False)
                reasons.extend(type(error).__name__ for error in result.errors)
                details.append(f"{result.folder}: {', '.join(reasons) or 'preflight failed'}")
            message = "Apply preflight failed; no classification or mutation started."
            if details:
                message += " " + "; ".join(details)
            self.query_one("#legacy-clean-job-error", Static).update(message)
        elif failure is not None:
            self.query_one("#legacy-clean-job-error", Static).update(type(failure).__name__)
        self.query_one("#legacy-clean-job-close", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "legacy-clean-job-close" and self._complete:
            self.dismiss(None)

    def action_close(self) -> None:
        if self._complete:
            self.dismiss(None)
