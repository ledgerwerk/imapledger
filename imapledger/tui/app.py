from __future__ import annotations

import asyncio
import logging
import shlex
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Label, ListItem, ListView, Static

from ..action_service import ActionReceipt
from ..analysis_service import MessageAnalysis
from ..application import (
    OPERATION_BY_ID,
    OPERATION_SPECS,
    CleanOperation,
    CleanRequest,
    CleanResult,
    DoctorOperation,
    DoctorRequest,
    ErrorPresentation,
    LegacyCleanOperation,
    LegacyCleanRequest,
    OperationContext,
    ProgressOperation,
    ReviewOperation,
    ReviewRequest,
    StateFolderStatus,
    StateOperation,
    StateResetRequest,
    StateResetResult,
)
from ..application.rules import RuleLearningOperation, RuleLearningPreview, RuleMigrationOperation, RuleMigrationPreview
from ..classification_state import ClassificationStateBackend, SpamOutcome
from ..cleaner import MessageResult as LegacyCleanMessageResult
from ..config import AuthSource, Settings, write_settings
from ..config_errors import ConfigLedgerError, SensitiveConfigError
from ..config_ledger import ConfigLedger, ConfigPullPreview
from ..config_mailbox import ConfigStoreMailbox
from ..credential_service import configure_stored_credential, remove_stored_credential
from ..credentials import (
    CredentialRef,
    change_credential_vault_passphrase,
    credential_backend_for,
    credential_backend_for_storage,
)
from ..image_analysis import ImageAnalysisReport, ImageAnalysisService, ImageRecommendation, ImageSkip
from ..mail_service import MessageDetail
from ..mailbox import FolderInfo, MessageSort, ProcessingMailbox
from ..message import MailSummary
from ..preflight import SourcePreflightResult, preflight_source
from ..processing_engine import ProcessedMessage, ProcessingReport
from ..progress_store import MessageResult, ProgressRun
from ..remote_images import RemoteImageLoader
from ..routing_action_service import RoutingActionReceipt
from ..routing_config import routing_rules_path_for_config
from ..routing_models import RoutingPlan, RoutingRule
from ..routing_models import RuleSet as RoutingRuleSet
from ..routing_rule_service import RoutingRuleService
from ..rule_service import RuleService
from ..rule_test_service import RuleTestService
from ..rules import MailRule, RuleSet, rules_path_for_config
from ..settings_service import SettingsService
from .command_center import CommandCenterScreen
from .config_ledger_screens import (
    ConfigLedgerScreen,
    ConfigPullDialog,
    ConfigPullPreviewScreen,
    ConfigPullRequest,
    ConfigPushConfirmation,
    ConfigPushDialog,
    ConfigPushRequest,
    ConfigTextScreen,
    ConfigVersionsScreen,
)
from .legacy_clean import (
    LegacyCleanApplyConfirmation,
    LegacyCleanDialog,
    LegacyCleanJobScreen,
    LegacyCleanPreflightScreen,
)
from .rule_screens import (
    ClassificationRuleEditorScreen,
    ClassificationRulesScreen,
    DeletePolicyConfirmation,
    RoutingRuleCenterScreen,
    RoutingRuleEditorScreen,
    RuleCenterScreen,
    RuleDeleteConfirmation,
    RuleDetailScreen,
    RuleEditorScreen,
    RuleLearnDialog,
    RuleLearnPreviewScreen,
    RuleMigrationPreviewScreen,
    RuleTestResultScreen,
)
from .session import AppSession, SessionState
from .system_screens import (
    ConnectDialog,
    CredentialDeleteDialog,
    CredentialSetDialog,
    CredentialSetRequest,
    EffectiveConfigScreen,
    ReloadConfirmation,
    SetupDialog,
    SetupRequest,
    SystemScreen,
    VaultPassphraseChange,
    VaultPassphraseDialog,
)

_LOG = logging.getLogger(__name__)


def _importance_label(score: float) -> str:
    if score >= 2.5:
        return "critical"
    if score >= 1.5:
        return "material"
    if score >= 0.5:
        return "supplementary"
    return "decorative"


def _image_guidance(recommendation: ImageRecommendation) -> str:
    return {
        ImageRecommendation.MUST_VIEW: "terminal text may be insufficient; use a trusted rich mail view",
        ImageRecommendation.USEFUL: "visual context may improve understanding",
        ImageRecommendation.OPTIONAL_IF_INTERESTED: "useful if you care about the advertised product or design",
        ImageRecommendation.SAFE_TO_IGNORE: "no important meaning appears to be lost",
        ImageRecommendation.REVIEW: "uncertain assessment; review using a trusted rich mail view",
    }[recommendation]


def _format_action(action: Any) -> str:
    label = action.action.value.upper()
    return f"{label} -> {action.destination}" if action.destination else label


class FolderListItem(ListItem):
    def __init__(self, folder_name: str | None, label: str) -> None:
        super().__init__(Label(label))
        self.folder_name = folder_name

    @property
    def is_review(self) -> bool:
        return self.folder_name is None


class ApplyConfirmation(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    ApplyConfirmation { align: center middle; }
    #confirm-box { width: 70; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #confirm-buttons { height: 3; align-horizontal: right; }
    #confirm-buttons Button { margin-left: 1; }
    """

    def __init__(self, analysis: MessageAnalysis | RoutingPlan) -> None:
        super().__init__()
        self.analysis = analysis

    def compose(self) -> ComposeResult:
        if isinstance(self.analysis, RoutingPlan):
            plan = self.analysis
            yield Static(
                "Apply current routing plan?\n\n"
                f"UID: {plan.uid}\nSource: {plan.folder}\n"
                f"Rule: {plan.winner_rule_id or 'fallback'}\nDestination: {plan.destination}\n\n"
                "MOVE this exact message?",
                markup=False,
            )
            with Horizontal(id="confirm-buttons"):
                yield Button("Move message", id="apply", variant="primary")
                yield Button("Cancel", id="cancel")
            return
        action = self.analysis.configured_action
        action_label = _format_action(action) if action is not None else "UNKNOWN"
        outcome = self.analysis.outcome or self.analysis.persisted_outcome
        category = outcome.value.upper() if outcome is not None else "UNKNOWN"
        action_kind = action.action.value.upper() if action is not None else "UNKNOWN"
        target = (
            action.destination
            if action is not None and action.destination
            else "permanent deletion"
            if action is not None and action.action.value == "delete"
            else self.analysis.folder
        )
        warning = (
            "Permanently delete this exact message? UID EXPUNGE cannot be undone by imapledger."
            if action is not None and action.action.value == "delete"
            else "Apply this classification action to the exact selected message?"
        )
        if action_kind == "DELETE":
            apply_label = "Delete message"
        elif action_kind == "MOVE":
            apply_label = "Move message"
        else:
            apply_label = "Apply"
        with Vertical(id="confirm-box"):
            yield Static(warning, markup=False)
            yield Static(
                f"Category: {category}\n"
                f"Rule: {category} -> {action_label}\n\n"
                f"Source: {self.analysis.folder}\n"
                f"UID: {self.analysis.uid}\n"
                f"Action: {action_kind}\n"
                f"Target: {target}\n\n"
                "This changes only the selected message.",
                markup=False,
            )
            with Horizontal(id="confirm-buttons"):
                yield Button(apply_label, variant="error" if action_kind == "DELETE" else "primary", id="apply")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "apply")

    def action_cancel(self) -> None:
        self.dismiss(False)


class StateScreen(ModalScreen[tuple[str, str] | None]):
    CSS = """
    StateScreen { align: center middle; }
    #state-box { width: 94%; height: 88%; border: round $accent; padding: 1 2; background: $surface; }
    #state-table { height: 1fr; }
    #state-buttons { height: 3; align-horizontal: right; }
    #state-buttons Button { margin-left: 1; }
    """

    def __init__(
        self,
        statuses: tuple[StateFolderStatus, ...],
        errors: tuple[tuple[str, str], ...] = (),
    ) -> None:
        super().__init__()
        self.statuses = statuses
        self.errors = errors
        self.folders = tuple(item.folder for item in statuses) + tuple(folder for folder, _ in errors)
        self.selected_folder: str | None = self.folders[0] if self.folders else None

    def compose(self) -> ComposeResult:
        with Vertical(id="state-box"):
            yield Static("Classification State", markup=False)
            yield DataTable(id="state-table", cursor_type="row")
            with Horizontal(id="state-buttons"):
                yield Button("Reset state…", id="state-reset", disabled=not bool(self.folders))
                yield Button("Close", id="state-close")

    def on_mount(self) -> None:
        table = self.query_one("#state-table", DataTable)
        table.add_columns(
            "Folder",
            "UIDVALIDITY",
            "Backend",
            "Persistence",
            "Total",
            "Spam",
            "Not spam",
            "Review",
            "Unclassified",
            "Conflicts",
        )
        for item in self.statuses:
            table.add_row(
                item.folder,
                str(item.uidvalidity),
                item.backend.value,
                item.keyword_persistence,
                str(item.total),
                str(item.spam),
                str(item.notspam),
                str(item.review),
                str(item.unclassified),
                str(item.conflicts),
            )
        for folder, error_type in self.errors:
            table.add_row(folder, "-", "-", f"ERROR: {error_type}", "-", "-", "-", "-", "-", "-")
        if self.folders:
            table.move_cursor(row=0)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "state-table" and 0 <= event.cursor_row < len(self.folders):
            self.selected_folder = self.folders[event.cursor_row]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "state-reset" and self.selected_folder is not None:
            self.dismiss(("reset", self.selected_folder))
        elif event.button.id == "state-close":
            self.dismiss(None)


class StateResetDialog(ModalScreen[StateResetRequest | None]):
    CSS = """
    StateResetDialog { align: center middle; }
    #state-reset-box { width: 78; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #state-reset-buttons { height: 3; align-horizontal: right; }
    #state-reset-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, settings: Settings) -> None:
        super().__init__()
        self.folder = folder
        self.settings = settings

    def compose(self) -> ComposeResult:
        with Vertical(id="state-reset-box"):
            yield Static(f"Preview classification-state reset\nSelected source: {self.folder}", markup=False)
            yield Input(placeholder="Exact UID (leave blank for folder-wide reset)", id="state-reset-uid")
            yield Checkbox("Reset all marked UIDs in this folder", id="state-reset-all")
            yield Checkbox("Include all configured source folders", id="state-reset-all-folders")
            yield Checkbox("I intend to apply after reviewing the preview", id="state-reset-apply")
            yield Static(
                "Choose an exact UID or explicitly select all marked UIDs.",
                id="state-reset-warning",
                markup=False,
            )
            with Horizontal(id="state-reset-buttons"):
                yield Button("Preview reset", id="state-reset-preview")
                yield Button("Cancel", id="state-reset-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "state-reset-cancel":
            self.dismiss(None)
            return
        try:
            uid_text = self.query_one("#state-reset-uid", Input).value.strip()
            uid = int(uid_text) if uid_text else None
            all_folders = self.query_one("#state-reset-all-folders", Checkbox).value
            request = StateResetRequest(
                folder=None if all_folders else self.folder,
                uid=uid,
                reset_all=self.query_one("#state-reset-all", Checkbox).value,
                all_folders=all_folders,
                apply=self.query_one("#state-reset-apply", Checkbox).value,
            )
            StateOperation(self.settings).reset_folders(request)
            self.dismiss(request)
        except (ValueError, TypeError) as exc:
            self.query_one("#state-reset-warning", Static).update(str(exc))


class StateResetPreviewScreen(ModalScreen[bool]):
    CSS = """
    StateResetPreviewScreen { align: center middle; }
    #state-preview-box { width: 82; height: 82%; border: round $warning; padding: 1 2; background: $surface; }
    #state-preview-scroll { height: 1fr; }
    #state-preview-buttons { height: 3; align-horizontal: right; }
    #state-preview-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: StateResetRequest, results: tuple[StateResetResult, ...]) -> None:
        super().__init__()
        self.request = request
        self.results = results

    def compose(self) -> ComposeResult:
        scope = (
            "All configured source folders: " + ", ".join(result.folder for result in self.results)
            if self.request.all_folders
            else f"Exact source folder: {self.request.folder}"
        )
        if self.request.uid is not None:
            scope += f"\nExact UID: {self.request.uid}"
        else:
            scope += "\nTarget: all marked state UIDs in the selected folder scope"
        counts = (
            "\n".join(
                f"{result.folder}: {len(result.targeted_uids)} UID(s) "
                f"[{', '.join(map(str, result.targeted_uids)) or 'none'}], {result.marker_count} marker(s)"
                for result in self.results
            )
            or "No state markers found."
        )
        intent = (
            "Apply was selected. Confirm below to remove only these markers."
            if self.request.apply
            else "Preview only. No changes will be made."
        )
        with Vertical(id="state-preview-box"):
            with VerticalScroll(id="state-preview-scroll"):
                yield Static(f"Classification-state reset preview\n\n{scope}\n\n{counts}\n\n{intent}", markup=False)
            with Horizontal(id="state-preview-buttons"):
                yield Button(
                    "Apply exact reset",
                    id="state-reset-confirm",
                    disabled=not self.request.apply,
                    variant="error",
                )
                yield Button("Close", id="state-preview-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "state-reset-confirm")


class ProgressScreen(ModalScreen[tuple[str, ProgressRun] | None]):
    CSS = """
    ProgressScreen { align: center middle; }
    #progress-box { width: 94%; height: 88%; border: round $accent; padding: 1 2; background: $surface; }
    #progress-runs { height: 1fr; }
    #progress-detail { height: 5; }
    #progress-buttons { height: 3; align-horizontal: right; }
    #progress-buttons Button { margin-left: 1; }
    """

    def __init__(
        self,
        runs: tuple[ProgressRun, ...],
        errors: dict[str, tuple[MessageResult, ...]],
        database: Path,
    ) -> None:
        super().__init__()
        self.runs = runs
        self.errors = errors
        self.database = database
        self.selected: ProgressRun | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="progress-box"):
            yield Static(f"Jobs / Progress runs    Database: {self.database}", markup=False)
            yield DataTable(id="progress-runs", cursor_type="row")
            yield Static("Select a run to inspect its counters.", id="progress-detail", markup=False)
            yield Static("", id="progress-errors", markup=False)
            with Horizontal(id="progress-buttons"):
                yield Button("View errors…", id="progress-view-errors", disabled=True)
                yield Button("Retry errors…", id="progress-retry", disabled=True)
                yield Button("Reset folder progress…", id="progress-reset", disabled=True)
                yield Button("Close", id="progress-close")

    def on_mount(self) -> None:
        table = self.query_one("#progress-runs", DataTable)
        table.add_columns("Folder", "Mode", "Rule", "Sort", "Status", "Cursor", "Scanned", "Errors", "Run")
        for index, run in enumerate(self.runs):
            table.add_row(
                run.source_folder,
                run.mode,
                run.rule_scope or "-",
                run.sort_direction,
                run.status,
                str(run.cursor_uid) if run.cursor_uid is not None else "-",
                str(run.scanned_count),
                str(run.error_count),
                run.id,
                key=str(index),
            )
        if self.runs:
            self._select_run(0)
            table.move_cursor(row=0)
        else:
            self.query_one("#progress-detail", Static).update("No progress runs are recorded for this account.")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "progress-runs":
            self._select_run(event.cursor_row)

    def _select_run(self, index: int) -> None:
        if index < 0 or index >= len(self.runs):
            return
        run = self.runs[index]
        self.selected = run
        self.query_one("#progress-detail", Static).update(
            f"Run: {run.id}    Status: {run.status}    Folder: {run.source_folder}\n"
            f"UIDVALIDITY: {run.uidvalidity}    Range: ({run.lower_bound_uid},{run.high_watermark_uid}]    "
            f"Cursor: {run.cursor_uid if run.cursor_uid is not None else '-'}\n"
            f"Scanned: {run.scanned_count}    Matched: {run.match_count}    Moved: {run.moved_count}    "
            f"No match: {run.no_match_count}    Errors: {run.error_count}"
        )
        has_errors = bool(self.errors.get(run.id))
        self.query_one("#progress-errors", Static).update(
            f"{run.error_count} stored error(s). Error details use safe error codes only."
        )
        self.query_one("#progress-view-errors", Button).disabled = not has_errors
        self.query_one("#progress-retry", Button).disabled = not has_errors
        self.query_one("#progress-reset", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "progress-view-errors" and self.selected is not None:
            errors = self.errors.get(self.selected.id, ())
            self.app.push_screen(ProgressErrorsScreen(self.selected, errors), self._error_list_result)
        elif event.button.id == "progress-retry" and self.selected is not None:
            self.dismiss(("retry", self.selected))
        elif event.button.id == "progress-reset" and self.selected is not None:
            self.dismiss(("reset", self.selected))
        elif event.button.id == "progress-close":
            self.dismiss(None)

    def _error_list_result(self, retry: bool | None) -> None:
        if retry and self.selected is not None:
            self.dismiss(("retry", self.selected))


class ProgressErrorsScreen(ModalScreen[bool | None]):
    CSS = """
    ProgressErrorsScreen { align: center middle; }
    #progress-errors-box { width: 80%; height: 82%; border: round $accent; padding: 1 2; background: $surface; }
    #progress-error-table { height: 1fr; }
    #progress-error-buttons { height: 3; align-horizontal: right; }
    #progress-error-buttons Button { margin-left: 1; }
    """

    def __init__(self, run: ProgressRun, errors: tuple[MessageResult, ...]) -> None:
        super().__init__()
        self.run = run
        self.errors = errors

    def compose(self) -> ComposeResult:
        with Vertical(id="progress-errors-box"):
            yield Static(f"Stored errors for {self.run.source_folder}, run {self.run.id}", markup=False)
            yield DataTable(id="progress-error-table")
            with Horizontal(id="progress-error-buttons"):
                yield Button("Retry errors…", id="progress-errors-retry", disabled=not bool(self.errors))
                yield Button("Close", id="progress-errors-close")

    def on_mount(self) -> None:
        table = self.query_one("#progress-error-table", DataTable)
        table.add_columns("UID", "Error code")
        for error in self.errors:
            table.add_row(str(error.uid), error.error_code or "unknown")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "progress-errors-retry":
            self.dismiss(True)
        elif event.button.id == "progress-errors-close":
            self.dismiss(None)


class ProgressResetConfirmation(ModalScreen[bool]):
    CSS = """
    ProgressResetConfirmation { align: center middle; }
    #progress-reset-box { width: 70; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #progress-reset-buttons { height: 3; align-horizontal: right; }
    #progress-reset-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, run_count: int) -> None:
        super().__init__()
        self.folder = folder
        self.run_count = run_count

    def compose(self) -> ComposeResult:
        with Vertical(id="progress-reset-box"):
            yield Static(
                f"Delete saved routing progress?\n\nFolder: {self.folder}\nRuns to delete: {self.run_count}\n\n"
                "This cannot be undone. Mailbox messages are not changed.",
                markup=False,
            )
            with Horizontal(id="progress-reset-buttons"):
                yield Button("Cancel", id="progress-reset-cancel")
                yield Button("Delete progress", id="progress-reset-confirm", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "progress-reset-confirm")


class DoctorScreen(ModalScreen[None]):
    CSS = """
    DoctorScreen { align: center middle; }
    #doctor-box { width: 94%; height: 88%; border: round $accent; padding: 1 2; background: $surface; }
    #doctor-table { height: 1fr; }
    #doctor-buttons { height: 3; align-horizontal: right; }
    """

    def __init__(self, results: tuple[SourcePreflightResult, ...], *, config_ok: bool = True) -> None:
        super().__init__()
        self.results = results
        self.config_ok = config_ok

    def compose(self) -> ComposeResult:
        with Vertical(id="doctor-box"):
            yield Static("System diagnostics", markup=False)
            yield Static(f"Configuration: {'OK' if self.config_ok else 'FAILED'}", id="doctor-summary", markup=False)
            yield DataTable(id="doctor-table")
            with Horizontal(id="doctor-buttons"):
                yield Button("Close", id="doctor-close")

    def on_mount(self) -> None:
        table = self.query_one("#doctor-table", DataTable)
        table.add_columns("Folder", "Source", "Capabilities", "Destinations", "Probe", "Errors", "Result")
        for result in self.results:
            capabilities = (
                ", ".join(sorted(item.decode("ascii", errors="replace") for item in result.capabilities)) or "none"
            )
            missing = ", ".join(item.decode("ascii", errors="replace") for item in result.missing_capabilities)
            destinations = (
                ", ".join(
                    f"{name}:{'OK' if exists else 'MISSING' if exists is False else 'UNKNOWN'}"
                    for name, exists in result.destinations
                )
                or "none"
            )
            probe = "not run"
            if result.probe is not None:
                probe = f"UIDVALIDITY {result.probe.uidvalidity}, {result.probe.message_count} messages"
            errors = ", ".join(type(error).__name__ for error in result.errors) or "none"
            table.add_row(
                result.folder,
                "OK" if result.opened else "FAILED",
                capabilities + (f"; missing {missing}" if missing else ""),
                destinations,
                probe,
                errors,
                "healthy" if result.ok else "failed",
            )
        if not self.results:
            self.query_one("#doctor-summary", Static).update("No configured source folders to diagnose.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "doctor-close":
            self.dismiss()


class CleanDialog(ModalScreen[CleanRequest | None]):
    CSS = """
    CleanDialog { align: center middle; }
    #clean-box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #clean-controls { height: auto; }
    #clean-buttons { height: 3; align-horizontal: right; }
    #clean-buttons Button { margin-left: 1; }
    #clean-error { color: $error; height: auto; }
    """

    def __init__(self, folder: str, *, default_rule: str = "") -> None:
        super().__init__()
        self.folder = folder
        self.default_rule = default_rule

    def compose(self) -> ComposeResult:
        with Vertical(id="clean-box"):
            yield Static("Clean selected folder", markup=False)
            yield Static(f"Source folder: {self.folder}", markup=False)
            yield Static("Mode: Full routing", markup=False)
            yield Label("Rule scope (blank means all enabled rules)")
            yield Input(value=self.default_rule, placeholder="All enabled rules", id="clean-rule")
            yield Label("Message limit")
            yield Input(value="10", placeholder="Unlimited", id="clean-limit")
            yield Label("Sort order")
            yield Input(value="oldest", id="clean-sort")
            yield Checkbox("Apply changes", id="clean-apply")
            yield Checkbox("Start a new run", id="clean-new-run")
            yield Checkbox("Retry errors", id="clean-retry-errors")
            yield Static("CLI equivalent: imapledger clean", id="clean-command", markup=False)
            yield Static("", id="clean-error", markup=False)
            with Horizontal(id="clean-buttons"):
                yield Button("Start clean", id="clean-start", variant="primary")
                yield Button("Cancel", id="clean-cancel")

    def on_mount(self) -> None:
        self._update_command()

    def on_input_changed(self, _event: Input.Changed) -> None:
        self._update_command()

    def on_checkbox_changed(self, _event: Checkbox.Changed) -> None:
        self._update_command()

    def _request(self) -> CleanRequest:
        limit_text = self.query_one("#clean-limit", Input).value.strip()
        try:
            limit = int(limit_text) if limit_text else None
        except ValueError as exc:
            raise ValueError("Limit must be a positive integer or blank for unlimited.") from exc
        sort = self.query_one("#clean-sort", Input).value.strip().lower() or "oldest"
        return CleanRequest(
            folder=self.folder,
            apply=self.query_one("#clean-apply", Checkbox).value,
            limit=limit,
            sort=sort,
            rule_scope=self.query_one("#clean-rule", Input).value.strip() or None,
            new_run=self.query_one("#clean-new-run", Checkbox).value,
            retry_errors=self.query_one("#clean-retry-errors", Checkbox).value,
        )

    def _update_command(self) -> None:
        if not self.is_mounted:
            return
        parts = ["imapledger clean", shlex.quote(self.folder)]
        limit = self.query_one("#clean-limit", Input).value.strip()
        if limit:
            parts.extend(("--limit", shlex.quote(limit)))
        rule = self.query_one("#clean-rule", Input).value.strip()
        if rule:
            parts.extend(("--rule", shlex.quote(rule)))
        sort = self.query_one("#clean-sort", Input).value.strip().lower() or "oldest"
        parts.extend(("--sort", shlex.quote(sort)))
        if self.query_one("#clean-apply", Checkbox).value:
            parts.append("--apply")
        if self.query_one("#clean-new-run", Checkbox).value:
            parts.append("--new-run")
        if self.query_one("#clean-retry-errors", Checkbox).value:
            parts.append("--retry-errors")
        self.query_one("#clean-command", Static).update("CLI equivalent: " + " ".join(parts))
        try:
            self._request()
        except ValueError as exc:
            self.query_one("#clean-error", Static).update(str(exc))
        else:
            self.query_one("#clean-error", Static).update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "clean-cancel":
            self.dismiss(None)
            return
        try:
            request = self._request()
        except ValueError as exc:
            self.query_one("#clean-error", Static).update(str(exc))
            return
        self.dismiss(request)


class CleanPreflightScreen(ModalScreen[str | None]):
    CSS = """
    CleanPreflightScreen { align: center middle; }
    #clean-preflight-box { width: 76; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #clean-preflight-buttons { height: 3; align-horizontal: right; }
    #clean-preflight-buttons Button { margin-left: 1; }
    """

    def __init__(self, folder: str, detail: str, *, fallback_missing: bool) -> None:
        super().__init__()
        self.folder = folder
        self.detail = detail
        self.fallback_missing = fallback_missing

    def compose(self) -> ComposeResult:
        with Vertical(id="clean-preflight-box"):
            yield Static("Cannot run full routing clean.", markup=False)
            yield Static(f"Source: {self.folder}\n\n{self.detail}", markup=False)
            with Horizontal(id="clean-preflight-buttons"):
                if self.fallback_missing:
                    yield Button("Open Rules", id="clean-open-rules", variant="primary")
                    yield Button("Run one rule only…", id="clean-one-rule")
                yield Button("Cancel", id="clean-preflight-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss({"clean-open-rules": "rules", "clean-one-rule": "single-rule"}.get(event.button.id))


class CleanApplyConfirmation(ModalScreen[bool]):
    CSS = """
    CleanApplyConfirmation { align: center middle; }
    #clean-confirm-box { width: 78; height: auto; border: round $warning; padding: 1 2; background: $surface; }
    #clean-confirm-buttons { height: 3; align-horizontal: right; }
    #clean-confirm-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: CleanRequest, destinations: tuple[str, ...]) -> None:
        super().__init__()
        self.request = request
        self.destinations = destinations

    def compose(self) -> ComposeResult:
        request = self.request
        with Vertical(id="clean-confirm-box"):
            yield Static(
                "Apply routing actions?\n\n"
                f"Source: {request.folder}\nMaximum messages: {request.limit or 'unlimited'}\n"
                f"Sort: {request.sort}\nRules: {request.rule_scope or 'full routing'}\n"
                f"Possible destinations: {', '.join(self.destinations) or 'none'}\n"
                f"Progress DB: {request.progress_db}\n\n"
                "Moves are applied message-by-message. This is best-effort, not transactional.\n"
                "Already confirmed moves are not rolled back if a later message fails.",
                markup=False,
            )
            with Horizontal(id="clean-confirm-buttons"):
                yield Button("Cancel", id="clean-confirm-cancel")
                yield Button("Apply", id="clean-confirm-apply", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "clean-confirm-apply")


class CleanJobScreen(ModalScreen[None]):
    CSS = """
    CleanJobScreen { align: center middle; }
    #clean-job-box { width: 94%; height: 88%; border: round $accent; padding: 1 2; background: $surface; }
    #clean-job-summary { height: 5; }
    #clean-job-table { height: 1fr; }
    #clean-job-error { height: auto; color: $error; }
    #clean-job-buttons { height: 3; align-horizontal: right; }
    #clean-job-buttons Button { margin-left: 1; }
    """

    def __init__(self, request: CleanRequest) -> None:
        super().__init__()
        self.request = request
        self.cancel_event = threading.Event()
        self.operation_id = uuid.uuid4().hex[:12]
        self._results: list[ProcessedMessage] = []
        self._table_ready = False
        self._pending_results: list[tuple[ProcessedMessage, ProgressRun]] = []
        self._pending_finish: CleanResult | None = None
        self._pending_error: ErrorPresentation | None = None
        self._report: ProcessingReport | None = None
        self._status = "running"

    def compose(self) -> ComposeResult:
        request = self.request
        mode = "apply" if request.apply else "preview"
        with Vertical(id="clean-job-box"):
            yield Static(
                f"CLEAN · {request.folder} · {mode} · limit {request.limit or 'unlimited'} · {request.sort}",
                markup=False,
            )
            yield Static(self._summary(), id="clean-job-summary", markup=False)
            yield DataTable(id="clean-job-table")
            yield Static("", id="clean-job-error", markup=False)
            with Horizontal(id="clean-job-buttons"):
                yield Button("Cancel run", id="clean-job-cancel", variant="warning")
                yield Button("Close", id="clean-job-close", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#clean-job-table", DataTable).add_columns(
            "UID", "Result", "Rule", "Destination", "Action", "Error"
        )
        self._table_ready = True
        self._update_summary()
        pending_results = self._pending_results
        self._pending_results = []
        for message, _run in pending_results:
            self._append_result(message)
        if self._pending_finish is not None:
            result = self._pending_finish
            self._pending_finish = None
            self.finish(result)
        elif self._pending_error is not None:
            error = self._pending_error
            self._pending_error = None
            self.fail(error)

    def _summary(self) -> str:
        run_id = self._report.run.id if self._report is not None else "pending"
        matched = sum(message.outcome in {"match", "fallback"} for message in self._results)
        moved = sum(message.confirmed for message in self._results)
        no_match = sum(message.outcome == "no_match" for message in self._results)
        errors = sum(message.outcome == "error" for message in self._results)
        return (
            f"Run: {run_id}    Status: {self._status}\n"
            f"Processed: {len(self._results)} / {self.request.limit or 'unlimited'}    "
            f"Matched: {matched}    Moved: {moved}    No match: {no_match}    Errors: {errors}"
        )

    def _update_summary(self) -> None:
        if self.is_mounted:
            self.query_one("#clean-job-summary", Static).update(self._summary())

    def add_result(self, message: ProcessedMessage, run: ProgressRun) -> None:
        if not self._table_ready:
            self._pending_results.append((message, run))
            return
        self._append_result(message)

    def _append_result(self, message: ProcessedMessage) -> None:
        self._results.append(message)
        plan = message.plan
        rule = plan.winner_rule_id if plan is not None and plan.winner_rule_id is not None else "-"
        destination = message.destination or "-"
        action = "preview" if not self.request.apply else ("confirmed" if message.confirmed else "not-moved")
        self.query_one("#clean-job-table", DataTable).add_row(
            str(message.uid), message.outcome, rule, destination, action, message.error_code or "-"
        )
        self._update_summary()

    def finish(self, result: CleanResult) -> None:
        if not self._table_ready:
            self._pending_finish = result
            return
        report = result.report
        self._report = report
        if report.stopped_by_user:
            self._status = "cancelled/stopped by user"
        elif report.stopped_on_ambiguous_move:
            self._status = "stopped for MOVE reconciliation"
            ambiguous = next(
                (
                    message
                    for message in report.messages
                    if message.error_code in {"PartialMoveError", "MoveUnconfirmed"}
                ),
                None,
            )
            uid = f" UID {ambiguous.uid}." if ambiguous is not None else "."
            self.query_one("#clean-job-error", Static).update(
                f"Ambiguous MOVE{uid} Stop and reconcile before continuing. Open progress errors next."
            )
        else:
            self._status = "completed"
        self._update_summary()
        self.query_one("#clean-job-close", Button).disabled = False
        self.query_one("#clean-job-cancel", Button).disabled = True
        run = report.run
        self.query_one("#clean-job-summary", Static).update(
            self._summary() + f"\nRun total scanned: {run.scanned_count}    Cursor: {run.cursor_uid or '-'}    "
            f"High watermark: {run.high_watermark_uid}"
        )
        if report.preview:
            self.query_one("#clean-job-error", Static).update(
                "Preview only. No mailbox or per-message progress state was changed."
            )

    def fail(self, error: ErrorPresentation) -> None:
        if not self._table_ready:
            self._pending_error = error
            return
        self._status = "failed"
        self._update_summary()
        self.query_one("#clean-job-error", Static).update(
            f"{error.title}\n{error.detail}" + (f"\nNext: {error.hint}" if error.hint else "")
        )
        self.query_one("#clean-job-close", Button).disabled = False
        self.query_one("#clean-job-cancel", Button).disabled = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "clean-job-cancel":
            self.cancel_event.set()
            event.button.disabled = True
            event.button.label = "Cancellation requested"
            return
        if event.button.id == "clean-job-close":
            self.dismiss()


class RemoteImageConfirmation(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("q", "cancel", "Cancel")]
    CSS = """
    RemoteImageConfirmation { align: center middle; }
    #remote-box { width: 76; height: auto; border: round $accent; padding: 1 2; background: $surface; }
    #remote-buttons { height: 3; align-horizontal: right; }
    #remote-buttons Button { margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="remote-box"):
            yield Static(
                "Loading remote images contacts external servers and may reveal that this message was opened. "
                "Only bounded HTTPS PNG/JPEG responses that pass the privacy checks will be sent for visual analysis. "
                "No cookies, credentials, or referrer are sent. Cancel is the default. Continue?",
                markup=False,
            )
            with Horizontal(id="remote-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Load and analyze", variant="warning", id="load")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "load")

    def action_cancel(self) -> None:
        self.dismiss(False)


class FolderListView(ListView):
    BINDINGS = [
        *ListView.BINDINGS,
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "first_item", "First", show=False),
        Binding("G", "last_item", "Last", show=False),
        Binding("home", "first_item", "First", show=False),
        Binding("end", "last_item", "Last", show=False),
    ]

    def action_first_item(self) -> None:
        self.index = 0

    def action_last_item(self) -> None:
        if self.children:
            self.index = len(self.children) - 1


class MessageTable(DataTable):
    BINDINGS = [
        *DataTable.BINDINGS,
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "first_row", "First", show=False),
        Binding("G", "last_row", "Last", show=False),
    ]

    def action_first_row(self) -> None:
        if self.row_count:
            self.move_cursor(row=0)

    def action_last_row(self) -> None:
        if self.row_count:
            self.move_cursor(row=self.row_count - 1)


class MessageDetailView(VerticalScroll):
    can_focus = True
    BINDINGS = [
        Binding("j", "scroll_down", "Scroll down", show=False),
        Binding("k", "scroll_up", "Scroll up", show=False),
        Binding("g", "scroll_home", "Top", show=False),
        Binding("G", "scroll_end", "Bottom", show=False),
        Binding("home", "scroll_home", "Top", show=False),
        Binding("end", "scroll_end", "Bottom", show=False),
        Binding("pageup", "scroll_page_up", "Page up", show=False),
        Binding("pagedown", "scroll_page_down", "Page down", show=False),
    ]

    def __init__(self, text: str, *, id: str) -> None:
        super().__init__(id=id)
        self._text = text

    def compose(self) -> ComposeResult:
        yield Static(self._text, markup=False)

    def update(self, text: str) -> None:
        self.query_one(Static).update(text)

    def action_scroll_down(self) -> None:
        self.scroll_relative(y=1)

    def action_scroll_up(self) -> None:
        self.scroll_relative(y=-1)

    def action_scroll_home(self) -> None:
        self.scroll_home()

    def action_scroll_end(self) -> None:
        self.scroll_end()

    def action_scroll_page_up(self) -> None:
        self.scroll_page_up()

    def action_scroll_page_down(self) -> None:
        self.scroll_page_down()


class HelpScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("h", "close_help", "Close help"),
        Binding("escape", "close_help", "Close help"),
        Binding("q", "close_help", "Close help"),
    ]
    CSS = """
    HelpScreen { align: center middle; }
    #help-box { width: 80%; max-width: 76; height: 80%; border: round $accent; padding: 1 2; background: $surface; }
    #help-title { height: 1; text-style: bold; }
    #help-scroll { height: 1fr; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="help-box"):
            yield Static("imapledger keyboard help", id="help-title", markup=False)
            with VerticalScroll(id="help-scroll"):
                yield Static(
                    "Navigation\n"
                    "  Left / H        previous pane (stops at first)\n"
                    "  Right / L       next pane (stops at last)\n"
                    "  Tab             next pane (wraps)\n"
                    "  Shift+Tab       previous pane (wraps)\n"
                    "  j / k, Down/Up  move in folders/messages, scroll detail\n"
                    "  g / G           first / last item or top / bottom\n"
                    "  Home / End      first / last item or top / bottom\n"
                    "  PageUp/Down     page in the focused pane\n"
                    "  Enter           open folder or message\n\n"
                    "Analysis\n"
                    "  c               classify selected message\n"
                    "  C               reclassify selected message\n"
                    "  i               analyze embedded images only\n"
                    "  I               review remote-image loading (privacy-sensitive)\n\n"
                    "Actions\n"
                    "  c               evaluate every enabled rule for the selected message\n"
                    "  C               reevaluate the current message\n"
                    "  i               analyze embedded images only\n"
                    "  I               review remote-image loading (privacy-sensitive)\n\n"
                    "Operational areas\n"
                    "  p               progress and jobs\n"
                    "  d               read-only diagnostics\n"
                    "  S               inspect/reset classification state\n"
                    "  e               explain selected message (read-only)\n"
                    "  s               system, connection, credentials, and config\n"
                    "  :               open Command Center (search all operations)\n"
                    "  G               Config Ledger\n"
                    "  x / X           Clean next 10 or open the modern Clean dialog\n"
                    "  B               Advanced / Legacy Clean for configured spam.folders\n"
                    "  p / d / S       Jobs, diagnostics, and classification state\n"
                    "  l               learn a routing rule from the selected message\n"
                    "  Mail controls   Prev/Next page, Sort, Size, Review source filter\n\n"
                    "Safe operations\n"
                    "  a               apply the current MOVE plan to the exact selected UID\n"
                    "  R               open the unified Rules workbench\n"
                    "  Pressing c never changes mailbox contents. Rule edits never move mail.\n"
                    "  r               refresh\n\n"
                    "Rules workbench\n"
                    "  j/k             select a rule\n"
                    "  Enter           edit selected rule\n"
                    "  n/e             create or edit a rule\n"
                    "  Space           enable or disable\n"
                    "  [ / ]           change priority\n"
                    "  t               test selected rule on current message\n"
                    "  T               evaluate all rules on current message\n"
                    "  d               delete selected rule\n\n"
                    "  m               preview/apply legacy rule migration\n"
                    "Full-pipeline analysis shows the first matching rule or the fallback."
                    " Applying requires current rules, UIDVALIDITY, and exact UID checks.\n\n"
                    "General\n"
                    "  h / ?           show help (h closes this page)\n"
                    "  Escape          close help\n"
                    "  q               quit (or close help)\n\n"
                    "Opening a message does not fetch remote images or send images to analysis. "
                    "Remote images can reveal that a message was opened. Image assessments are "
                    "informational only and never apply mail actions. Destructive actions still "
                    "require a and explicit confirmation.",
                    markup=False,
                )

    def action_close_help(self) -> None:
        self.dismiss()


class MailReviewApp(App[None]):
    TITLE = "imapledger"
    SUB_TITLE = "IMAP operations workbench"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "progress", "Progress"),
        Binding("d", "doctor", "Doctor"),
        Binding("x", "clean_ten", "Clean 10"),
        Binding("B", "legacy_clean", "Advanced / Legacy Clean"),
        Binding("X", "clean_dialog", "Clean…"),
        Binding("c", "classify", "Classify"),
        Binding("e", "explain", "Explain"),
        Binding("l", "learn_rule", "Learn rule"),
        Binding("S", "state", "State"),
        Binding("s", "system", "System"),
        Binding("C", "reclassify", "Reclassify"),
        Binding("a", "apply", "Action"),
        Binding("R", "rules", "Rules"),
        Binding("F", "filters", "Rules", show=False),
        Binding("i", "analyze_images", "Analyze images"),
        Binding("I", "remote_images", "Remote images"),
        Binding(":", "command_center", "Command Center"),
        Binding("G", "config_ledger", "Config Ledger"),
        Binding("tab", "next_pane", "Next pane", priority=True),
        Binding("shift+tab", "previous_pane", "Previous pane", priority=True),
        Binding("left", "pane_left", "Previous pane", priority=True),
        Binding("right", "pane_right", "Next pane", priority=True),
        Binding("H", "pane_left", "Previous pane", priority=True),
        Binding("L", "pane_right", "Next pane", priority=True),
        Binding("h", "help", "Help", priority=True),
        Binding("?", "help", "Help"),
    ]
    CSS = """
    #workspace { height: 1fr; layout: vertical; }
    .pane { border: round $primary-background; padding: 0 1; }
    .pane:focus-within { border: round $accent; }
    #folder-pane { height: 8; width: 1fr; }
    #message-pane { height: 1fr; width: 1fr; }
    #mail-controls { height: 6; }
    #mail-controls > Horizontal { height: 3; }
    #mail-controls Button { margin-right: 1; padding: 0 1; }
    #mail-page-info { height: 2; }
    #detail-pane { height: 2fr; width: 1fr; }
    #folders, #messages { height: 1fr; }
    #message-detail { height: 1fr; overflow-y: auto; }
    #visual-analysis { height: 6; border-top: solid $primary-background; padding-top: 1; overflow-y: auto; }
    #analysis { height: 8; border-top: solid $primary-background; padding-top: 1; overflow-y: auto; }
    #activity { height: 5; border-top: solid $primary-background; padding-top: 1; overflow-y: auto; }
    #status { height: 1; dock: bottom; background: $primary-background; color: $text; }
    """

    def __init__(
        self,
        config: Path,
        *,
        session: AppSession | None = None,
        password: str = "",
        mail_service: Any | None = None,
        review_operation: ReviewOperation | None = None,
        settings: Settings | None = None,
        rules: RuleSet | None = None,
        rule_service: RuleService | None = None,
        routing_rules: RoutingRuleSet | None = None,
        routing_rule_service: RoutingRuleService | None = None,
        rule_test_service: RuleTestService | None = None,
        settings_service: SettingsService | None = None,
        analysis_service: Any | None = None,
        action_service: Any | None = None,
        image_analysis_service: Any | None = None,
        remote_image_loader: Any | None = None,
    ) -> None:
        super().__init__()
        self.session = session
        if session is not None:
            config = session.config_path
            password = session.password
            mail_service = session.mail_service
            settings = session.settings
            review_operation = ReviewOperation(settings) if settings is not None else None
            routing_rules = session.routing_rules
            routing_rule_service = session.routing_rule_service
            analysis_service = session.analysis_service
            action_service = session.action_service
        self.config = config
        self._password = password
        self.mail_service = mail_service
        self.review_operation = review_operation
        self.settings = settings
        self.settings_service = settings_service or (SettingsService(config) if settings else None)
        self.rules = rules or RuleSet()
        self.rule_service = rule_service or (
            RuleService(rules_path_for_config(config), source_folders=settings.spam.folders) if settings else None
        )
        self.routing_rules = routing_rules or RoutingRuleSet()
        self.routing_rule_service = routing_rule_service
        self.rule_test_service = rule_test_service
        self.analysis_service = analysis_service
        self.action_service = action_service
        self.image_analysis_service = image_analysis_service
        self.remote_image_loader = remote_image_loader
        self._remote_image_analysis: ImageAnalysisReport | None = None
        self._remote_image_skips: tuple[ImageSkip, ...] = ()
        self._remote_images_loaded: int | None = None
        self._image_analysis: ImageAnalysisReport | None = None
        self._remote_image_cache: dict[tuple[str, int, int], tuple[ImageAnalysisReport, int]] = {}
        self._image_generation = 0
        self._image_cache: dict[tuple[str, int, int], ImageAnalysisReport] = {}
        self.folders: tuple[FolderInfo, ...] = ()
        self._folder_item_by_name: dict[str, FolderListItem] = {}
        self._review_item: FolderListItem | None = None
        self._rows: list[tuple[str, MailSummary]] = []
        self._page_limit = 50
        self._page_offset = 0
        self._page_sort = MessageSort.NEWEST
        self._page_has_previous = False
        self._page_has_next = False
        self._review_filter: str | None = None
        self._list_folder: str | None = None
        self._selected_folder: str | None = None
        self._loading_folder: str | None = None
        self._detail: MessageDetail | None = None
        self._analysis: MessageAnalysis | RoutingPlan | None = None
        self._analysis_read_only = False
        self._folder_generation = 0
        self._message_generation = 0
        self._classification_generation = 0
        self._action_running = False
        self._activity: list[str] = []
        self._clean_running = False
        self._clean_job: CleanJobScreen | None = None
        self._config_ledger_mutation_running = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="workspace"):
            with Vertical(id="folder-pane", classes="pane"):
                yield Static("Folders and smart views", markup=False)
                yield FolderListView(id="folders")
            with Vertical(id="message-pane", classes="pane"):
                yield Static("Messages", markup=False)
                with Vertical(id="mail-controls"):
                    with Horizontal():
                        yield Button("Prev", id="mail-previous", disabled=True)
                        yield Button("Next", id="mail-next", disabled=True)
                    with Horizontal():
                        yield Button("Sort", id="mail-sort")
                        yield Button("Size", id="mail-size")
                        yield Button("Source", id="review-filter", disabled=True)
                yield Static("Page 1 · newest · size 50", id="mail-page-info", markup=False)
                yield MessageTable(id="messages", cursor_type="row")
            with Vertical(id="detail-pane", classes="pane"):
                yield MessageDetailView("Select a message to read its text content.", id="message-detail")
                yield Static("Visual content is inventoried when a message opens.", id="visual-analysis", markup=False)
                yield Static("Analysis will not run until requested.", id="analysis", markup=False)
                yield Static("Activity", id="activity", markup=False)
        yield Static("Starting", id="status", markup=False)
        yield Footer()

    def on_resize(self, event: Any) -> None:
        workspace = self.query_one("#workspace")
        folder_pane = self.query_one("#folder-pane")
        message_pane = self.query_one("#message-pane")
        detail_pane = self.query_one("#detail-pane")
        if event.size.width < 90:
            workspace.styles.layout = "vertical"
            folder_pane.styles.width, folder_pane.styles.height = "1fr", 3
            message_pane.styles.width, message_pane.styles.height = "1fr", "1fr"
            detail_pane.styles.width, detail_pane.styles.height = "1fr", "2fr"
            self.query_one("#visual-analysis").styles.height = 3
            self.query_one("#analysis").styles.height = 3
            self.query_one("#activity").styles.height = 2
        else:
            workspace.styles.layout = "horizontal"
            folder_pane.styles.width, folder_pane.styles.height = "24%", "1fr"
            message_pane.styles.width, message_pane.styles.height = "38%", "1fr"
            detail_pane.styles.width, detail_pane.styles.height = "38%", "1fr"
            self.query_one("#visual-analysis").styles.height = 6
            self.query_one("#analysis").styles.height = 8
            self.query_one("#activity").styles.height = 8

    def on_mount(self) -> None:
        self.query_one("#messages", DataTable).add_columns("Folder", "State", "UID", "From", "Subject", "Date", "Size")
        self._render_mail_controls(total=0)
        if self.mail_service is None:
            state = self.session.status if self.session is not None else SessionState.DISCONNECTED
            self._set_status(f"{state.value}. Press s for System and setup.")
            self.query_one("#message-detail", MessageDetailView).update(
                "Mail is disconnected. System, configuration, and credential workflows remain available.\n\n"
                "Press s to connect or configure a session."
            )
            if self.session is not None and state in {
                SessionState.NO_CONFIG,
                SessionState.CONFIG_ERROR,
                SessionState.CREDENTIAL_MISSING,
            }:
                self.call_after_refresh(self.action_system)
            return
        self._set_status("Loading folders…")
        self.run_worker(self._startup(), group="startup-folders", exclusive=True, exit_on_error=False)

    async def _startup(self) -> None:
        try:
            if self.mail_service is None:
                raise RuntimeError("Mail services were not initialized before Textual started")
            self.folders = await asyncio.to_thread(self.mail_service.list_folders, include_counts=False)
            self._render_folders()
            self._set_status("Connected. Choose a folder.")
            self.run_worker(self._refresh_counts(), group="folder-counts", exit_on_error=False)
        except Exception as exc:
            if self.session is not None:
                await asyncio.to_thread(self.session.disconnect)
                self._adopt_session()
            self._set_status(f"Disconnected after startup failure: {type(exc).__name__}. Press s for System.")
            self.query_one("#message-detail", MessageDetailView).update(
                "imapledger could not connect. No mailbox changes were made.\n\n"
                f"{type(exc).__name__}. Open System to check credentials or retry."
            )

    def _folder_label(self, folder: FolderInfo) -> str:
        counts = f"  {folder.total}" if folder.total is not None else ""
        unread = f" ({folder.unread} unread)" if folder.unread else ""
        return f"{folder.name}{counts}{unread}"

    def _render_folders(self) -> None:
        folders = tuple(folder for folder in self.folders if folder.selectable)
        view = self.query_one("#folders", ListView)
        current_names = tuple(self._folder_item_by_name)
        folder_names = tuple(folder.name for folder in folders)
        if self._review_item is None or current_names != folder_names:
            view.clear()
            self._folder_item_by_name = {}
            self._review_item = FolderListItem(None, "Review smart view")
            view.append(self._review_item)
            for folder in folders:
                item = FolderListItem(folder.name, self._folder_label(folder))
                self._folder_item_by_name[folder.name] = item
                view.append(item)
            return

        for folder in folders:
            self._folder_item_by_name[folder.name].query_one(Label).update(self._folder_label(folder))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "folders" or not isinstance(event.item, FolderListItem):
            return
        folder = "Review" if event.item.is_review else event.item.folder_name
        if folder is None:
            return
        self._page_offset = 0
        self._review_filter = None
        generation = self._begin_folder_load(folder)
        self.run_worker(
            self._select_folder(folder, generation),
            group="folder-page",
            exclusive=True,
            exit_on_error=False,
        )

    def _begin_folder_load(self, folder: str) -> int:
        self._folder_generation += 1
        self._message_generation += 1
        self._classification_generation += 1
        self._image_generation += 1
        self._image_analysis = None
        self._remote_image_analysis = None
        self._remote_image_skips = ()
        self._remote_images_loaded = None
        self._selected_folder = folder
        self._list_folder = folder
        self._loading_folder = folder
        self._detail = None
        self._analysis = None
        self._analysis_read_only = False
        self._rows = []
        self._page_has_previous = False
        self._page_has_next = False
        self.query_one("#messages", DataTable).clear()
        self.query_one("#message-detail", MessageDetailView).update(f"Loading {folder}...")
        self.query_one("#visual-analysis", Static).update("Select a message to inspect visual content.")
        self.query_one("#analysis", Static).update("Analysis will not run until a message is opened.")
        self._set_status(f"Loading {folder} page...")
        self._render_mail_controls(total=0)
        return self._folder_generation

    async def _select_folder(self, folder: str, generation: int | None = None) -> None:
        if generation is None:
            generation = self._begin_folder_load(folder)
        try:
            review_errors = False
            if folder == "Review":
                request = ReviewRequest(
                    folder=self._review_filter,
                    limit=self._page_limit,
                    offset=self._page_offset,
                    sort=self._page_sort,
                )
                if self.review_operation is not None:
                    page = await asyncio.to_thread(
                        self.review_operation.run,
                        request,
                        password=self._password,
                    )
                    page_rows = page.items
                    self._page_has_previous = page.has_previous
                    self._page_has_next = page.has_next
                    total = page.total
                    review_errors = bool(page.errors)
                    if page.errors:
                        self._set_status(
                            f"Review loaded with {len(page.errors)} source error(s): "
                            f"{', '.join(type(error).__name__ for _, error in page.errors)}"
                        )
                else:
                    rows = await asyncio.to_thread(
                        self.mail_service.review_messages,
                        limit=self._page_limit,
                        offset=self._page_offset,
                    )
                    page_rows = tuple(rows)
                    total = len(page_rows)
                    self._page_has_previous = self._page_offset > 0
                    self._page_has_next = len(page_rows) >= self._page_limit
            else:
                page = await asyncio.to_thread(
                    self.mail_service.list_messages,
                    folder,
                    limit=self._page_limit,
                    offset=self._page_offset,
                    sort=self._page_sort,
                )
                page_rows = tuple((folder, item) for item in page.items)
                self._page_has_previous = page.has_previous
                self._page_has_next = page.has_next
                total = page.total
            if generation != self._folder_generation:
                return
            self._populate_rows(page_rows)
            self._loading_folder = None
            if not review_errors:
                self._set_status(
                    f"{folder}: {len(page_rows)} messages loaded, page {self._page_offset // self._page_limit + 1}."
                )
            self._render_mail_controls(total=total)
        except Exception as exc:
            if generation == self._folder_generation:
                self._loading_folder = None
                self._rows = []
                self._page_has_previous = False
                self._page_has_next = False
                self.query_one("#messages", DataTable).clear()
                self.query_one("#message-detail", MessageDetailView).update(
                    f"Could not load {folder} ({type(exc).__name__}). Press r to retry."
                )
                self._render_mail_controls(total=0)
                self._set_status(f"Could not load {folder}: {type(exc).__name__}")

    def _populate_rows(self, rows: tuple[tuple[str, MailSummary], ...]) -> None:
        self._rows = list(rows)
        table = self.query_one("#messages", DataTable)
        table.clear()
        for index, (folder, summary) in enumerate(rows):
            state = summary.persisted_state.value.upper() if summary.persisted_state else "?"
            flags = {
                flag.decode("ascii", errors="replace") if isinstance(flag, bytes) else flag for flag in summary.flags
            }
            if "\\Seen" not in flags:
                state = "● " + state
            table.add_row(
                folder,
                state,
                str(summary.uid),
                summary.sender,
                summary.subject,
                summary.date,
                str(summary.size_bytes or "-"),
                key=str(index),
            )

    def _render_mail_controls(self, *, total: int) -> None:
        self.query_one("#mail-previous", Button).disabled = not self._page_has_previous
        self.query_one("#mail-next", Button).disabled = not self._page_has_next
        review_enabled = self._list_folder == "Review" and self.settings is not None
        self.query_one("#review-filter", Button).disabled = not review_enabled
        page_number = self._page_offset // self._page_limit + 1
        source = self._review_filter or "all sources" if self._list_folder == "Review" else self._list_folder or "none"
        self.query_one("#mail-page-info", Static).update(
            f"Page {page_number} · {self._page_sort.value} · {self._page_limit} · {source} · {len(self._rows)}/{total}"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "mail-previous":
            self._change_page(-1)
        elif event.button.id == "mail-next":
            self._change_page(1)
        elif event.button.id == "mail-sort":
            self._page_sort = MessageSort.OLDEST if self._page_sort is MessageSort.NEWEST else MessageSort.NEWEST
            self._page_offset = 0
            self._reload_current_page()
        elif event.button.id == "mail-size":
            sizes = (25, 50, 100)
            self._page_limit = sizes[(sizes.index(self._page_limit) + 1) % len(sizes)]
            self._page_offset = 0
            self._reload_current_page()
        elif event.button.id == "review-filter":
            self._cycle_review_filter()

    def _change_page(self, direction: int) -> None:
        if direction < 0 and not self._page_has_previous or direction > 0 and not self._page_has_next:
            return
        self._page_offset = max(0, self._page_offset + direction * self._page_limit)
        self._reload_current_page()

    def _cycle_review_filter(self) -> None:
        if self.settings is None or self._list_folder != "Review":
            return
        filters = (None, *self.settings.spam.folders)
        try:
            index = filters.index(self._review_filter)
        except ValueError:
            index = 0
        self._review_filter = filters[(index + 1) % len(filters)]
        self._page_offset = 0
        self._reload_current_page()

    def _reload_current_page(self) -> None:
        if self._list_folder is None:
            return
        self.run_worker(
            self._select_folder(self._list_folder),
            group="folder-page",
            exclusive=True,
            exit_on_error=False,
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        index = event.cursor_row
        if index < 0 or index >= len(self._rows):
            return
        folder, summary = self._rows[index]
        self._set_status(f"Opening {folder} UID {summary.uid}…")
        self.run_worker(
            self._open_message(folder, summary.uid),
            group="message-detail",
            exclusive=True,
            exit_on_error=False,
        )

    async def _open_message(self, folder: str, uid: int) -> None:
        self._message_generation += 1
        self._image_generation += 1
        self._image_analysis = None
        self._detail = None
        self._remote_image_analysis = None
        self._remote_image_skips = ()
        self._remote_images_loaded = None
        self._classification_generation += 1
        generation = self._message_generation
        self._selected_folder = folder
        self.query_one("#message-detail", MessageDetailView).update("Opening message with BODY.PEEK…")
        self.query_one("#visual-analysis", Static).update("Loading visual inventory...")
        try:
            detail = await asyncio.to_thread(self.mail_service.get_message, folder, uid)
            if generation != self._message_generation:
                return
            self._detail = detail
            self._analysis = None
            self._analysis_read_only = False
            message = detail.item.message
            if message is None:
                raise RuntimeError(detail.item.skip_reason or "message is unavailable")
            state = detail.persisted_state.outcome if detail.persisted_state else None
            image_key = self._image_cache_key(detail)
            self._image_analysis = self._image_cache.get(image_key)
            remote_cached = self._remote_image_cache.get(image_key)
            if remote_cached is not None:
                self._remote_image_analysis, self._remote_images_loaded = remote_cached
                self._remote_image_skips = self._remote_image_analysis.skipped_images
            self._render_visual_content(message, self._image_analysis)
            self.query_one("#message-detail", MessageDetailView).update(
                self._render_message(folder, message, detail, state)
            )
            if (
                state is not None
                and self.analysis_service is not None
                and not getattr(self.analysis_service, "is_routing", False)
            ):
                self._analysis = await asyncio.to_thread(
                    self.analysis_service.analyze,
                    folder,
                    message,
                    persisted_outcome=state,
                )
                if generation != self._message_generation:
                    return
                self._render_analysis(self._analysis)
            else:
                self.query_one("#analysis", Static).update(
                    "Persisted state: none\nClassifier: not run. Press c to classify."
                )
            self._set_status(f"{folder} UID {uid}. Read-only browsing; no message was marked seen.")
        except Exception as exc:
            if generation == self._message_generation:
                self._set_status(f"Could not open message: {type(exc).__name__}")
                self.query_one("#message-detail", MessageDetailView).update(
                    f"Message could not be opened ({type(exc).__name__})."
                )

    def _render_message(self, folder: str, message: Any, detail: MessageDetail, state: SpamOutcome | None) -> str:
        parts = [
            f"Folder: {folder}    UID: {message.uid}",
            f"From: {message.sender}",
            f"To: {', '.join(message.recipients)}",
            f"Date: {message.date}",
            f"Subject: {message.subject}",
            f"Message-ID: {message.message_id}",
            "",
            message.body,
            "",
            f"Persisted state: {state.value.upper() if state else 'UNCLASSIFIED'}",
            f"Body source: {message.body_source}",
        ]
        if message.body_truncated:
            parts.append(f"Body truncated at max_body_chars={self.settings.spam.max_body_chars}.")
        if message.has_attachments:
            parts.append(f"Attachments: {message.attachment_count} (not opened by imapledger)")
        return "\n".join(parts)

    @staticmethod
    def _image_cache_key(detail: MessageDetail) -> tuple[str, int, int]:
        return detail.folder, detail.uidvalidity, detail.item.uid

    def action_analyze_images(self) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None:
            self._set_status("Select a message first.")
            return
        if self.image_analysis_service is None:
            self._set_status("Visual image analysis is unavailable.")
            return
        message = detail.item.message
        key = self._image_cache_key(detail)
        cached = self._image_cache.get(key)
        if cached is not None:
            self._image_analysis = cached
            self._render_visual_content(message, cached)
            self._set_status("Using cached visual image analysis.")
            return
        if not message.images:
            report = ImageAnalysisReport(0, 0, 0, message.remote_image_count, ())
            self._image_cache[key] = report
            self._image_analysis = report
            self._render_visual_content(message, report)
            self._set_status("No embedded images to analyze.")
            return
        self._image_generation += 1
        generation = self._image_generation
        self._image_analysis = None
        self._render_visual_content(message, analyzing=True)
        self._set_status("Analyzing embedded images in a background thread...")
        self.run_worker(
            self._analyze_images(detail, key, generation),
            group="image-analysis",
            exclusive=True,
            exit_on_error=False,
        )

    async def _analyze_images(
        self,
        detail: MessageDetail,
        key: tuple[str, int, int],
        generation: int,
    ) -> None:
        try:
            report = await asyncio.to_thread(self.image_analysis_service.analyze, detail.item.message)
        except Exception as exc:
            if (
                generation == self._image_generation
                and self._detail is not None
                and self._image_cache_key(self._detail) == key
            ):
                self._set_status(f"Visual analysis failed: {type(exc).__name__}")
                self.query_one("#visual-analysis", Static).update(
                    "Visual image analysis unavailable. Press i to retry."
                )
            return
        current = self._detail
        if generation != self._image_generation or current is None or self._image_cache_key(current) != key:
            return
        self._image_analysis = report
        if not any(item.reason == "visual analysis unavailable" for item in report.skipped_images):
            self._image_cache[key] = report
        self._render_visual_content(detail.item.message, report)
        self._set_status("Visual image analysis complete.")

    def action_remote_images(self) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None:
            self._set_status("Select a message first.")
            return
        if not detail.item.message.remote_images:
            self._set_status("The selected message has no remote image references.")
            return
        if self.remote_image_loader is None or self.image_analysis_service is None:
            self._set_status("Remote image loading or visual analysis is unavailable.")
            return
        key = self._image_cache_key(detail)
        remote_cached = self._remote_image_cache.get(key)
        if remote_cached is not None:
            self._remote_image_analysis, self._remote_images_loaded = remote_cached
            self._remote_image_skips = self._remote_image_analysis.skipped_images
            self._render_visual_content(detail.item.message, self._image_analysis)
            self._set_status("Using cached remote visual analysis. No remote request was made.")
            return
        self.push_screen(RemoteImageConfirmation(), self._remote_images_confirmed)

    def _remote_images_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            self._set_status("Remote image loading cancelled. No remote requests were made.")
            return
        detail = self._detail
        if detail is None or detail.item.message is None:
            self._set_status("Select a message first.")
            return
        key = self._image_cache_key(detail)
        self._image_generation += 1
        generation = self._image_generation
        self._remote_image_analysis = None
        self._remote_image_skips = ()
        self._remote_images_loaded = None
        self._render_visual_content(detail.item.message, self._image_analysis, remote_loading=True)
        self._set_status("Loading remote images after confirmation...")
        self.run_worker(
            self._analyze_remote_images(detail, key, generation),
            group="image-analysis",
            exclusive=True,
            exit_on_error=False,
        )

    async def _analyze_remote_images(
        self,
        detail: MessageDetail,
        key: tuple[str, int, int],
        generation: int,
    ) -> None:
        message = detail.item.message
        try:
            images, fetch_skips = await asyncio.to_thread(self.remote_image_loader.fetch_all, message.remote_images)
            raw_report = await asyncio.to_thread(
                self.image_analysis_service.analyze,
                replace(message, images=images),
            )
        except Exception as exc:
            if (
                generation == self._image_generation
                and self._detail is not None
                and self._image_cache_key(self._detail) == key
            ):
                self._set_status(f"Remote visual analysis failed: {type(exc).__name__}")
                self.query_one("#visual-analysis", Static).update(
                    "Remote visual analysis unavailable. No remote image data was retained."
                )
            return
        current = self._detail
        if generation != self._image_generation or current is None or self._image_cache_key(current) != key:
            return
        skips = fetch_skips + raw_report.skipped_images
        report = ImageAnalysisReport(
            embedded_total=message.remote_image_count,
            analyzed=raw_report.analyzed,
            skipped=len(skips),
            remote_total=message.remote_image_count,
            assessments=raw_report.assessments,
            skipped_images=skips,
        )
        self._remote_image_analysis = report
        self._remote_image_skips = skips
        self._remote_images_loaded = len(images)
        self._remote_image_cache[key] = (report, len(images))
        self._render_visual_content(
            message,
            self._image_analysis,
            remote_report=report,
            remote_loading=False,
            remote_loaded=len(images),
            remote_skips=skips,
        )
        self._set_status("Remote visual analysis complete. Results are informational only.")

    def _render_visual_content(
        self,
        message: Any,
        report: ImageAnalysisReport | None = None,
        *,
        analyzing: bool = False,
        remote_report: ImageAnalysisReport | None = None,
        remote_loading: bool = False,
        remote_loaded: int | None = None,
        remote_skips: tuple[ImageSkip, ...] = (),
    ) -> None:
        if remote_report is None and not remote_loading:
            remote_report = self._remote_image_analysis
            remote_loaded = self._remote_images_loaded
            remote_skips = self._remote_image_skips
        classifiable = sum(image.classifiable for image in message.images)
        lines = [
            "Visual content",
            f"Images: {message.image_count} embedded ({classifiable} classifiable), "
            f"{message.remote_image_count} remote",
        ]
        if report is None:
            lines.append(
                "Embedded image analysis: running..." if analyzing else "Embedded image analysis: not run. Press i."
            )
            lines.extend(
                f"Image {image.index} skipped: {image.skip_reason}" for image in message.images if image.skip_reason
            )
        else:
            lines.append(f"Embedded image analysis: {report.analyzed} analyzed, {report.skipped} skipped")
            self._append_image_assessments(lines, report, "Image")
            lines.extend(
                f"[{item.index}/{report.embedded_total}] ANALYSIS UNAVAILABLE: {item.content_type}, "
                f"{item.size_bytes} bytes. Reason: {item.reason}"
                for item in report.skipped_images
            )

        if remote_loading:
            lines.append("Remote image loading and analysis: running after confirmation...")
        elif remote_report is None:
            if message.remote_image_count:
                lines.append("Remote images were not loaded for privacy. Press I to review privacy-sensitive loading.")
            else:
                lines.append("Remote images: none referenced.")
        else:
            loaded = remote_loaded if remote_loaded is not None else 0
            lines.append(
                f"Remote image analysis: {loaded} fetched, {remote_report.analyzed} analyzed, "
                f"{remote_report.skipped} skipped"
            )
            self._append_image_assessments(lines, remote_report, "Remote image")
            lines.extend(
                f"[remote {item.index}/{remote_report.remote_total}] NOT ANALYZED: "
                f"{item.content_type}, {item.size_bytes} bytes. Reason: {item.reason}"
                for item in remote_skips
            )
        self.query_one("#visual-analysis", Static).update("\n".join(lines))

    @staticmethod
    def _append_image_assessments(lines: list[str], report: ImageAnalysisReport, label: str) -> None:
        for assessment in report.assessments:
            importance = _importance_label(assessment.importance_score)
            recommendation = assessment.recommendation.value.replace("_", " ").upper()
            prefix = "Remote image" if label == "Remote image" else "Image"
            lines.extend(
                (
                    f"[{prefix.lower()} {assessment.index}/{report.remote_total}] {recommendation}"
                    if label == "Remote image"
                    else f"[{assessment.index}/{report.embedded_total}] {recommendation}",
                    f"  Role: {assessment.role} confidence={assessment.role_confidence:.2f}",
                    f"  Importance: {importance} score={assessment.importance_score:.2f} "
                    f"confidence={assessment.importance_confidence:.2f}",
                    f"  Text insufficient without image: {assessment.text_insufficient_probability:.2f}",
                    f"  Actionable/financial information: {assessment.actionable_information_probability:.2f}",
                    f"  Interest-dependent: {assessment.interest_dependent_probability:.2f}",
                    f"  Guidance: {_image_guidance(assessment.recommendation)}",
                )
            )

    def _render_analysis(self, analysis: MessageAnalysis | RoutingPlan, *, actionable: bool = True) -> None:
        lines = ["Analysis"]
        if isinstance(analysis, RoutingPlan):
            lines.append(f"  Source: {analysis.folder} UID {analysis.uid}")
            lines.append(f"  Rules fingerprint: {analysis.rules_fingerprint[:12]}")
            lines.append("  Rule evaluations:")
            for result in analysis.rule_results:
                confidence = f"  p={result.confidence:.2f}" if result.confidence is not None else ""
                detail = f"  ({result.detail})" if result.detail else ""
                lines.append(f"    {result.rule_id:<18} {result.state.value.upper()}{confidence}{detail}")
            if analysis.winner_rule_id is not None:
                lines.append(f"  Winner: {analysis.winner_rule_id} (first matching rule by priority)")
            else:
                lines.append("  Winner: none" if analysis.mode == "single-rule" else "  Winner: fallback")
            lines.append(f"  Destination: {analysis.destination or '(none)'}")
            lines.append("  Action: MOVE" if analysis.destination else "  Action: none")
            lines.append("  Applied: no")
            if analysis.model is not None:
                lines.append(f"  Model: {analysis.model}")
            if analysis.request_id is not None:
                lines.append(f"  Request: {analysis.request_id}")
            next_step = (
                "  a Apply this exact plan"
                if actionable and analysis.destination
                else "  No action is planned"
                if actionable
                else "  Read-only explanation; press c for an actionable plan"
            )
            lines.extend(("", "Next", next_step))
            self.query_one("#analysis", Static).update("\n".join(lines))
            return
        outcome = analysis.outcome or analysis.persisted_outcome
        if analysis.decision_source == "persisted-state":
            lines.append("  Source: persisted state")
            lines.append(f"  Category: {outcome.value.upper() if outcome is not None else '-'}")
            lines.append("  Classifier: not run")
        elif analysis.decision_source == "rule":
            lines.extend(("  Source: routing filter", f"  Filter: {analysis.rule_id}", "  Classification: not run"))
        elif analysis.verdict is not None:
            lines.extend(
                (
                    "  Source: semantic classifier",
                    f"  Category: {outcome.value.upper() if outcome is not None else '-'}",
                    f"  Verdict: {analysis.verdict.name}",
                )
            )
            if analysis.signals is not None:
                lines.append(
                    "  Signals: "
                    f"bulk {analysis.signals.unsolicited_bulk:.2f}, phishing {analysis.signals.phishing_or_scam:.2f}, "
                    f"identity {analysis.signals.identity_deception:.2f}, "
                    f"legitimate {analysis.signals.legitimate_expected:.2f}, "
                    f"delete {analysis.signals.delete_safe:.2f}"
                )
            lines.append(f"  Reasons: {', '.join(analysis.reasons) or '-'}")
        else:
            lines.extend(("  Source: none", "  Classifier: not run"))

        if outcome is not None:
            action = analysis.configured_action
            action_label = _format_action(action) if action is not None else "not configured"
            action_label = action_label.replace(" -> ", " ")
            lines.extend(
                (
                    "",
                    "Classification rule",
                    f"  {outcome.value.upper()} → {action_label}",
                    "",
                    "Scope",
                    f"  Manual action: available in {analysis.folder}",
                    (
                        f"  Batch clean: {analysis.folder} is an automatic clean folder"
                        if self.settings and analysis.folder in self.settings.spam.folders
                        else f"  Batch clean: {analysis.folder} is not in the automatic clean folders"
                    ),
                    "",
                    "Next",
                    f"  a Apply {action_label}" if action is not None else "  No action is configured",
                    "  R Edit classification rules",
                )
            )
        else:
            lines.extend(("", "Next", "  R Edit classification rules"))
        self.query_one("#analysis", Static).update("\n".join(lines))

    @staticmethod
    def _action_effect(action: Any) -> str:
        if action is None:
            return "no mailbox action is configured"
        if action.action.value == "keep":
            return "no move/delete"
        if action.action.value == "move":
            return f"move to {action.destination}"
        return "delete this exact UID after confirmation"

    @staticmethod
    def _current_action_label(analysis: MessageAnalysis, action: Any) -> str:
        if action is None:
            return "no mailbox action is configured"
        if action.action.value == "move":
            return f"MOVE UID {analysis.uid} from {analysis.folder} to {action.destination}"
        if action.action.value == "delete":
            return f"DELETE UID {analysis.uid} from {analysis.folder}"
        return f"KEEP UID {analysis.uid} in {analysis.folder} (no move/delete)"

    def action_state(self) -> None:
        if self.settings is None or not self._password:
            self._set_status("Classification state requires a connected IMAP session.")
            return
        self.run_worker(self._open_state(), group="state-status", exclusive=True, exit_on_error=False)

    async def _open_state(self) -> None:
        if self.settings is None:
            return
        operation = StateOperation(self.settings)
        statuses: list[StateFolderStatus] = []
        errors: list[tuple[str, str]] = []
        for folder in self.settings.spam.folders:
            try:
                status = await asyncio.to_thread(
                    operation.status,
                    folder,
                    password=self._password,
                )
            except Exception as exc:
                errors.append((folder, type(exc).__name__))
            else:
                statuses.append(status)
        self.push_screen(StateScreen(tuple(statuses), tuple(errors)), self._state_screen_choice)

    def _state_screen_choice(self, choice: tuple[str, str] | None) -> None:
        if choice is None or self.settings is None:
            return
        action, folder = choice
        if action == "reset":
            self.push_screen(StateResetDialog(folder, self.settings), self._state_reset_request)

    def _state_reset_request(self, request: StateResetRequest | None) -> None:
        if request is None:
            return
        self.run_worker(
            self._preview_state_reset(request),
            group="state-reset-preview",
            exclusive=True,
            exit_on_error=False,
        )

    async def _preview_state_reset(self, request: StateResetRequest) -> None:
        if self.settings is None:
            return
        operation = StateOperation(self.settings)
        try:
            folders = operation.reset_folders(request)
            preview_request = replace(request, apply=False)
            results = tuple(
                [
                    await asyncio.to_thread(
                        operation.reset_folder,
                        folder,
                        preview_request,
                        password=self._password,
                    )
                    for folder in folders
                ]
            )
            self.push_screen(
                StateResetPreviewScreen(request, results),
                lambda confirmed: self._apply_state_reset(request) if confirmed and request.apply else None,
            )
        except Exception as exc:
            self._set_status(f"State reset preview failed: {type(exc).__name__}.")

    def _apply_state_reset(self, request: StateResetRequest) -> None:
        if self.settings is None or not request.apply:
            return
        self.run_worker(
            self._apply_state_reset_job(request),
            group="state-reset-apply",
            exclusive=True,
            exit_on_error=False,
        )

    async def _apply_state_reset_job(self, request: StateResetRequest) -> None:
        if self.settings is None:
            return
        operation = StateOperation(self.settings)
        try:
            applied_request = replace(request, apply=True)
            folders = operation.reset_folders(applied_request)
            results = []
            for folder in folders:
                results.append(
                    await asyncio.to_thread(
                        operation.reset_folder,
                        folder,
                        applied_request,
                        password=self._password,
                    )
                )
            self._activity.append(f"Classification state reset applied to {len(results)} configured source folder(s).")
            self._render_activity()
            self._set_status("Classification state reset completed.")
            await self._open_state()
        except Exception as exc:
            self._set_status(f"State reset failed: {type(exc).__name__}.")

    def action_progress(self) -> None:
        if self.settings is None:
            self._set_status("Progress is unavailable until configuration is loaded.")
            return
        self.run_worker(self._open_progress(), group="progress-screen", exclusive=True, exit_on_error=False)

    async def _open_progress(self) -> None:
        try:

            def load_progress():
                progress = ProgressOperation(self.settings)
                runs = progress.list_runs(limit=1000)
                errors = {run.id: progress.errors(run.id) for run in runs if run.error_count}
                return progress, runs, errors

            progress, runs, errors = await asyncio.to_thread(load_progress)
            self.push_screen(ProgressScreen(runs, errors, progress.path), self._progress_choice)
        except Exception as exc:
            self._set_status(f"Progress unavailable: {type(exc).__name__}.")

    def _progress_choice(self, choice: tuple[str, ProgressRun] | None) -> None:
        if choice is None:
            return
        action, run = choice
        if action == "retry":
            self._begin_clean(
                CleanRequest(
                    folder=run.source_folder,
                    apply=True,
                    sort=run.sort_direction,
                    rule_scope=run.rule_scope,
                    retry_errors=True,
                )
            )
        elif action == "reset":
            self._confirm_progress_reset(run.source_folder)

    def _confirm_progress_reset(self, folder: str) -> None:
        if self.settings is None:
            return
        try:
            runs = ProgressOperation(self.settings).list_runs(folder=folder, limit=1000)
        except Exception as exc:
            self._set_status(f"Progress unavailable: {type(exc).__name__}.")
            return

        def reset_result(confirmed: bool) -> None:
            if confirmed:
                self._delete_progress(folder)
            else:
                self._set_status("Progress reset cancelled.")

        self.push_screen(
            ProgressResetConfirmation(folder, len(runs)),
            reset_result,
        )

    def _delete_progress(self, folder: str) -> None:
        if self.settings is None:
            return
        self.run_worker(self._reset_progress(folder), group="progress-reset", exclusive=True, exit_on_error=False)

    async def _reset_progress(self, folder: str) -> None:
        try:
            operation = ProgressOperation(self.settings)
            deleted = await asyncio.to_thread(operation.reset_folder, folder)
            self._activity.append(f"Deleted {deleted} progress run(s) for {folder}.")
            self._render_activity()
            self._set_status(f"Progress reset for {folder}.")
            await self._open_progress()
        except Exception as exc:
            self._set_status(f"Progress reset failed: {type(exc).__name__}.")

    def action_doctor(self) -> None:
        if self.settings is None or not self._password:
            self._set_status("Diagnostics require a connected IMAP session.")
            return
        self.run_worker(self._run_doctor(), group="doctor", exclusive=True, exit_on_error=False)

    async def _run_doctor(self) -> None:
        if self.settings is None:
            return
        operation = DoctorOperation(self.settings)
        actions = self.settings.spam.actions
        action_destinations = [
            action.destination
            for action in (actions.spam, actions.not_spam, actions.review)
            if action.destination is not None
        ]
        requires_delete = any(
            action.action.value == "delete" for action in (actions.spam, actions.not_spam, actions.review)
        )
        results: list[SourcePreflightResult] = []
        for folder in self.settings.spam.folders:
            destinations = list(action_destinations)
            routes = self.routing_rules.enabled_rules(folder)
            destinations.extend(rule.destination for rule in routes)
            if routes and self.routing_rules.fallback_destination is not None:
                destinations.append(self.routing_rules.fallback_destination)
            request = DoctorRequest(
                folder=folder,
                destinations=tuple(dict.fromkeys(destinations)),
                requires_delete=requires_delete,
                require_state_persistence=self.settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS,
                deep_probe=True,
            )
            try:
                result = await asyncio.to_thread(
                    operation.run,
                    request,
                    password=self._password,
                )
            except Exception as exc:
                self._set_status(f"Diagnostics failed: {type(exc).__name__}.")
                return
            results.append(result)
        self._activity.append(f"Diagnostics completed for {len(results)} source folder(s).")
        self._render_activity()
        self.push_screen(DoctorScreen(tuple(results)))

    def action_clean_ten(self) -> None:
        folder = self._selected_folder
        if folder is None or folder == "Review" or folder not in self._folder_item_by_name:
            self._set_status("Select a real folder before starting Clean 10.")
            return
        self._begin_clean(CleanRequest(folder=folder, limit=10, apply=False, sort="oldest"))

    def action_clean_dialog(self) -> None:
        folder = self._selected_folder
        if folder is None or folder == "Review" or folder not in self._folder_item_by_name:
            self._set_status("Select a real folder before opening Clean…")
            return
        self.push_screen(CleanDialog(folder), self._clean_dialog_result)

    def _clean_dialog_result(self, request: CleanRequest | None) -> None:
        if request is not None:
            self._begin_clean(request)

    def action_legacy_clean(self) -> None:
        if self.settings is None:
            self._set_status("Legacy Clean is unavailable until configuration is loaded.")
            return
        if not self._password or self.mail_service is None:
            self._set_status("Connect to IMAP before opening Advanced / Legacy Clean.")
            return
        if not self.settings.spam.folders:
            self._set_status("Legacy Clean requires configured spam.folders source folders.")
            return
        self.push_screen(LegacyCleanDialog(self.settings.spam.folders), self._legacy_clean_request)

    def _legacy_clean_request(self, request: LegacyCleanRequest | None) -> None:
        if request is None:
            return
        if self._clean_running:
            self._set_status("A clean operation is already running.")
            return
        if request.apply:
            self.run_worker(
                self._prepare_legacy_clean(request),
                group="legacy-clean-preflight",
                exclusive=True,
                exit_on_error=False,
            )
        else:
            self._launch_legacy_clean(request)

    async def _prepare_legacy_clean(self, request: LegacyCleanRequest) -> None:
        if self.settings is None:
            self._set_status("Legacy Clean configuration is unavailable.")
            return
        operation = LegacyCleanOperation(self.settings, self.rules)
        try:
            results = await asyncio.to_thread(
                operation.preflight,
                request,
                password=self._password,
            )
        except Exception as exc:
            self._set_status(f"Legacy Clean preflight failed: {type(exc).__name__}.")
            return
        self.push_screen(
            LegacyCleanPreflightScreen(results),
            lambda proceed: self._legacy_clean_preflight_result(request, results, proceed),
        )

    def _legacy_clean_preflight_result(
        self,
        request: LegacyCleanRequest,
        results: tuple[SourcePreflightResult, ...],
        proceed: bool | None,
    ) -> None:
        if not proceed or not results or any(not result.ok for result in results):
            self._set_status("Legacy Clean preflight blocked or cancelled.")
            return
        self.push_screen(
            LegacyCleanApplyConfirmation(request, self.settings.spam.folders),
            lambda confirmed: self._legacy_clean_confirmation_result(request, confirmed),
        )

    def _legacy_clean_confirmation_result(
        self,
        request: LegacyCleanRequest,
        confirmed: bool | None,
    ) -> None:
        if confirmed:
            self._launch_legacy_clean(request)
        else:
            self._set_status("Legacy Clean cancelled.")

    def _launch_legacy_clean(self, request: LegacyCleanRequest) -> None:
        if self._clean_running:
            self._set_status("A clean operation is already running.")
            return
        if self.settings is None or not self._password:
            self._set_status("Legacy Clean is unavailable until the IMAP session is connected.")
            return
        self._clean_running = True
        job = LegacyCleanJobScreen(request, self.settings.spam.folders)
        self._activity.append(
            f"Started Legacy Clean {'APPLY' if request.apply else 'PREVIEW'}: {', '.join(self.settings.spam.folders)}."
        )
        self._render_activity()
        self.push_screen(job)
        self.run_worker(
            self._run_legacy_clean(request, job),
            group="legacy-clean",
            exclusive=True,
            exit_on_error=False,
        )

    async def _run_legacy_clean(self, request: LegacyCleanRequest, job: LegacyCleanJobScreen) -> None:
        settings = self.settings
        password = self._password
        if settings is None or not password:
            failure = RuntimeError("connected legacy clean settings are unavailable")
            job.finish(report_count=0, failure=failure)
            self._set_status(f"Legacy Clean failed: {type(failure).__name__}.")
            self._clean_running = False
            return
        operation = LegacyCleanOperation(settings, self.rules)

        def on_result(folder: str, result: LegacyCleanMessageResult, position: int, total: int) -> None:
            self.call_from_thread(job.append_result, folder, result, position, total)

        try:
            result = await asyncio.to_thread(
                operation.run,
                request,
                password=password,
                on_result=on_result,
            )
        except Exception as exc:
            job.finish(report_count=0, failure=exc)
            self._set_status(f"Legacy Clean failed: {type(exc).__name__}.")
            self._activity.append(f"Legacy Clean failed: {type(exc).__name__}.")
            self._render_activity()
            self._clean_running = False
            return
        failure = result.failure
        if result.preflight_failed:
            failure = RuntimeError("apply preflight failed; no classification or mutation was started")
        job.finish(
            report_count=len(result.reports),
            failure=failure,
            preflight_results=result.preflight_results if result.preflight_failed else (),
        )
        self._clean_running = False
        if failure is not None:
            self._set_status(f"Legacy Clean stopped: {type(failure).__name__}.")
            self._activity.append(f"Legacy Clean stopped: {type(failure).__name__}.")
        else:
            self._set_status("Legacy Clean complete.")
            self._activity.append("Legacy Clean complete.")
            if request.apply:
                self.action_refresh()
        self._render_activity()

    def _begin_clean(self, request: CleanRequest) -> None:
        if self._clean_running:
            self._set_status("A clean operation is already running.")
            return
        if self.settings is None or not self._password:
            self._set_status("Clean is unavailable until the IMAP session is connected.")
            return
        operation = CleanOperation(self.settings, self.routing_rules)
        try:
            preflight = operation.preflight(request)
        except ValueError as exc:
            detail = "No fallback destination is configured." if "fallback_destination" in str(exc) else str(exc)
            fallback_missing = "fallback_destination" in str(exc) and request.rule_scope is None
            self._activity.append(f"Clean blocked for {request.folder}: {detail}")
            self._render_activity()
            self.push_screen(
                CleanPreflightScreen(request.folder, detail, fallback_missing=fallback_missing),
                lambda choice: self._clean_preflight_choice(choice, request.folder),
            )
            return
        if request.apply:
            self.run_worker(
                self._prepare_clean_apply(request, operation, preflight),
                group="clean-preflight",
                exclusive=True,
                exit_on_error=False,
            )
        else:
            self._launch_clean(request, operation)

    async def _prepare_clean_apply(
        self,
        request: CleanRequest,
        operation: CleanOperation,
        preflight: Any,
    ) -> None:
        self._set_status(f"Checking {request.folder} before apply…")
        try:
            result = await asyncio.to_thread(
                preflight_source,
                self.settings,
                request.folder,
                password=self._password,
                destinations=preflight.destinations,
                requires_delete=False,
                deep_probe=False,
                mailbox_factory=ProcessingMailbox,
            )
        except Exception:
            detail = "Mailbox preflight failed. Check the connection, MOVE capability, and configured destinations."
        else:
            if result.ok:
                self.push_screen(
                    CleanApplyConfirmation(request, preflight.destinations),
                    lambda confirmed: (
                        self._launch_clean(request, operation)
                        if confirmed
                        else self._set_status("Clean apply cancelled.")
                    ),
                )
                return
            missing = ", ".join(
                capability.decode("ascii", errors="replace") for capability in result.missing_capabilities
            )
            missing_destinations = ", ".join(
                destination for destination, exists in result.destinations if exists is not True
            )
            issues = []
            if not result.opened:
                issues.append("the source folder could not be opened read-only")
            if missing:
                issues.append(f"missing required capability: {missing}")
            if missing_destinations:
                issues.append(f"missing destinations: {missing_destinations}")
            if result.errors and not issues:
                issues.append("the mailbox reported a preflight error")
            detail = "Apply is blocked. " + "; ".join(issues or ["mailbox preflight did not pass"]) + "."
        self._activity.append(f"Clean blocked for {request.folder}: {detail}")
        self._render_activity()
        self._set_status(f"Clean apply blocked for {request.folder}.")
        self.push_screen(CleanPreflightScreen(request.folder, detail, fallback_missing=False))

    def _clean_preflight_choice(self, choice: str | None, folder: str) -> None:
        if choice == "rules":
            self.action_rules()
        elif choice == "single-rule":
            rules = self.routing_rules.enabled_rules(folder)
            default_rule = rules[0].id if rules else ""
            self.push_screen(CleanDialog(folder, default_rule=default_rule), self._clean_dialog_result)

    def _launch_clean(self, request: CleanRequest, operation: CleanOperation) -> None:
        if self._clean_running:
            return
        self._clean_running = True
        job = CleanJobScreen(request)
        self._clean_job = job
        self._activity.append(
            f"Clean started: {request.folder} {'apply' if request.apply else 'preview'}, "
            f"limit={request.limit or 'unlimited'}, sort={request.sort}."
        )
        self._render_activity()
        self._set_status(f"Clean started for {request.folder}.")
        self.push_screen(job)
        self.run_worker(
            self._execute_clean(request, operation, job),
            group="clean-operation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _execute_clean(
        self,
        request: CleanRequest,
        operation: CleanOperation,
        job: CleanJobScreen,
    ) -> None:
        try:

            def on_result(message: ProcessedMessage, run: ProgressRun) -> None:
                self.call_from_thread(job.add_result, message, run)

            result = await asyncio.to_thread(
                operation.run,
                request,
                password=self._password,
                on_result=on_result,
                should_stop=job.cancel_event.is_set,
            )
            job.finish(result)
            outcome = "stopped by user" if result.report.stopped_by_user else "completed"
            self._activity.append(
                f"Clean {outcome}: {request.folder}, {len(result.report.messages)} messages this command."
            )
            self._render_activity()
            self._set_status(f"Clean {outcome} for {request.folder}.")
            if request.apply:
                await self._refresh()
        except Exception as exc:
            code = type(exc).__name__
            title = "Clean operation failed"
            detail = (
                "The operation stopped. Previously confirmed moves remain applied."
                if request.apply
                else "The preview stopped. No mailbox or per-message progress state was changed."
            )
            hint = "Review the job results and progress errors before retrying."
            job.fail(ErrorPresentation(code=code, title=title, detail=detail, hint=hint, retryable=True))
            self._activity.append(f"Clean failed: {request.folder} ({code}).")
            self._render_activity()
            self._set_status(f"Clean failed: {code}.")
        finally:
            self._clean_running = False

    def action_classify(self) -> None:
        self.run_worker(self._classify(reclassify=False), group="classification", exclusive=True, exit_on_error=False)

    def action_explain(self) -> None:
        self.run_worker(
            self._classify(reclassify=False, explain=True),
            group="classification",
            exclusive=True,
            exit_on_error=False,
        )

    def action_reclassify(self) -> None:
        self.run_worker(self._classify(reclassify=True), group="classification", exclusive=True, exit_on_error=False)

    async def _classify(self, *, reclassify: bool, explain: bool = False) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None or self.analysis_service is None:
            self._set_status("Select a message first.")
            return
        status = "Explaining selected message (read-only)…" if explain else "Classifying in a background thread…"
        self._set_status(status)
        started = time.monotonic()
        self._classification_generation += 1
        generation = self._classification_generation
        self._analysis = None
        self._analysis_read_only = False
        self.query_one("#analysis", Static).update("Analysis\n  Recomputing the selected message.")
        try:
            state = detail.persisted_state.outcome if detail.persisted_state else None
            analysis = await asyncio.to_thread(
                self.analysis_service.analyze,
                detail.folder,
                detail.item.message,
                persisted_outcome=state,
                reclassify=reclassify,
            )
            if generation != self._classification_generation:
                return
            self._analysis = analysis
            self._analysis_read_only = explain
            self._render_analysis(analysis, actionable=not explain)
            _LOG.debug("ui.classify duration_ms=%.1f result_count=1", (time.monotonic() - started) * 1000)
            if explain:
                self._set_status("Explanation complete. No action was applied.")
            elif isinstance(analysis, RoutingPlan):
                outcome = analysis.winner_rule_id or ("fallback" if analysis.destination else "no route")
                self._set_status(f"Routing analysis complete: {outcome}.")
            elif analysis.decision_source == "rule":
                self._set_status(f"Analysis complete: routing rule {analysis.rule_id} matched.")
            elif analysis.decision_source == "persisted-state":
                outcome = analysis.persisted_outcome.value.upper() if analysis.persisted_outcome else "unknown"
                self._set_status(f"Analysis complete: using stored {outcome} state.")
            else:
                outcome = analysis.outcome.value.upper() if analysis.outcome else "unknown"
                self._set_status(f"Classification complete: {outcome}.")
        except Exception as exc:
            self._set_status(f"Classification failed: {type(exc).__name__}")

    def action_apply(self) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None:
            self._set_status("Select a message first.")
            return
        if self._action_running:
            self._set_status("An action is already running.")
            return
        analysis = self._analysis
        if analysis is None:
            self._set_status("Classify this message first with c.")
            return
        if self._analysis_read_only:
            self._set_status("This is a read-only explanation. Press c to create an actionable analysis.")
            return
        if isinstance(analysis, RoutingPlan):
            if analysis.destination is None:
                self._set_status("The current plan has no MOVE destination.")
                return
        elif analysis.configured_action is None:
            self._set_status("No classification action is configured.")
            return
        self._confirm_action(analysis)

    def _confirm_action(self, analysis: MessageAnalysis | RoutingPlan) -> None:
        detail = self._detail
        if detail is None:
            self._set_status("Select a message before confirming an action.")
            return
        self.push_screen(
            ApplyConfirmation(analysis),
            lambda confirmed: self._confirmed_action(confirmed, analysis, detail),
        )

    def action_classification_rules(self) -> None:
        self.action_rules()

    def action_learn_rule(self) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None:
            self._set_status("Select a message before learning a rule.")
            return
        if self.settings is None or self.routing_rule_service is None:
            self._set_status("The routing rules service is unavailable.")
            return
        if detail.folder not in self.settings.spam.folders:
            self._set_status("Rule learning requires a configured source folder.")
            return
        destinations = tuple(
            folder.name
            for folder in self.folders
            if folder.selectable
            and folder.name not in self.settings.spam.folders
            and (self.settings.config_store is None or folder.name != self.settings.config_store.folder)
        )
        self.push_screen(
            RuleLearnDialog(detail.folder, detail.item.uid, destinations),
            lambda result: self._rule_learn_dialog_result(detail, result),
        )

    def _rule_learn_dialog_result(
        self,
        detail: MessageDetail,
        result: tuple[str, str | None] | None,
    ) -> None:
        if result is None or detail.item.message is None:
            return
        destination, name = result
        self.run_worker(
            self._propose_learned_rule(detail, destination, name),
            group="rule-learning",
            exclusive=True,
            exit_on_error=False,
        )

    async def _propose_learned_rule(
        self,
        detail: MessageDetail,
        destination: str,
        name: str | None,
    ) -> None:
        if self.routing_rule_service is None or detail.item.message is None:
            return
        try:
            existing = await asyncio.to_thread(self.routing_rule_service.load)
            operation = RuleLearningOperation()
            preview = await asyncio.to_thread(
                operation.propose,
                detail.item.message,
                folder=detail.folder,
                destination=destination,
                existing_rules=existing,
                name=name,
            )
            self.push_screen(
                RuleLearnPreviewScreen(detail.folder, detail.item.uid, destination, preview),
                lambda save: self._save_learned_rule(preview) if save else None,
            )
        except Exception as exc:
            self._set_status(f"Rule proposal failed: {type(exc).__name__}.")

    def _save_learned_rule(self, preview: RuleLearningPreview) -> None:
        if self.routing_rule_service is None:
            return
        self.run_worker(
            self._save_learned_rule_job(preview),
            group="rule-learning-save",
            exclusive=True,
            exit_on_error=False,
        )

    async def _save_learned_rule_job(self, preview: RuleLearningPreview) -> None:
        if self.routing_rule_service is None:
            return
        try:
            operation = RuleLearningOperation()
            result = await asyncio.to_thread(operation.save, preview, self.routing_rule_service)
            self._replace_routing_rules(result.rules)
            await self._reanalyze_current_message()
            self._activity.append(f"Saved learned routing rule {result.changed_rule_id}.")
            self._render_activity()
            self._set_status(result.detail)
            self._open_routing_rules()
        except Exception as exc:
            self._set_status(f"Rule save failed: {type(exc).__name__}.")

    def action_rules(self) -> None:
        if self.routing_rule_service is not None:
            self._open_routing_rules()
        else:
            self._open_outcome_policy()

    def action_filters(self) -> None:
        if self.routing_rule_service is not None:
            self._open_routing_rules()
            return
        if self.rule_service is None:
            self._set_status("Routing filter management is unavailable.")
            return
        try:
            rules = self.rule_service.load()
        except Exception as exc:
            self._set_status(f"Could not load routing filters: {type(exc).__name__}")
            return
        self.rules = rules
        self.push_screen(RuleCenterScreen(rules), self._rule_center_selected)

    def _routing_folders(self) -> tuple[str, ...]:
        config_folder = self.settings.config_store.folder if self.settings and self.settings.config_store else None
        return tuple(folder.name for folder in self.folders if folder.selectable and folder.name != config_folder)

    def _open_routing_rules(self) -> None:
        if self.routing_rule_service is None:
            self._set_status("Rules workbench is unavailable.")
            return
        try:
            rules = self.routing_rule_service.load()
        except Exception as exc:
            self.routing_rules = RoutingRuleSet()
            self.push_screen(
                RoutingRuleCenterScreen(self.routing_rules, self._routing_folders()),
                self._routing_rule_center_selected,
            )
            self._set_status(
                f"Could not load rules ({type(exc).__name__}). Use Migrate legacy rules to inspect conversion."
            )
            return
        self.routing_rules = rules
        self.push_screen(RoutingRuleCenterScreen(rules, self._routing_folders()), self._routing_rule_center_selected)

    async def _preview_rule_migration(self) -> None:
        path = routing_rules_path_for_config(self.config)
        operation = RuleMigrationOperation(path)
        try:
            preview = await asyncio.to_thread(operation.preview)
            self.push_screen(
                RuleMigrationPreviewScreen(path, preview),
                lambda confirmed: self._apply_rule_migration(preview) if confirmed else None,
            )
        except Exception as exc:
            self._set_status(f"Rule migration preview failed: {type(exc).__name__}.")

    def _apply_rule_migration(self, preview: RuleMigrationPreview) -> None:
        self.run_worker(
            self._apply_rule_migration_job(preview),
            group="rule-migration-apply",
            exclusive=True,
            exit_on_error=False,
        )

    async def _apply_rule_migration_job(self, preview: RuleMigrationPreview) -> None:
        try:
            operation = RuleMigrationOperation(routing_rules_path_for_config(self.config))
            result = await asyncio.to_thread(operation.apply, preview)
            self._replace_routing_rules(result.rules)
            await self._reanalyze_current_message()
            self._activity.append(f"Migrated {len(result.rules.rules)} routing rule(s) to schema 2.")
            self._render_activity()
            self._set_status("Rule migration applied.")
            self._open_routing_rules()
        except Exception as exc:
            self._set_status(f"Rule migration failed: {type(exc).__name__}.")

    def _routing_rule_center_selected(self, selection: tuple[str, str | None] | None) -> None:
        if selection is None:
            return
        action, selected = selection
        if action == "close":
            return
        if action == "migrate":
            self.run_worker(
                self._preview_rule_migration(),
                group="rule-migration-preview",
                exclusive=True,
                exit_on_error=False,
            )
            return
        if action == "fallback":
            self.run_worker(self._save_routing_fallback(selected), group="routing-rule-mutation", exclusive=True)
            return
        if action == "test-all":
            self.run_worker(self._test_routing_rules(), group="routing-rule-test", exclusive=True)
            return
        if action == "new":
            self.push_screen(
                RoutingRuleEditorScreen(None, self._routing_folders()),
                lambda rule: self._routing_rule_saved(rule, None),
            )
            return
        rule = next((item for item in self.routing_rules.rules if item.id == selected), None)
        if rule is None:
            self._set_status("Select a rule first.")
            return
        if action == "edit":
            self.push_screen(
                RoutingRuleEditorScreen(rule, self._routing_folders()),
                lambda replacement: self._routing_rule_saved(replacement, rule.id),
            )
        elif action == "test":
            self.run_worker(self._test_routing_rules(rule.id), group="routing-rule-test", exclusive=True)
        else:
            self.run_worker(
                self._mutate_routing_rule(action, rule.id),
                group="routing-rule-mutation",
                exclusive=True,
                exit_on_error=False,
            )

    def _routing_rule_saved(self, rule: RoutingRule | None, existing_id: str | None) -> None:
        if rule is None:
            self._set_status("Rule edit cancelled. No changes made.")
            return
        self.run_worker(
            self._save_routing_rule(rule, existing_id),
            group="routing-rule-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _save_routing_rule(self, rule: RoutingRule, existing_id: str | None) -> None:
        try:
            if self.routing_rule_service is None:
                raise RuntimeError("rules service unavailable")
            if existing_id is None:
                result = await asyncio.to_thread(self.routing_rule_service.add, rule)
            else:
                result = await asyncio.to_thread(self.routing_rule_service.update, existing_id, rule)
            self._replace_routing_rules(result.rules)
            await self._reanalyze_current_message()
            self._set_status(f"Saved rule {rule.id}. Current message analysis refreshed.")
            self._open_routing_rules()
        except Exception as exc:
            self._set_status(f"Rule save failed: {type(exc).__name__}.")

    async def _mutate_routing_rule(self, action: str, rule_id: str) -> None:
        try:
            if self.routing_rule_service is None:
                raise RuntimeError("rules service unavailable")
            if action == "toggle":
                rule = next(item for item in self.routing_rules.rules if item.id == rule_id)
                result = await asyncio.to_thread(self.routing_rule_service.set_enabled, rule_id, not rule.enabled)
            elif action == "up":
                result = await asyncio.to_thread(self.routing_rule_service.move, rule_id, -1)
            elif action == "down":
                result = await asyncio.to_thread(self.routing_rule_service.move, rule_id, 1)
            elif action == "remove":
                result = await asyncio.to_thread(self.routing_rule_service.remove, rule_id)
            else:
                return
            if result.changed_rule_id is None:
                self._set_status(result.detail)
                return
            self._replace_routing_rules(result.rules)
            await self._reanalyze_current_message()
            self._activity.append(result.detail)
            self._render_activity()
            self._set_status(result.detail)
            self._open_routing_rules()
        except Exception as exc:
            self._set_status(f"Rule change failed: {type(exc).__name__}.")

    async def _save_routing_fallback(self, destination: str | None) -> None:
        try:
            if self.routing_rule_service is None:
                raise RuntimeError("rules service unavailable")
            if destination is not None and destination not in self._routing_folders():
                raise ValueError(f"Destination {destination} is not an available folder.")
            result = await asyncio.to_thread(self.routing_rule_service.set_fallback_destination, destination)
            self._replace_routing_rules(result.rules)
            await self._reanalyze_current_message()
            self._set_status("Fallback destination saved.")
            self._open_routing_rules()
        except Exception as exc:
            self._set_status(f"Fallback save failed: {type(exc).__name__}.")

    async def _test_routing_rules(self, rule_scope: str | None = None) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None or self.analysis_service is None:
            self._set_status("Select a message before testing rules.")
            return
        try:
            plan = await asyncio.to_thread(
                self.analysis_service.analyze,
                detail.folder,
                detail.item.message,
                rule_scope=rule_scope,
            )
            lines = [f"Routing test: {rule_scope or 'all rules'}", f"Source: {plan.folder} UID {plan.uid}", ""]
            lines.extend(
                f"{item.rule_id}: {item.state.value}"
                + (f" p={item.confidence:.2f}" if item.confidence is not None else "")
                for item in plan.rule_results
            )
            lines.extend(
                (
                    "",
                    f"Winner: {plan.winner_rule_id or 'none'}",
                    f"Destination: {plan.destination or '(none)'}",
                )
            )
            lines.append("\nRead-only. No message was moved.")
            self.push_screen(RuleTestResultScreen("\n".join(lines)))
        except Exception as exc:
            self._set_status(f"Rule test failed: {type(exc).__name__}.")

    def _replace_routing_rules(self, rules: RoutingRuleSet) -> None:
        self.routing_rules = rules
        for service in (self.analysis_service, self.action_service):
            if service is not None and hasattr(service, "set_rules"):
                service.set_rules(rules)
        self._classification_generation += 1
        self._analysis = None
        self._analysis_read_only = False
        self.query_one("#analysis", Static).update(
            "Analysis\n  Routing rules changed. Refreshing analysis before any action."
        )

    def _open_outcome_policy(self) -> None:
        if self.settings is None or self.settings_service is None:
            self._set_status("Classification Rules editing is unavailable.")
            return
        self.push_screen(ClassificationRulesScreen(self.settings), self._outcome_policy_selected)

    def _outcome_policy_selected(self, outcome: SpamOutcome | None) -> None:
        if outcome is None or self.settings is None:
            return
        folders = tuple(
            folder.name
            for folder in self.folders
            if folder.selectable
            and folder.name not in self.settings.spam.folders
            and (self.settings.config_store is None or folder.name != self.settings.config_store.folder)
        )
        action = getattr(self.settings.spam.actions, outcome.value)
        self.push_screen(
            ClassificationRuleEditorScreen(outcome, action, folders),
            lambda result: self._outcome_action_selected(outcome, result, folders),
        )

    def _outcome_action_selected(
        self,
        outcome: SpamOutcome,
        result: tuple[Any, bool] | None,
        destinations: tuple[str, ...],
    ) -> None:
        if result is None:
            self._set_status("Classification rule edit cancelled. No changes made.")
            return
        action, explicit_delete = result
        if action.action.value == "move" and action.destination not in destinations:
            self._set_status(f"Destination {action.destination} is not an available classification destination.")
            return
        if action.action.value == "delete":
            if outcome is not SpamOutcome.SPAM or not explicit_delete:
                self._set_status("DELETE requires explicit global SPAM action confirmation.")
                return
            self.push_screen(
                DeletePolicyConfirmation(),
                lambda confirmed: self._delete_policy_confirmed(outcome, action, confirmed),
            )
            return
        self.run_worker(
            self._save_outcome_policy(outcome, action),
            group="settings-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    def _delete_policy_confirmed(self, outcome: SpamOutcome, action: Any, confirmed: bool) -> None:
        if not confirmed:
            self._set_status("Global DELETE policy change cancelled. No changes made.")
            return
        self.run_worker(
            self._save_outcome_policy(outcome, action),
            group="settings-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _save_outcome_policy(self, outcome: SpamOutcome, action: Any) -> None:
        try:
            if self.settings_service is None:
                raise RuntimeError("settings service unavailable")
            result = await asyncio.to_thread(self.settings_service.set_classification_action, outcome, action)
            self.settings = result.settings
            for service in (self.analysis_service, self.action_service):
                if service is not None and hasattr(service, "set_settings"):
                    service.set_settings(result.settings)
            await self._reanalyze_current_message()
            before = _format_action(result.previous_action)
            after = _format_action(result.action)
            self._activity.append(f"Classification rule changed: {outcome.value.upper()} {before} -> {after}")
            self._render_activity()
            self._set_status(f"Classification rule changed: {outcome.value.upper()} {before} -> {after}.")
        except Exception as exc:
            self._set_status(f"Classification rule save failed: {type(exc).__name__}.")

    def _open_rule_editor(self, rule: MailRule | None = None) -> None:
        if self.rule_service is None or self.settings is None:
            self._set_status("Routing filter management is unavailable.")
            return
        detail = self._detail
        message = detail.item.message if detail is not None else None
        screen = RuleEditorScreen(
            rule=rule,
            message=message,
            current_folder=self._selected_folder,
            existing_ids=tuple(item.id for item in self.rules.rules),
            source_folders=self.settings.spam.folders,
        )
        self.push_screen(screen, lambda result: self._rule_editor_saved(result, rule.id if rule else None))

    def _rule_editor_saved(self, result: tuple[MailRule, bool] | None, existing_id: str | None) -> None:
        if result is None:
            self._set_status("Rule edit cancelled. No changes made.")
            return
        rule, apply_current = result
        destinations = {folder.name for folder in self.folders if folder.selectable}
        if rule.action.action.value == "move" and rule.action.destination not in destinations:
            self._set_status(f"Destination {rule.action.destination} is not an available folder.")
            return
        self.run_worker(
            self._save_rule(rule, existing_id=existing_id, apply_current=apply_current),
            group="rule-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _save_rule(self, rule: MailRule, *, existing_id: str | None, apply_current: bool) -> None:
        try:
            if self.rule_service is None:
                raise RuntimeError("rule service unavailable")
            if existing_id is not None:
                result = await asyncio.to_thread(self.rule_service.update, existing_id, rule)
            else:
                result = await asyncio.to_thread(self.rule_service.add, rule)
            self._replace_rules(result.rules)
            await self._reanalyze_current_message()
            self._activity.append(f"Rule {'updated' if existing_id else 'saved'}: {rule.id}")
            self._render_activity()
            if apply_current:
                if self._analysis is None or self._analysis.rule_id != rule.id:
                    self._set_status("Rule saved, but it is not the winning rule for the current message.")
                    return
                self._set_status(f"Rule saved: {rule.id}. Confirm the exact message action.")
                self._confirm_action(self._analysis)
            else:
                self._set_status(f"Saved rule {rule.id}. Current message analysis refreshed.")
            if not apply_current:
                self.action_filters()
        except Exception as exc:
            self._set_status(f"Rule save failed: {type(exc).__name__}.")

    def _rule_center_selected(self, selection: tuple[str, str | None]) -> None:
        action, rule_id = selection
        if action == "close":
            return
        if action == "new":
            self._open_rule_editor()
            return
        rule = next((item for item in self.rules.rules if item.id == rule_id), None)
        if rule is None:
            self._set_status("Select a rule first.")
            return
        if action == "edit":
            self._open_rule_editor(rule)
        elif action == "detail":
            detail = self._detail
            message = detail.item.message if detail else None
            winning = self.rules.first_match(detail.folder, message) if message and detail else None
            matches = bool(message and detail and detail.folder in rule.source_folders and rule.match.matches(message))
            self.push_screen(
                RuleDetailScreen(
                    rule,
                    self.rules.rules.index(rule) + 1,
                    len(self.rules.rules),
                    matches_current=matches,
                    winning=winning is not None and winning.id == rule.id,
                ),
                lambda _: self.action_filters(),
            )
        elif action == "remove":
            self.push_screen(
                RuleDeleteConfirmation(rule),
                lambda confirm: self._remove_rule_confirmed(rule.id, confirm),
            )
        elif action == "test":
            self.run_worker(self._test_rule(rule), group="rule-test", exclusive=True, exit_on_error=False)
        else:
            self.run_worker(
                self._mutate_rule(action, rule.id),
                group="rule-mutation",
                exclusive=True,
                exit_on_error=False,
            )

    def _remove_rule_confirmed(self, rule_id: str, confirmed: bool) -> None:
        if confirmed:
            self.run_worker(
                self._mutate_rule("remove", rule_id),
                group="rule-mutation",
                exclusive=True,
                exit_on_error=False,
            )
        else:
            self._set_status("Rule removal cancelled. No changes made.")

    async def _mutate_rule(self, action: str, rule_id: str) -> None:
        try:
            if self.rule_service is None:
                raise RuntimeError("rule service unavailable")
            rule = next(item for item in self.rules.rules if item.id == rule_id)
            if action == "toggle":
                result = await asyncio.to_thread(self.rule_service.set_enabled, rule_id, not rule.enabled)
            elif action == "up":
                result = await asyncio.to_thread(self.rule_service.move, rule_id, -1)
            elif action == "down":
                result = await asyncio.to_thread(self.rule_service.move, rule_id, 1)
            elif action == "remove":
                result = await asyncio.to_thread(self.rule_service.remove, rule_id)
            else:
                return
            if result.changed_rule_id is None:
                self._set_status(result.detail)
                return
            self._replace_rules(result.rules)
            await self._reanalyze_current_message()
            self._activity.append(result.detail)
            self._render_activity()
            self._set_status(result.detail)
            self.action_filters()
        except Exception as exc:
            self._set_status(f"Rule change failed: {type(exc).__name__}.")

    async def _test_rule(self, rule: MailRule) -> None:
        if self.rule_test_service is None:
            self._set_status("Rule testing is unavailable in this session.")
            return
        try:
            result = await asyncio.to_thread(self.rule_test_service.test, rule, limit=50)
            lines = [f"Rule test: {rule.id}", f"Scanned: {result.scanned}", f"Matches: {len(result.matches)}", ""]
            lines.extend(f"{item.folder} UID {item.uid}  {item.sender}  {item.subject}" for item in result.matches)
            lines.append("\nRead-only. No messages changed.")
            self.push_screen(RuleTestResultScreen("\n".join(lines)))
        except Exception as exc:
            self._set_status(f"Rule test failed: {type(exc).__name__}.")

    def _replace_rules(self, rules: RuleSet) -> None:
        self.rules = rules
        for service in (self.analysis_service, self.action_service):
            if service is not None and hasattr(service, "set_rules"):
                service.set_rules(rules)

    async def _reanalyze_current_message(self) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None or self.analysis_service is None:
            return
        generation = self._classification_generation
        state = detail.persisted_state.outcome if detail.persisted_state else None
        analysis = await asyncio.to_thread(
            self.analysis_service.analyze,
            detail.folder,
            detail.item.message,
            persisted_outcome=state,
        )
        if generation != self._classification_generation:
            return
        self._analysis_read_only = False
        self._analysis = analysis
        self._render_analysis(analysis)

    def _render_activity(self) -> None:
        self.query_one("#activity", Static).update("Activity\n" + "\n".join(self._activity[-20:]))

    def _confirmed_action(
        self,
        confirmed: bool,
        analysis: MessageAnalysis | RoutingPlan,
        detail: MessageDetail,
    ) -> None:
        if confirmed and not self._action_running:
            self._action_running = True
            self.run_worker(
                self._apply_confirmed(analysis, detail),
                group="action",
                exit_on_error=False,
            )

    async def _apply_confirmed(
        self,
        analysis: MessageAnalysis | RoutingPlan,
        detail: MessageDetail,
    ) -> None:
        if self.action_service is None:
            self._set_status("Mailbox action service is unavailable.")
            self._action_running = False
            return
        self._set_status("Applying confirmed mailbox action in a background thread…")
        started = time.monotonic()
        try:
            if isinstance(analysis, RoutingPlan):
                routing_receipt: RoutingActionReceipt = await asyncio.to_thread(
                    self.action_service.apply,
                    analysis,
                    uidvalidity=detail.uidvalidity,
                    confirmed_by_user=True,
                )
                result = "confirmed" if routing_receipt.applied and routing_receipt.confirmed else "not confirmed"
                activity = (
                    f"{routing_receipt.plan.folder} UID {routing_receipt.plan.uid}: MOVE {result}"
                    f" to {routing_receipt.plan.destination}"
                )
                if routing_receipt.detail:
                    activity += f" ({routing_receipt.detail})"
                self._activity.append(activity)
                self.query_one("#activity", Static).update("Activity\n" + "\n".join(self._activity[-20:]))
                self._set_status(f"Action {result}.")
                if routing_receipt.applied and routing_receipt.confirmed:
                    summary = self._find_summary(routing_receipt.plan.folder, routing_receipt.plan.uid)
                    rows = [
                        (row_folder, row_summary)
                        for row_folder, row_summary in self._rows
                        if not (
                            row_folder == routing_receipt.plan.folder and row_summary.uid == routing_receipt.plan.uid
                        )
                    ]
                    self._populate_rows(tuple(rows))
                    if (
                        self._detail is not None
                        and self._detail.folder == routing_receipt.plan.folder
                        and self._detail.item.uid == routing_receipt.plan.uid
                    ):
                        self._detail = None
                        self._analysis = None
                        self.query_one("#message-detail", MessageDetailView).update(
                            "Select a message to read its text content."
                        )
                        self.query_one("#analysis", Static).update("Analysis will not run until requested.")
                    self._set_status("MOVE confirmed. Updating folder counts…")
                    self._adjust_folder_count(routing_receipt.plan.folder, -1, summary=summary)
                    targets = tuple(
                        dict.fromkeys(
                            folder
                            for folder in (routing_receipt.plan.folder, routing_receipt.plan.destination)
                            if folder
                        )
                    )
                    self.run_worker(self._refresh_action_counts(targets), group="folder-counts", exit_on_error=False)
                return
            receipt: ActionReceipt = await asyncio.to_thread(
                self.action_service.apply,
                analysis,
                uidvalidity=detail.uidvalidity,
                confirmed_by_user=True,
            )
            result = "confirmed" if receipt.applied and receipt.confirmed else "not confirmed"
            _LOG.debug("ui.apply duration_ms=%.1f result_count=1", (time.monotonic() - started) * 1000)
            activity = f"{receipt.folder} UID {receipt.uid}: {receipt.requested_action.action.value.upper()} {result}"
            if receipt.destination:
                activity += f" to {receipt.destination}"
            if receipt.detail:
                activity += f" ({receipt.detail})"
            self._activity.append(activity)
            self.query_one("#activity", Static).update("Activity\n" + "\n".join(self._activity[-20:]))
            self._set_status(f"Action {result}.")
            if receipt.applied and receipt.confirmed:
                action = receipt.requested_action.action.value
                if action in {"move", "delete"}:
                    summary = self._find_summary(receipt.folder, receipt.uid)
                    rows = [
                        (row_folder, summary)
                        for row_folder, summary in self._rows
                        if not (row_folder == receipt.folder and summary.uid == receipt.uid)
                    ]
                    self._populate_rows(tuple(rows))
                    if self._detail is not None and self._detail.item.uid == receipt.uid:
                        self._detail = None
                        self._analysis = None
                        self.query_one("#message-detail", MessageDetailView).update(
                            "Select a message to read its text content."
                        )
                        self.query_one("#analysis", Static).update("Analysis will not run until requested.")
                if action in {"move", "delete"}:
                    action_name = receipt.requested_action.action.value.upper()
                    self._set_status(f"Action confirmed. {action_name} applied; updating counts…")
                    self._adjust_folder_count(receipt.folder, -1, summary=summary)
                    targets = tuple(dict.fromkeys(folder for folder in (receipt.folder, receipt.destination) if folder))
                    self.run_worker(self._refresh_action_counts(targets), group="folder-counts", exit_on_error=False)
                elif action == "keep" and analysis.outcome is not None:
                    rows = []
                    for row_folder, summary in self._rows:
                        if row_folder == receipt.folder and summary.uid == receipt.uid:
                            if self._list_folder == "Review" and analysis.outcome is not SpamOutcome.REVIEW:
                                continue
                            summary = replace(summary, persisted_state=analysis.outcome)
                        rows.append((row_folder, summary))
                    self._populate_rows(tuple(rows))
        except Exception as exc:
            self._set_status(f"Action failed: {type(exc).__name__}")
        finally:
            self._action_running = False

    def action_refresh(self) -> None:
        if self.mail_service is None:
            state = self.session.status.value if self.session is not None else SessionState.DISCONNECTED.value
            self._set_status(f"Mail is disconnected ({state}). Press s for System.")
            return
        self._set_status("Refreshing folders and current page…")
        self.run_worker(self._refresh(), group="startup-folders", exclusive=True, exit_on_error=False)

    async def _refresh(self) -> None:
        try:
            self.folders = await asyncio.to_thread(self.mail_service.list_folders, include_counts=False)
            self._render_folders()
            if self._list_folder is not None:
                await self._select_folder(self._list_folder)
            self.run_worker(self._refresh_counts(), group="folder-counts", exit_on_error=False)
        except Exception as exc:
            self._set_status(f"Refresh failed: {type(exc).__name__}")

    async def _refresh_counts(self) -> None:
        if self._loading_folder is None:
            self._set_status("Refreshing counts…")
        try:
            self.folders = await asyncio.to_thread(self.mail_service.list_folders, include_counts=True)
            self._render_folders()
            if self._loading_folder is None:
                self._set_status("Folder counts refreshed.")
        except Exception as exc:
            if self._loading_folder is None:
                self._set_status(f"Count refresh failed: {type(exc).__name__}")

    def _find_summary(self, folder: str, uid: int) -> MailSummary | None:
        return next(
            (summary for row_folder, summary in self._rows if row_folder == folder and summary.uid == uid),
            None,
        )

    def _adjust_folder_count(self, name: str, delta: int, *, summary: MailSummary | None = None) -> None:
        unseen_delta = (
            delta
            if summary is not None
            and not any(
                (flag.decode("ascii", errors="replace") if isinstance(flag, bytes) else flag) == "\\Seen"
                for flag in summary.flags
            )
            else 0
        )
        self.folders = tuple(
            replace(folder, total=max(0, folder.total + delta), unread=max(0, folder.unread + unseen_delta))
            if folder.name == name and folder.total is not None and folder.unread is not None
            else folder
            for folder in self.folders
        )
        self._render_folders()

    async def _refresh_action_counts(self, folders: tuple[str, ...]) -> None:
        try:
            counts = await asyncio.to_thread(self.mail_service.refresh_folder_counts, folders)
            self.folders = tuple(
                replace(folder, total=counts[folder.name][0], unread=counts[folder.name][1])
                if folder.name in counts
                else folder
                for folder in self.folders
            )
            self._render_folders()
            self._set_status("Action complete. Source/destination counts refreshed.")
        except Exception as exc:
            self._set_status(f"Action complete. Count refresh failed: {type(exc).__name__}")

    _PANE_IDS = ("folders", "messages", "message-detail")

    def _focused_pane_index(self) -> int:
        widget = self.focused
        while widget is not None:
            if widget.id in self._PANE_IDS:
                return self._PANE_IDS.index(widget.id)
            widget = widget.parent
        return 0

    def _focus_pane(self, index: int) -> None:
        self.query_one(f"#{self._PANE_IDS[index]}").focus()

    def action_next_pane(self) -> None:
        self._focus_pane((self._focused_pane_index() + 1) % len(self._PANE_IDS))

    def action_previous_pane(self) -> None:
        self._focus_pane((self._focused_pane_index() - 1) % len(self._PANE_IDS))

    def action_pane_left(self) -> None:
        self._focus_pane(max(0, self._focused_pane_index() - 1))

    def action_pane_right(self) -> None:
        self._focus_pane(min(len(self._PANE_IDS) - 1, self._focused_pane_index() + 1))

    def action_help(self) -> None:
        if isinstance(self.screen, HelpScreen):
            self.screen.action_close_help()
        else:
            self.push_screen(HelpScreen())

    def _operation_context(self) -> OperationContext:
        settings = self.settings
        return OperationContext(
            config=settings is not None,
            credential=bool(self._password),
            connected=self.mail_service is not None,
            selected_folder=self._selected_folder in self._folder_item_by_name and self._selected_folder != "Review",
            selected_message=self._detail is not None and self._detail.item.message is not None,
            routing_rules=self.routing_rule_service is not None,
            config_store=settings is not None and settings.config_store is not None,
        )

    def action_command_center(self) -> None:
        self.push_screen(
            CommandCenterScreen(OPERATION_SPECS, self._operation_context()),
            self._dispatch_operation,
        )

    def _dispatch_operation(self, operation_id: str | None) -> None:
        if operation_id is None:
            return
        spec = OPERATION_BY_ID.get(operation_id)
        if spec is None:
            return
        reason = spec.unavailable_reason(self._operation_context())
        if reason is not None:
            self._set_status(f"{spec.title} unavailable: {reason}.")
            return
        settings = self.settings
        if operation_id == "init":
            session = self._ensure_session()
            self.push_screen(SetupDialog(session.config_path, session.settings), self._setup_request)
        elif operation_id == "config.show" and settings is not None:
            self.push_screen(EffectiveConfigScreen(settings, self.config))
        elif operation_id == "auth.set" and settings is not None:
            self.push_screen(CredentialSetDialog(settings), self._credential_set_request)
        elif operation_id == "auth.status":
            self.action_system()
        elif operation_id == "auth.delete" and settings is not None:
            self.push_screen(CredentialDeleteDialog(settings.imap.auth.source), self._credential_delete_request)
        elif operation_id == "auth.change_passphrase" and settings is not None:
            self.push_screen(
                VaultPassphraseDialog(settings.imap.auth.vault_min_passphrase_length),
                self._vault_passphrase_request,
            )
        elif operation_id == "folders":
            self.action_refresh()
        elif operation_id == "doctor":
            self.action_doctor()
        elif operation_id == "clean":
            if self._operation_context().selected_folder:
                self.action_clean_dialog()
            else:
                self.action_legacy_clean()
        elif operation_id == "explain":
            self.action_explain()
        elif operation_id.startswith("rule."):
            if operation_id == "rule.learn":
                self.action_learn_rule()
            else:
                self.action_rules()
        elif operation_id.startswith("progress."):
            self.action_progress()
        elif operation_id.startswith("state."):
            self.action_state()
        elif operation_id == "mail.list":
            self.action_refresh()
        elif operation_id == "mail.show":
            self._focus_pane(2)
        elif operation_id == "mail.classify":
            self.action_classify()
        elif operation_id == "review.list":
            self._open_review_view()
        elif operation_id.startswith("config_ledger."):
            self.action_config_ledger()

    def action_config_ledger(self) -> None:
        context = self._operation_context()
        if self._config_ledger_mutation_running:
            self._set_status("A Config Ledger mutation is still running.")
            return
        if not context.config:
            self._set_status("Config Ledger requires a valid configuration.")
            return
        if not context.config_store:
            self._set_status("Config Ledger is disabled. Add a [config_store] table to configuration.")
            return
        if not context.connected or not context.credential:
            self._set_status("Connect with configured credentials before opening Config Ledger.")
            return
        self.run_worker(
            self._load_config_ledger(),
            group="config-ledger",
            exclusive=True,
            exit_on_error=False,
        )

    def _config_ledger_call(self, operation: Callable[[ConfigLedger], Any], *, writable: bool = False) -> Any:
        settings = self.settings
        if settings is None or settings.config_store is None or not self._password:
            raise RuntimeError("connected Config Ledger settings are unavailable")
        store = settings.config_store
        with ConfigStoreMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=self._password,
            folder=store.folder,
            max_file_bytes=store.max_file_bytes,
            writable=writable,
        ) as mailbox:
            return operation(ConfigLedger(mailbox, store))

    async def _load_config_ledger(self) -> None:
        try:
            summaries = await asyncio.to_thread(self._config_ledger_call, lambda ledger: ledger.list_tools())
        except Exception as exc:
            self._set_status(f"Config Ledger unavailable: {type(exc).__name__}.")
            return
        store_folder = self.settings.config_store.folder if self.settings and self.settings.config_store else ""
        self.push_screen(
            ConfigLedgerScreen(summaries, store_folder=store_folder),
            self._config_ledger_choice,
        )

    def _config_ledger_choice(self, choice: tuple[str, str] | None) -> None:
        if choice is None:
            return
        action, tool = choice
        if action == "push":
            self.push_screen(ConfigPushDialog(tool), self._config_push_request)
        elif action == "versions":
            self._load_config_versions(tool)
        elif action == "view":
            self._show_config_text(tool, "", "view")
        elif action == "diff":
            self._show_config_text(tool, "", "diff")
        elif action == "pull":
            self._load_config_versions(tool, action="pull")

    def _load_config_versions(
        self,
        tool: str,
        *,
        action: str = "versions",
        selected_version: str | None = None,
    ) -> None:
        self.run_worker(
            self._load_config_versions_job(tool, action, selected_version),
            group="config-ledger",
            exclusive=True,
            exit_on_error=False,
        )

    async def _load_config_versions_job(
        self,
        tool: str,
        action: str,
        selected_version: str | None,
    ) -> None:
        try:
            versions = await asyncio.to_thread(
                self._config_ledger_call,
                lambda ledger: ledger.list_versions(tool),
            )
        except Exception as exc:
            self._set_status(f"Config Ledger versions unavailable: {type(exc).__name__}.")
            return
        if action == "pull":
            self.push_screen(
                ConfigPullDialog(tool, versions, selected_version),
                self._config_pull_request,
            )
        else:
            self.push_screen(
                ConfigVersionsScreen(tool, versions),
                self._config_version_choice,
            )

    def _config_version_choice(self, choice: tuple[str, str, str] | None) -> None:
        if choice is None:
            return
        action, tool, version = choice
        if action == "view":
            self._show_config_text(tool, version, "view")
        elif action == "diff":
            self._show_config_text(tool, version, "diff")
        elif action == "pull":
            self._load_config_versions(tool, action="pull", selected_version=version)

    def _show_config_text(self, tool: str, version: str, action: str) -> None:
        self.run_worker(
            self._show_config_text_job(tool, version, action),
            group="config-ledger",
            exclusive=True,
            exit_on_error=False,
        )

    async def _show_config_text_job(self, tool: str, version: str, action: str) -> None:
        selected_version = version or None
        try:
            if action == "view":
                body = await asyncio.to_thread(
                    self._config_ledger_call,
                    lambda ledger: ledger.cat(tool, version=selected_version),
                )
                title = f"Config Ledger snapshot: {tool} {version or 'current'}"
                warning = "Snapshot text may contain sensitive values. Review only in a trusted terminal."
            else:
                body = await asyncio.to_thread(
                    self._config_ledger_call,
                    lambda ledger: ledger.diff(tool, version=selected_version),
                )
                title = f"Config Ledger diff: {tool} {version or 'current'}"
                warning = "Diff text may reveal sensitive values. Review only in a trusted terminal."
        except Exception as exc:
            self._set_status(f"Config Ledger {action} unavailable: {type(exc).__name__}.")
            return
        self.push_screen(ConfigTextScreen(title, body, warning=warning))

    def _config_push_request(self, request: ConfigPushRequest | None) -> None:
        if request is None:
            return
        store_folder = self.settings.config_store.folder if self.settings and self.settings.config_store else ""
        self.push_screen(
            ConfigPushConfirmation(request, store_folder),
            lambda confirmed: self._push_config(request) if confirmed else self._set_status("Config push cancelled."),
        )

    def _push_config(self, request: ConfigPushRequest) -> None:
        if self._config_ledger_mutation_running:
            self._set_status("A Config Ledger mutation is still running.")
            return
        self._config_ledger_mutation_running = True
        self.run_worker(
            self._push_config_job(request),
            group="config-ledger-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _push_config_job(self, request: ConfigPushRequest) -> None:
        try:
            result = await asyncio.to_thread(
                self._config_ledger_call,
                lambda ledger: ledger.push(
                    request.tool,
                    request.path,
                    allow_sensitive_plaintext=request.allow_sensitive_plaintext,
                    resolve_conflict=request.resolve_conflict,
                ),
                writable=True,
            )
        except SensitiveConfigError as exc:
            self.push_screen(ConfigTextScreen("Config push blocked", str(exc)))
            self._config_ledger_mutation_running = False
            return
        except ConfigLedgerError as exc:
            self.push_screen(ConfigTextScreen("Config push blocked", str(exc)))
            self._config_ledger_mutation_running = False
            return
        except Exception as exc:
            self._set_status(f"Config push failed: {type(exc).__name__}.")
            self._config_ledger_mutation_running = False
            return
        snapshot = result.snapshot
        state = "already current" if not result.created else "snapshot pushed"
        body = (
            f"Tool: {snapshot.tool}\nVersion: {snapshot.version_id}\n"
            f"SHA256: {snapshot.content_sha256}\nSize: {snapshot.size_bytes} bytes\n"
            f"Parents: {', '.join(snapshot.parent_version_ids) or 'none'}"
        )
        self._activity.append(f"Config Ledger {state}: {snapshot.tool} {snapshot.version_id}.")
        self._render_activity()
        self._set_status(f"Config Ledger {state}.")
        self.push_screen(ConfigTextScreen("Config Ledger push result", body))
        self._config_ledger_mutation_running = False

    def _config_pull_request(self, request: ConfigPullRequest | None) -> None:
        if request is None:
            return
        self.run_worker(
            self._preview_config_pull(request),
            group="config-ledger-preview",
            exclusive=True,
            exit_on_error=False,
        )

    async def _preview_config_pull(self, request: ConfigPullRequest) -> None:
        try:
            preview = await asyncio.to_thread(
                self._config_ledger_call,
                lambda ledger: ledger.preview_pull(
                    request.tool,
                    version=request.version_id,
                    to=request.target,
                ),
            )
        except Exception as exc:
            self._set_status(f"Config pull preview failed: {type(exc).__name__}.")
            return
        self.push_screen(
            ConfigPullPreviewScreen(preview),
            lambda confirmed: (
                self._confirm_config_pull(preview) if confirmed else self._set_status("Config pull cancelled.")
            ),
        )

    def _confirm_config_pull(self, preview: ConfigPullPreview) -> None:
        is_active_config = preview.target.resolve() == self.config.resolve()
        if is_active_config:
            self._confirm_session_reload(
                "Pull will replace the active configuration file.",
                lambda: self._apply_config_pull(preview),
            )
        else:
            self._apply_config_pull(preview)

    def _apply_config_pull(self, preview: ConfigPullPreview) -> None:
        if self._config_ledger_mutation_running:
            self._set_status("A Config Ledger mutation is still running.")
            return
        self._config_ledger_mutation_running = True
        self.run_worker(
            self._apply_config_pull_job(preview),
            group="config-ledger-mutation",
            exclusive=True,
            exit_on_error=False,
        )

    async def _apply_config_pull_job(self, preview: ConfigPullPreview) -> None:
        try:
            result = await asyncio.to_thread(
                self._config_ledger_call,
                lambda ledger: ledger.apply_pull(preview, confirm_overwrite=True),
            )
        except ConfigLedgerError as exc:
            self._set_status(f"Config pull blocked: {exc}. Preview again before retrying.")
            self._config_ledger_mutation_running = False
            return
        except Exception as exc:
            self._set_status(f"Config pull failed: {type(exc).__name__}.")
            self._config_ledger_mutation_running = False
            return
        if preview.target.resolve() == self.config.resolve() and self.session is not None:
            await self._reload_session_job()
        if result.already_up_to_date:
            self._set_status(f"{result.target} is already up to date.")
        elif result.written:
            self._set_status(f"Wrote {result.target}")
        body = f"Target: {result.target}\nVersion: {result.version_id}\nWritten: {result.written}"
        self.push_screen(ConfigTextScreen("Config Ledger pull result", body))
        self._config_ledger_mutation_running = False

    def _open_review_view(self) -> None:
        if self._selected_folder != "Review":
            generation = self._begin_folder_load("Review")
            self.run_worker(
                self._select_folder("Review", generation),
                group="folder-page",
                exclusive=True,
                exit_on_error=False,
            )

    def _ensure_session(self) -> AppSession:
        if self.session is None:
            self.session = AppSession(self.config)
            self.session.load_local()
            self._adopt_session()
        return self.session

    def action_system(self) -> None:
        session = self._ensure_session()
        self.push_screen(
            SystemScreen(
                session.config_path,
                session.status,
                settings=session.settings,
                credential_summary=session.credential_summary,
                error_type=session.error_type,
            ),
            self._system_choice,
        )

    def _system_choice(self, choice: str | None) -> None:
        if choice is None:
            return
        session = self._ensure_session()
        settings = session.settings
        if choice == "setup":
            self.push_screen(SetupDialog(session.config_path, settings), self._setup_request)
        elif choice == "config" and settings is not None:
            self.push_screen(EffectiveConfigScreen(settings, session.config_path))
        elif choice == "connect":
            self.action_connect()
        elif choice == "disconnect":
            self._disconnect_session()
        elif choice == "reload":
            self._confirm_session_reload("Reload local configuration", self._reload_session)
        elif choice == "auth-set" and settings is not None:
            self.push_screen(CredentialSetDialog(settings), self._credential_set_request)
        elif choice == "auth-delete" and settings is not None:
            self.push_screen(
                CredentialDeleteDialog(settings.imap.auth.source),
                self._credential_delete_request,
            )
        elif choice == "auth-passphrase" and settings is not None:
            self.push_screen(
                VaultPassphraseDialog(settings.imap.auth.vault_min_passphrase_length),
                self._vault_passphrase_request,
            )

    def _confirm_session_reload(self, reason: str, callback: Any) -> None:
        session = self._ensure_session()
        if not session.connected:
            callback()
            return
        self.push_screen(
            ReloadConfirmation(reason),
            lambda confirmed: callback() if confirmed else self._set_status("Session reload cancelled."),
        )

    def _setup_request(self, request: SetupRequest | None) -> None:
        if request is None:
            return
        self._confirm_session_reload(
            "Save configuration and reload the session?",
            lambda: self.run_worker(
                self._save_setup(request),
                group="session-reload",
                exclusive=True,
                exit_on_error=False,
            ),
        )

    async def _save_setup(self, request: SetupRequest) -> None:
        try:
            await asyncio.to_thread(write_settings, request.settings, request.config_path, overwrite=request.overwrite)
            await self._reload_session_job(request.config_path)
            self._set_status("Configuration saved. Connect from System when ready.")
        except Exception as exc:
            self._set_status(f"Configuration save failed: {type(exc).__name__}.")

    def _reload_session(self, config_path: Path | None = None) -> None:
        self._ensure_session()
        self.run_worker(
            self._reload_session_job(config_path),
            group="session-reload",
            exclusive=True,
            exit_on_error=False,
        )

    async def _reload_session_job(self, config_path: Path | None = None) -> None:
        session = self._ensure_session()
        try:
            state = await asyncio.to_thread(session.reload, config_path)
            self._adopt_session()
            self._set_status(f"Session reloaded: {state.value}. Mail remains disconnected.")
        except Exception as exc:
            self._set_status(f"Session reload failed: {type(exc).__name__}.")

    def _adopt_session(self) -> None:
        if self.session is None:
            return
        session = self.session
        self.config = session.config_path
        self._password = session.password
        self.settings = session.settings
        self.mail_service = session.mail_service
        self.analysis_service = session.analysis_service
        self.action_service = session.action_service
        self.routing_rules = session.routing_rules
        self.routing_rule_service = session.routing_rule_service
        self.review_operation = ReviewOperation(self.settings) if self.settings is not None else None
        self.settings_service = SettingsService(self.config) if self.settings is not None else None
        self.rule_service = (
            RuleService(rules_path_for_config(self.config), source_folders=self.settings.spam.folders)
            if self.settings is not None
            else None
        )
        self.rules = RuleSet()
        self.folders = ()
        self._folder_item_by_name = {}
        self._review_item = None
        self._rows = []
        self._page_offset = 0
        self._selected_folder = None
        self._list_folder = None
        self._loading_folder = None
        self._detail = None
        self._analysis = None
        self._analysis_read_only = False
        self._classification_generation += 1
        self._image_generation += 1
        self._image_analysis = None
        self._remote_image_analysis = None
        self._remote_image_skips = ()
        self._remote_images_loaded = None
        if self.is_mounted:
            self.query_one("#messages", DataTable).clear()
            self.query_one("#folders", ListView).clear()
            self._render_folders()
            self._render_mail_controls(total=0)
            self.query_one("#message-detail", MessageDetailView).update(
                "Mail is disconnected. System, configuration, and credential workflows remain available.\n\n"
                "Press s to connect or configure a session."
            )

    def action_connect(self) -> None:
        session = self._ensure_session()
        if session.settings is None:
            self._set_status("A valid local configuration is required before connecting.")
            return
        source = session.settings.imap.auth.source
        if source is AuthSource.KEYRING:
            self._start_connect("")
        else:
            self.push_screen(ConnectDialog(source), self._connect_secret)

    def _connect_secret(self, secret: str | None) -> None:
        if secret is not None:
            self._start_connect(secret)

    def _start_connect(self, secret: str) -> None:
        self._set_status("Connecting to IMAP…")
        self.run_worker(
            self._connect_session(secret),
            group="session-connect",
            exclusive=True,
            exit_on_error=False,
        )

    async def _connect_session(self, secret: str) -> None:
        session = self._ensure_session()
        try:
            await asyncio.to_thread(session.connect, secret)
            self._adopt_session()
            await self._startup()
        except Exception as exc:
            self._adopt_session()
            self._set_status(f"Connection failed: {type(exc).__name__}. Open System to retry.")
        finally:
            secret = ""

    def _disconnect_session(self) -> None:
        session = self._ensure_session()
        self.run_worker(
            self._disconnect_session_job(session),
            group="session-disconnect",
            exclusive=True,
            exit_on_error=False,
        )

    async def _disconnect_session_job(self, session: AppSession) -> None:
        await asyncio.to_thread(session.disconnect)
        self._adopt_session()
        self._set_status(f"Disconnected. Session state: {session.status.value}.")

    def _credential_set_request(self, request: CredentialSetRequest | None) -> None:
        if request is None or self.settings is None:
            return
        settings = self.settings
        self._confirm_session_reload(
            "Store the credential and reload the session?",
            lambda: self.run_worker(
                self._store_credential(settings, request),
                group="credential-update",
                exclusive=True,
                exit_on_error=False,
            ),
        )

    async def _store_credential(self, settings: Settings, request: CredentialSetRequest) -> None:
        try:

            def store() -> None:
                backend = credential_backend_for_storage(
                    request.storage,
                    vault_path=settings.imap.auth.vault_path,
                    vault_min_passphrase_length=settings.imap.auth.vault_min_passphrase_length,
                )
                ref = CredentialRef(settings.imap.host, settings.imap.port, settings.imap.username)
                configure_stored_credential(
                    config_path=self.config,
                    config=settings,
                    backend=backend,
                    ref=ref,
                    password=request.password,
                    passphrase=request.passphrase,
                    replace=request.replace,
                )

            await asyncio.to_thread(store)
            await self._reload_session_job()
            self._set_status("Credential stored. The session is disconnected and ready to connect.")
        except Exception as exc:
            self._set_status(f"Credential update failed: {type(exc).__name__}.")
        finally:
            request.password = ""
            request.passphrase = None

    def _credential_delete_request(self, passphrase: str | None) -> None:
        if passphrase is None or self.settings is None:
            return
        settings = self.settings
        self._confirm_session_reload(
            "Delete the stored credential and reload the session?",
            lambda: self.run_worker(
                self._delete_credential(settings, passphrase),
                group="credential-update",
                exclusive=True,
                exit_on_error=False,
            ),
        )

    async def _delete_credential(self, settings: Settings, passphrase: str) -> None:
        try:

            def delete() -> bool:
                auth = settings.imap.auth
                backend = credential_backend_for(
                    auth.source,
                    vault_path=auth.vault_path,
                    vault_min_passphrase_length=auth.vault_min_passphrase_length,
                )
                ref = CredentialRef(settings.imap.host, settings.imap.port, settings.imap.username)
                return remove_stored_credential(
                    config_path=self.config,
                    config=settings,
                    backend=backend,
                    ref=ref,
                    passphrase=passphrase if auth.source is AuthSource.VAULT else None,
                )

            deleted = await asyncio.to_thread(delete)
            await self._reload_session_job()
            self._set_status("Stored credential deleted." if deleted else "No stored credential was deleted.")
        except Exception as exc:
            self._set_status(f"Credential deletion failed: {type(exc).__name__}.")

    def _vault_passphrase_request(self, request: VaultPassphraseChange | None) -> None:
        if request is None or self.settings is None:
            return
        settings = self.settings
        self._confirm_session_reload(
            "Change the vault passphrase and reload the session?",
            lambda: self.run_worker(
                self._change_vault_passphrase(settings, request),
                group="credential-update",
                exclusive=True,
                exit_on_error=False,
            ),
        )

    async def _change_vault_passphrase(self, settings: Settings, request: VaultPassphraseChange) -> None:
        try:
            await asyncio.to_thread(
                change_credential_vault_passphrase,
                request.old_passphrase,
                request.new_passphrase,
                vault_path=settings.imap.auth.vault_path,
                min_passphrase_length=settings.imap.auth.vault_min_passphrase_length,
            )
            await self._reload_session_job()
            self._set_status("Vault passphrase changed. The session is disconnected.")
        except Exception as exc:
            self._set_status(f"Vault passphrase change failed: {type(exc).__name__}.")
        finally:
            request.old_passphrase = ""
            request.new_passphrase = ""

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def on_unmount(self) -> None:
        self._image_cache.clear()
        self._image_analysis = None
        self._remote_image_analysis = None
        self._remote_image_cache.clear()
        self._remote_image_skips = ()
        self._remote_images_loaded = None
        self._password = ""
        if self.session is not None:
            self.session.close()
        else:
            if self.mail_service is not None:
                self.mail_service.close()
            if self.action_service is not None and hasattr(self.action_service, "close"):
                self.action_service.close()


def run(config: Path) -> None:
    session = AppSession(config)
    session.load_local()
    try:
        MailReviewApp(
            config,
            session=session,
            image_analysis_service=ImageAnalysisService(),
            remote_image_loader=RemoteImageLoader(),
        ).run()
    finally:
        session.close()
