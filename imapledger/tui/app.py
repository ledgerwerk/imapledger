from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Label, ListItem, ListView, Static

from ..action_service import ActionReceipt, ActionService
from ..analysis_service import AnalysisService, MessageAnalysis
from ..classification_state import SpamOutcome
from ..config import Settings, load_settings
from ..credentials import resolve_credential
from ..mail_service import MailService, MessageDetail
from ..mailbox import FolderInfo
from ..message import MailSummary
from ..rules import RuleSet, load_rules, rules_path_for_config

_LOG = logging.getLogger(__name__)


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

    def __init__(self, analysis: MessageAnalysis) -> None:
        super().__init__()
        self.analysis = analysis

    def compose(self) -> ComposeResult:
        action = self.analysis.configured_action
        action_text = action.action.value.upper() if action else "UNKNOWN"
        if action is not None and action.destination:
            action_text += f" to {action.destination}"
        warning = (
            "Permanently delete this exact message? UID EXPUNGE cannot be undone by imapledger."
            if action is not None and action.action.value == "delete"
            else "Apply the configured action to this exact message?"
        )
        with Vertical(id="confirm-box"):
            yield Static(warning, markup=False)
            yield Static(
                f"Outcome: {self.analysis.outcome.value.upper() if self.analysis.outcome else 'RULE'}\n"
                f"Action: {action_text}\nFolder: {self.analysis.folder}\nUID: {self.analysis.uid}",
                markup=False,
            )
            with Horizontal(id="confirm-buttons"):
                yield Button("Apply", variant="error" if action_text == "DELETE" else "primary", id="apply")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "apply")

    def action_cancel(self) -> None:
        self.dismiss(False)


class MailReviewApp(App[None]):
    TITLE = "imapledger"
    SUB_TITLE = "Safe terminal mail review"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("c", "classify", "Classify"),
        Binding("C", "reclassify", "Reclassify"),
        Binding("a", "apply", "Apply"),
        Binding("tab", "next_pane", "Next pane"),
        Binding("?", "help", "Help"),
    ]
    CSS = """
    #workspace { height: 1fr; layout: vertical; }
    .pane { border: round $primary-background; padding: 0 1; }
    #folder-pane { height: 8; width: 1fr; }
    #message-pane { height: 1fr; width: 1fr; }
    #detail-pane { height: 2fr; width: 1fr; }
    #folders, #messages { height: 1fr; }
    #message-detail { height: 1fr; overflow-y: auto; }
    #analysis { height: 8; border-top: solid $primary-background; padding-top: 1; overflow-y: auto; }
    #activity { height: 5; border-top: solid $primary-background; padding-top: 1; overflow-y: auto; }
    #status { height: 1; dock: bottom; background: $primary-background; color: $text; }
    """

    def __init__(
        self,
        config: Path,
        *,
        mail_service: Any | None = None,
        settings: Settings | None = None,
        rules: RuleSet | None = None,
        analysis_service: Any | None = None,
        action_service: Any | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.mail_service = mail_service
        self.settings = settings
        self.rules = rules
        self.analysis_service = analysis_service
        self.action_service = action_service
        self.folders: tuple[FolderInfo, ...] = ()
        self._folder_item_by_name: dict[str, FolderListItem] = {}
        self._review_item: FolderListItem | None = None
        self._rows: list[tuple[str, MailSummary]] = []
        self._selected_folder: str | None = None
        self._loading_folder: str | None = None
        self._detail: MessageDetail | None = None
        self._analysis: MessageAnalysis | None = None
        self._folder_generation = 0
        self._message_generation = 0
        self._classification_generation = 0
        self._action_running = False
        self._activity: list[str] = []
        self._active_pane = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="workspace"):
            with Vertical(id="folder-pane", classes="pane"):
                yield Static("Folders and smart views", markup=False)
                yield ListView(id="folders")
            with Vertical(id="message-pane", classes="pane"):
                yield Static("Messages", markup=False)
                yield DataTable(id="messages", cursor_type="row")
            with Vertical(id="detail-pane", classes="pane"):
                yield Static("Select a message to read its text content.", id="message-detail", markup=False)
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
            folder_pane.styles.width, folder_pane.styles.height = "1fr", 8
            message_pane.styles.width, message_pane.styles.height = "1fr", "1fr"
            detail_pane.styles.width, detail_pane.styles.height = "1fr", "2fr"
            self.query_one("#analysis").styles.height = 8
            self.query_one("#activity").styles.height = 5
        else:
            workspace.styles.layout = "horizontal"
            folder_pane.styles.width, folder_pane.styles.height = "24%", "1fr"
            message_pane.styles.width, message_pane.styles.height = "38%", "1fr"
            detail_pane.styles.width, detail_pane.styles.height = "38%", "1fr"
            self.query_one("#analysis").styles.height = 12
            self.query_one("#activity").styles.height = 8

    def on_mount(self) -> None:
        self.query_one("#messages", DataTable).add_columns("Folder", "State", "UID", "From", "Subject", "Date", "Size")
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
            self._set_status(f"Could not start: {type(exc).__name__}")
            self.query_one("#message-detail", Static).update(
                "imapledger could not connect. No mailbox changes were made.\n\n"
                f"{type(exc).__name__}. Press r to retry or q to quit."
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
        self._selected_folder = folder
        self._loading_folder = folder
        self._detail = None
        self._analysis = None
        self._rows = []
        self.query_one("#messages", DataTable).clear()
        self.query_one("#message-detail", Static).update(f"Loading {folder}...")
        self.query_one("#analysis", Static).update("Analysis will not run until a message is opened.")
        self._set_status(f"Loading {folder} page...")
        return self._folder_generation

    async def _select_folder(self, folder: str, generation: int | None = None) -> None:
        if generation is None:
            generation = self._begin_folder_load(folder)
        try:
            if folder == "Review":
                rows = await asyncio.to_thread(self.mail_service.review_messages, limit=50, offset=0)
                page_rows = tuple(rows)
            else:
                page = await asyncio.to_thread(self.mail_service.list_messages, folder, limit=50, offset=0)
                page_rows = tuple((folder, item) for item in page.items)
            if generation != self._folder_generation:
                return
            self._populate_rows(page_rows)
            self._loading_folder = None
            self._set_status(f"{folder}: {len(page_rows)} messages loaded.")
        except Exception as exc:
            if generation == self._folder_generation:
                self._loading_folder = None
                self._rows = []
                self.query_one("#messages", DataTable).clear()
                self.query_one("#message-detail", Static).update(
                    f"Could not load {folder} ({type(exc).__name__}). Press r to retry."
                )
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
        self._classification_generation += 1
        generation = self._message_generation
        self._selected_folder = folder
        self.query_one("#message-detail", Static).update("Opening message with BODY.PEEK…")
        try:
            detail = await asyncio.to_thread(self.mail_service.get_message, folder, uid)
            if generation != self._message_generation:
                return
            self._detail = detail
            self._analysis = None
            message = detail.item.message
            if message is None:
                raise RuntimeError(detail.item.skip_reason or "message is unavailable")
            state = detail.persisted_state.outcome if detail.persisted_state else None
            self.query_one("#message-detail", Static).update(self._render_message(folder, message, detail, state))
            if state is not None and self.analysis_service is not None:
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
                self.query_one("#message-detail", Static).update(f"Message could not be opened ({type(exc).__name__}).")

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

    def _render_analysis(self, analysis: MessageAnalysis) -> None:
        action = analysis.configured_action
        action_label = action.action.value.upper() if action else "unavailable"
        if action is not None and action.destination:
            action_label += f" to {action.destination}"
        persisted = analysis.persisted_outcome.value.upper() if analysis.persisted_outcome else "none"
        lines = ["Analysis", f"Persisted state: {persisted}"]
        if analysis.decision_source == "persisted-state":
            lines.append("Classifier: not run (stored state)")
        elif analysis.rule_id:
            lines.extend((f"Rule: {analysis.rule_id}", "Classifier: not run (deterministic rule)"))
        elif analysis.verdict is not None:
            lines.append(f"Outcome: {analysis.outcome.value.upper() if analysis.outcome else '-'}")
            lines.append(f"Verdict: {analysis.verdict.name}")
            if analysis.signals is not None:
                lines.append(
                    "Signals: "
                    f"bulk {analysis.signals.unsolicited_bulk:.2f}, phishing {analysis.signals.phishing_or_scam:.2f}, "
                    f"identity {analysis.signals.identity_deception:.2f}, "
                    f"legitimate {analysis.signals.legitimate_expected:.2f}, "
                    f"delete {analysis.signals.delete_safe:.2f}"
                )
            lines.append(f"Reasons: {', '.join(analysis.reasons) or '-'}")
        else:
            lines.append("Classifier: not run")
        lines.append(f"Configured action: {action_label}")
        if self._selected_folder not in (self.settings.spam.folders if self.settings else ()):
            lines.append("Automation unavailable: this folder is not configured in spam.folders.")
        self.query_one("#analysis", Static).update("\n".join(lines))

    def action_classify(self) -> None:
        self.run_worker(self._classify(reclassify=False), group="classification", exclusive=True, exit_on_error=False)

    def action_reclassify(self) -> None:
        self.run_worker(self._classify(reclassify=True), group="classification", exclusive=True, exit_on_error=False)

    async def _classify(self, *, reclassify: bool) -> None:
        detail = self._detail
        if detail is None or detail.item.message is None or self.analysis_service is None:
            self._set_status("Select a message first.")
            return
        self._set_status("Classifying in a background thread…")
        started = time.monotonic()
        self._classification_generation += 1
        generation = self._classification_generation
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
            self._render_analysis(analysis)
            _LOG.debug("ui.classify duration_ms=%.1f result_count=1", (time.monotonic() - started) * 1000)
            outcome = analysis.outcome.value.upper() if analysis.outcome else "RULE"
            self._set_status(f"Classification complete: {outcome}.")
        except Exception as exc:
            self._set_status(f"Classification failed: {type(exc).__name__}")

    def action_apply(self) -> None:
        analysis = self._analysis
        if self._action_running:
            self._set_status("An action is already running.")
            return
        if analysis is None or analysis.configured_action is None:
            self._set_status("Classify the selected message before applying an action.")
            return
        if self.settings is None or analysis.folder not in self.settings.spam.folders:
            self._set_status("Automation unavailable: folder is not configured in spam.folders.")
            return
        self.push_screen(ApplyConfirmation(analysis), self._confirmed_action)

    def _confirmed_action(self, confirmed: bool) -> None:
        if confirmed and not self._action_running:
            self._action_running = True
            self.run_worker(self._apply_confirmed(True), group="action", exit_on_error=False)

    async def _apply_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        analysis = self._analysis
        detail = self._detail
        if analysis is None or detail is None or self.action_service is None:
            return
        self._set_status("Applying configured action in a background thread…")
        started = time.monotonic()
        try:
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
                        self.query_one("#message-detail", Static).update("Select a message to read its text content.")
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
                            if self._selected_folder == "Review" and analysis.outcome is not SpamOutcome.REVIEW:
                                continue
                            summary = replace(summary, persisted_state=analysis.outcome)
                        rows.append((row_folder, summary))
                    self._populate_rows(tuple(rows))
        except Exception as exc:
            self._set_status(f"Action failed: {type(exc).__name__}")
        finally:
            self._action_running = False

    def action_refresh(self) -> None:
        self._set_status("Refreshing folders and current page…")
        self.run_worker(self._refresh(), group="startup-folders", exclusive=True, exit_on_error=False)

    async def _refresh(self) -> None:
        try:
            self.folders = await asyncio.to_thread(self.mail_service.list_folders, include_counts=False)
            self._render_folders()
            if self._selected_folder is not None:
                await self._select_folder(self._selected_folder)
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

    def action_next_pane(self) -> None:
        widgets = [self.query_one("#folders"), self.query_one("#messages"), self.query_one("#message-detail")]
        self._active_pane = (self._active_pane + 1) % len(widgets)
        widgets[self._active_pane].focus()

    def action_help(self) -> None:
        self._set_status(
            "Keys: arrows/Enter select, c classify, C reclassify, a apply, r refresh, Tab switch pane, q quit."
        )

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def on_unmount(self) -> None:
        if self.mail_service is not None:
            self.mail_service.close()
        if self.action_service is not None and hasattr(self.action_service, "close"):
            self.action_service.close()


def run(config: Path) -> None:
    import sys

    password = ""
    mail_service = None
    action_service = None
    try:
        settings = load_settings(config)
        rules = load_rules(rules_path_for_config(config), source_folders=settings.spam.folders)
        password = resolve_credential(settings.imap).password
        mail_service = MailService(settings, password)
        analysis_service = AnalysisService(settings, rules)
        action_service = ActionService(settings, password, rules)
        MailReviewApp(
            config,
            mail_service=mail_service,
            settings=settings,
            rules=rules,
            analysis_service=analysis_service,
            action_service=action_service,
        ).run()
    except Exception as exc:
        print(f"imapledger could not start: {type(exc).__name__}", file=sys.stderr)
        raise
    finally:
        if mail_service is not None:
            mail_service.close()
        if action_service is not None:
            action_service.close()
        password = ""
