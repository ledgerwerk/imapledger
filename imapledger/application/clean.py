from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..mailbox import MailboxError, ProcessingMailbox
from ..processing_engine import ProcessedMessage, ProcessingEngine, ProcessingReport
from ..progress_store import ProgressRun, ProgressStore, SortDirection, default_progress_path
from ..routing_models import RoutingModelError, RuleSet


@dataclass(frozen=True, slots=True)
class CleanRequest:
    folder: str
    apply: bool = False
    limit: int | None = None
    sort: SortDirection = "oldest"
    rule_scope: str | None = None
    new_run: bool = False
    retry_errors: bool = False
    progress_db: Path = field(default_factory=default_progress_path)

    def __post_init__(self) -> None:
        if not isinstance(self.folder, str) or not self.folder.strip():
            raise ValueError("source folder must be a non-empty string")
        if self.folder != self.folder.strip():
            raise ValueError("source folder must not have leading or trailing whitespace")
        if not isinstance(self.apply, bool):
            raise ValueError("apply must be a boolean")
            raise ValueError("message limit must be a positive integer")
        if self.sort not in {"oldest", "newest"}:
            raise ValueError("sort direction must be oldest or newest")
        if self.new_run and self.retry_errors:
            raise ValueError("--new-run cannot be combined with --retry-errors")
        if self.retry_errors and not self.apply:
            raise ValueError("--retry-errors requires --apply")
        if not isinstance(self.progress_db, Path):
            object.__setattr__(self, "progress_db", Path(self.progress_db))


@dataclass(frozen=True, slots=True)
class CleanPreflight:
    folder: str
    mode: str
    destinations: tuple[str, ...]
    rule_scope: str | None


@dataclass(frozen=True, slots=True)
class CleanResult:
    report: ProcessingReport
    touched_folders: tuple[str, ...]


class CleanOperation:
    """Run the shared modern, folder-scoped routing clean use case."""

    def __init__(
        self,
        settings: Settings,
        rules: RuleSet,
        *,
        mailbox_factory: Callable[..., ProcessingMailbox] = ProcessingMailbox,
        progress_store_factory: Callable[[Path], ProgressStore] = ProgressStore,
    ) -> None:
        self._settings = settings
        self._rules = rules
        self._mailbox_factory = mailbox_factory
        self._progress_store_factory = progress_store_factory

    def preflight(self, request: CleanRequest) -> CleanPreflight:
        config_store_folder = self._settings.config_store.folder if self._settings.config_store is not None else None
        try:
            self._rules.validate_destinations(request.folder, config_store_folder=config_store_folder)
        except RoutingModelError as exc:
            raise ValueError(str(exc)) from exc

        selected_rules = self._rules.enabled_rules(request.folder)
        if request.rule_scope is not None:
            selected_rules = tuple(rule for rule in selected_rules if rule.id == request.rule_scope)
            if not selected_rules:
                raise ValueError(f"enabled rule not found for source {request.folder}: {request.rule_scope}")
        elif self._rules.fallback_destination is None:
            raise ValueError("full routing requires rules.fallback_destination")

        destinations = [rule.destination for rule in selected_rules]
        if request.rule_scope is None and self._rules.fallback_destination is not None:
            destinations.append(self._rules.fallback_destination)
        return CleanPreflight(
            folder=request.folder,
            mode="single-rule" if request.rule_scope is not None else "full",
            destinations=tuple(dict.fromkeys(destinations)),
            rule_scope=request.rule_scope,
        )

    def run(
        self,
        request: CleanRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
        on_result: Callable[[ProcessedMessage, ProgressRun], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> CleanResult:
        preflight = self.preflight(request)
        store = self._progress_store_factory(request.progress_db)
        try:
            with self._mailbox_factory(
                host=self._settings.imap.host,
                port=self._settings.imap.port,
                username=self._settings.imap.username,
                password=password,
                folder=request.folder,
                writable=request.apply,
                allowed_destinations=preflight.destinations,
                max_message_bytes=self._settings.spam.max_message_bytes,
                max_body_chars=self._settings.spam.max_body_chars,
                event_callback=event_callback,
            ) as mailbox:
                report = ProcessingEngine(
                    settings=self._settings,
                    rules=self._rules,
                    progress_store=store,
                ).run(
                    mailbox,
                    apply=request.apply,
                    limit=request.limit,
                    rule_scope=request.rule_scope,
                    sort_direction=request.sort,
                    new_run=request.new_run,
                    retry_errors=request.retry_errors,
                    on_result=on_result,
                    should_stop=should_stop,
                )
        except MailboxError:
            raise

        touched_folders: tuple[str, ...] = ()
        if request.apply:
            touched = [request.folder]
            touched.extend(
                message.destination
                for message in report.messages
                if message.confirmed and message.destination is not None and message.destination not in touched
            )
            touched_folders = tuple(touched)
        return CleanResult(report=report, touched_folders=touched_folders)
