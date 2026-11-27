from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..mailbox import FolderInfo, ProcessingMailbox
from ..message import MailMessage
from ..processing_engine import ProcessedMessage
from ..progress_store import ProgressRun, ProgressStore, SortDirection, default_progress_path
from ..routing_action_service import RoutingActionReceipt, RoutingActionService
from ..routing_analysis_service import RoutingAnalysisService
from ..routing_models import RoutingPlan, RuleSet
from .clean import CleanOperation, CleanPreflight, CleanRequest, CleanResult


@dataclass(frozen=True, slots=True)
class RuleRunRequest:
    folders: tuple[str, ...]
    apply: bool = False
    limit: int | None = None
    sort: SortDirection = "oldest"
    rule_scope: str | None = None
    new_run: bool = False
    retry_errors: bool = False
    progress_db: Path = field(default_factory=default_progress_path)

    def __post_init__(self) -> None:
        if not isinstance(self.folders, (tuple, list)) or not self.folders:
            raise ValueError("at least one source folder is required")
        folders = tuple(self.folders)
        if any(not isinstance(folder, str) or not folder.strip() or folder != folder.strip() for folder in folders):
            raise ValueError("source folders must be non-empty names without surrounding whitespace")
        if len(set(folders)) != len(folders):
            raise ValueError("source folders must not contain duplicates")
        object.__setattr__(self, "folders", folders)
        if not isinstance(self.apply, bool):
            raise ValueError("apply must be a boolean")
        if self.limit is not None and (
            isinstance(self.limit, bool) or not isinstance(self.limit, int) or self.limit < 1
        ):
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
class RuleRunPreflight:
    folders: tuple[CleanPreflight, ...]

    @property
    def destinations(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(destination for folder in self.folders for destination in folder.destinations))


@dataclass(frozen=True, slots=True)
class RuleRunResult:
    results: tuple[tuple[str, CleanResult], ...]

    @property
    def touched_folders(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(folder for _, result in self.results for folder in result.touched_folders))

    @property
    def messages(self) -> tuple[tuple[str, ProcessedMessage], ...]:
        return tuple((folder, message) for folder, result in self.results for message in result.report.messages)

    @property
    def progress(self) -> tuple[tuple[str, ProgressRun], ...]:
        return tuple((folder, result.report.run) for folder, result in self.results)


class RuleRunOperation:
    """Coordinate rule preview or apply across one or more mail folders."""

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
        self._single_folder = CleanOperation(
            settings,
            rules,
            mailbox_factory=mailbox_factory,
            progress_store_factory=progress_store_factory,
        )

    def selectable_folders(self, folders: tuple[FolderInfo, ...]) -> tuple[str, ...]:
        config_store = self._settings.config_store.folder if self._settings.config_store is not None else None
        return tuple(folder.name for folder in folders if folder.selectable and folder.name != config_store)

    def preflight(self, request: RuleRunRequest) -> RuleRunPreflight:
        config_store = self._settings.config_store.folder if self._settings.config_store is not None else None
        if config_store is not None and config_store in request.folders:
            raise ValueError("Config Ledger folder cannot be used as a rule source")
        return RuleRunPreflight(
            tuple(
                self._single_folder.preflight(
                    CleanRequest(
                        folder=folder,
                        apply=request.apply,
                        limit=request.limit,
                        sort=request.sort,
                        rule_scope=request.rule_scope,
                        new_run=request.new_run,
                        retry_errors=request.retry_errors,
                        progress_db=request.progress_db,
                    )
                )
                for folder in request.folders
            )
        )

    def run(
        self,
        request: RuleRunRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
        on_result: Callable[[str, ProcessedMessage, ProgressRun], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RuleRunResult:
        self.preflight(request)
        results: list[tuple[str, CleanResult]] = []
        for folder in request.folders:
            if should_stop is not None and should_stop():
                break

            def folder_result(message: ProcessedMessage, progress: ProgressRun, current_folder: str = folder) -> None:
                if on_result is not None:
                    on_result(current_folder, message, progress)

            result = self._single_folder.run(
                CleanRequest(
                    folder=folder,
                    apply=request.apply,
                    limit=request.limit,
                    sort=request.sort,
                    rule_scope=request.rule_scope,
                    new_run=request.new_run,
                    retry_errors=request.retry_errors,
                    progress_db=request.progress_db,
                ),
                password=password,
                event_callback=event_callback,
                on_result=folder_result,
                should_stop=should_stop,
            )
            results.append((folder, result))
        return RuleRunResult(tuple(results))


class RuleEvaluationOperation:
    """Evaluate the ordered rules for one exact selected message without mutation."""

    def __init__(self, settings: Settings, rules: RuleSet, *, config: Path | None = None) -> None:
        self._service = RoutingAnalysisService(settings, rules, config=config)

    def set_rules(self, rules: RuleSet) -> None:
        self._service.set_rules(rules)

    def set_settings(self, settings: Settings) -> None:
        self._service.set_settings(settings)

    def evaluate(self, folder: str, message: MailMessage, *, rule_scope: str | None = None) -> RoutingPlan:
        return self._service.analyze(folder, message, rule_scope=rule_scope)


class RuleApplyMessageOperation:
    """Apply a confirmed current evaluation to the exact message UID it names."""

    def __init__(self, service: RoutingActionService) -> None:
        self._service = service

    def apply(self, plan: RoutingPlan, *, uidvalidity: int, confirmed_by_user: bool) -> RoutingActionReceipt:
        return self._service.apply(plan, uidvalidity=uidvalidity, confirmed_by_user=confirmed_by_user)

    def set_rules(self, rules: RuleSet) -> None:
        self._service.set_rules(rules)

    def set_settings(self, settings: Settings) -> None:
        self._service.set_settings(settings)

    def close(self) -> None:
        self._service.close()
