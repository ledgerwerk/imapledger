from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..classification_state import ClassificationStateBackend, all_state_keywords
from ..classifier import PyJevSpamClassifier
from ..cleaner import CleanReport, MessageResult, SpamCleaner
from ..config import ActionKind, ConfigError, Settings
from ..mailbox import MailboxError, MessageSelection, MessageSort, ScopedMailbox
from ..preflight import SourcePreflightResult, preflight_source
from ..rules import RuleSet


@dataclass(frozen=True, slots=True)
class LegacyCleanRequest:
    apply: bool = False
    limit: int | None = None
    offset: int = 0
    sort: MessageSort = MessageSort.NEWEST
    reclassify: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.apply, bool) or not isinstance(self.reclassify, bool):
            raise ValueError("apply and reclassify must be booleans")
        if self.limit is not None and (
            not isinstance(self.limit, int) or isinstance(self.limit, bool) or self.limit <= 0
        ):
            raise ValueError("message limit must be a positive integer")
        if not isinstance(self.offset, int) or isinstance(self.offset, bool) or self.offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if not isinstance(self.sort, MessageSort):
            raise ValueError("sort must be a MessageSort")


@dataclass(frozen=True, slots=True)
class LegacyCleanResult:
    reports: tuple[CleanReport, ...]
    preflight_results: tuple[SourcePreflightResult, ...]
    preflight_failed: bool
    failure: Exception | None = None


class LegacyCleanOperation:
    """Run the deprecated category-based clean workflow over configured spam folders."""

    def __init__(
        self,
        settings: Settings,
        rules: RuleSet,
        *,
        mailbox_factory: Callable[..., Any] | None = None,
        classifier_factory: Callable[..., Any] | None = None,
        preflight: Callable[..., SourcePreflightResult] | None = None,
    ) -> None:
        self._settings = settings
        self._rules = rules
        self._mailbox_factory = mailbox_factory or ScopedMailbox
        self._classifier_factory = classifier_factory or PyJevSpamClassifier
        self._preflight = preflight or preflight_source

    def validate_config(self) -> None:
        folders = self._settings.spam.folders
        if not folders:
            raise ConfigError("bare `clean` requires spam.folders; use `clean FOLDER` for an explicit routing source")
        store = self._settings.config_store
        if store is None:
            return
        destinations = self._move_destinations()
        if store.folder in folders:
            raise ConfigError("config-store folder must not be a spam source folder")
        if store.folder in destinations:
            raise ConfigError("config-store folder must not be a cleaning move destination")

    def preflight(
        self,
        request: LegacyCleanRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> tuple[SourcePreflightResult, ...]:
        self.validate_config()
        if not request.apply:
            return ()
        requires_delete = any(
            action.action is ActionKind.DELETE
            for action in (
                self._settings.spam.actions.spam,
                self._settings.spam.actions.not_spam,
                self._settings.spam.actions.review,
            )
        )
        requires_state_persistence = (
            self._settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS
            and any(
                action.action is ActionKind.KEEP
                for action in (
                    self._settings.spam.actions.spam,
                    self._settings.spam.actions.not_spam,
                    self._settings.spam.actions.review,
                )
            )
        )
        return tuple(
            self._preflight(
                self._settings,
                folder,
                password=password,
                destinations=self._move_destinations(),
                requires_delete=requires_delete,
                require_state_persistence=requires_state_persistence,
                deep_probe=False,
                mailbox_factory=self._mailbox_factory,
                event_callback=event_callback,
            )
            for folder in self._settings.spam.folders
        )

    def run(
        self,
        request: LegacyCleanRequest,
        *,
        password: str,
        event_callback: Callable[[str], None] | None = None,
        on_folder_start: Callable[[str, int, int, int | None, MessageSelection], None] | None = None,
        on_result: Callable[[str, MessageResult, int, int], None] | None = None,
    ) -> LegacyCleanResult:
        preflights = self.preflight(request, password=password, event_callback=event_callback)
        preflight_failed = request.apply and any(not result.ok for result in preflights)
        if preflight_failed:
            return LegacyCleanResult((), preflights, True)

        excluded_keywords = (
            all_state_keywords()
            if self._settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS and not request.reclassify
            else ()
        )
        selection = MessageSelection(
            limit=request.limit,
            offset=request.offset,
            sort=request.sort,
            excluded_keywords=excluded_keywords,
        )
        destinations = self._move_destinations()
        allow_delete = any(
            action.action is ActionKind.DELETE
            for action in (
                self._settings.spam.actions.spam,
                self._settings.spam.actions.not_spam,
                self._settings.spam.actions.review,
            )
        )
        requires_state_persistence = (
            self._settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS
            and any(
                action.action is ActionKind.KEEP
                for action in (
                    self._settings.spam.actions.spam,
                    self._settings.spam.actions.not_spam,
                    self._settings.spam.actions.review,
                )
            )
        )
        reports: list[CleanReport] = []
        failure: Exception | None = None
        try:
            with self._classifier_factory(
                trusted_authserv_ids=self._settings.spam.trusted_authserv_ids,
                trusted_provider_headers=self._settings.spam.trusted_provider_headers,
            ) as classifier:
                for folder in self._settings.spam.folders:
                    report: CleanReport | None = None
                    try:
                        with self._mailbox_factory(
                            host=self._settings.imap.host,
                            port=self._settings.imap.port,
                            username=self._settings.imap.username,
                            password=password,
                            folder=folder,
                            writable=request.apply,
                            allowed_destinations=destinations,
                            allow_delete=allow_delete,
                            max_message_bytes=self._settings.spam.max_message_bytes,
                            max_body_chars=self._settings.spam.max_body_chars,
                            event_callback=event_callback,
                        ) as mailbox:
                            if request.apply and requires_state_persistence:
                                mailbox.require_persistent_classification_state()
                            if request.apply:
                                for destination in destinations:
                                    if not mailbox.destination_exists(destination):
                                        raise MailboxError(f"configured move destination does not exist: {destination}")
                            snapshot = mailbox.snapshot()
                            unclassified_count = (
                                len(mailbox.candidate_uids(excluded_keywords=selection.excluded_keywords))
                                if selection.excluded_keywords
                                else None
                            )
                            if on_folder_start is not None:
                                on_folder_start(
                                    mailbox.folder,
                                    len(snapshot.uids),
                                    mailbox.selected_count(selection),
                                    unclassified_count,
                                    selection,
                                )
                            report = SpamCleaner(
                                mailbox,
                                classifier,
                                policy=self._settings.spam.policy,
                                actions=self._settings.spam.actions,
                                rules=self._rules,
                                state_backend=self._settings.spam.state.backend,
                            ).run(
                                apply=request.apply,
                                reclassify=request.reclassify,
                                selection=selection,
                                on_result=(
                                    lambda row, position, total, source_folder=mailbox.folder: on_result(
                                        source_folder, row, position, total
                                    )
                                )
                                if on_result is not None
                                else None,
                            )
                            reports.append(report)
                    except Exception as exc:
                        failure = exc
                        break
                    if report is not None and report.mutation_error is not None:
                        failure = report.mutation_error
                        break
        except Exception as exc:
            failure = exc
        return LegacyCleanResult(tuple(reports), preflights, False, failure)

    def _move_destinations(self) -> tuple[str, ...]:
        destinations = [
            action.destination
            for action in (
                self._settings.spam.actions.spam,
                self._settings.spam.actions.not_spam,
                self._settings.spam.actions.review,
            )
            if action.action is ActionKind.MOVE and action.destination is not None
        ]
        destinations.extend(self._rules.move_destinations())
        return tuple(dict.fromkeys(destinations))
