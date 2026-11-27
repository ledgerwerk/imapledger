from __future__ import annotations

from pathlib import Path

from .config import Settings
from .evidence import MailboxContext
from .message import MailMessage
from .routing_evaluator import SemanticRoutingEvaluator
from .routing_models import RoutingPlan, RuleSet


class RoutingAnalysisService:
    is_routing = True

    def __init__(self, settings: Settings, rules: RuleSet, *, config: Path | None = None) -> None:
        self._settings = settings
        self._rules = rules
        self._config = config

    def set_rules(self, rules: RuleSet) -> None:
        self._rules = rules

    def set_settings(self, settings: Settings) -> None:
        self._settings = settings

    def analyze(
        self,
        folder: str,
        message: MailMessage,
        *,
        rule_scope: str | None = None,
        **_: object,
    ) -> RoutingPlan:
        settings = self._settings
        evaluator = SemanticRoutingEvaluator(
            config=self._config,
            context=MailboxContext(source_folder=folder),
            config_store_folder=settings.config_store.folder if settings.config_store is not None else None,
        )
        with evaluator:
            return evaluator.plan(folder, message, self._rules, rule_scope=rule_scope)
