from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from .rules import RuleMatch

RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


class RoutingModelError(ValueError):
    """Invalid routing-domain data."""


class RuleType(str, Enum):
    SPAM = "spam"
    SEMANTIC = "semantic"
    HEADER = "header"


class EvaluationState(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RoutingRule:
    id: str
    enabled: bool
    type: RuleType
    destination: str
    description: str | None = None
    match_at: float | None = None
    match: RuleMatch | None = None
    source_folders: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or RULE_ID_PATTERN.fullmatch(self.id) is None:
            raise RoutingModelError("rule id must match [a-z0-9][a-z0-9-]{0,63}")
        if not isinstance(self.enabled, bool):
            raise RoutingModelError("rule enabled must be a boolean")
        try:
            rule_type = RuleType(self.type)
        except (TypeError, ValueError) as exc:
            raise RoutingModelError("rule type must be spam, semantic, or header") from exc
        object.__setattr__(self, "type", rule_type)
        if not isinstance(self.destination, str) or not self.destination.strip():
            raise RoutingModelError("rule destination must be a non-empty folder name")
        if self.destination != self.destination.strip():
            raise RoutingModelError("rule destination must not have leading or trailing whitespace")
        if self.description is not None and (not isinstance(self.description, str) or not self.description.strip()):
            raise RoutingModelError("rule description must be a non-empty string")
        if rule_type is RuleType.SEMANTIC and self.description is None:
            raise RoutingModelError("semantic rule requires a description")
        if self.match_at is not None:
            if isinstance(self.match_at, bool) or not isinstance(self.match_at, (float, int)):
                raise RoutingModelError("rule match_at must be a probability")
            if not math.isfinite(self.match_at) or not 0 <= self.match_at <= 1:
                raise RoutingModelError("rule match_at must be between 0 and 1")
            object.__setattr__(self, "match_at", float(self.match_at))
        if rule_type is not RuleType.SEMANTIC and self.match_at is not None:
            raise RoutingModelError("match_at is only valid for semantic rules")
        if rule_type is RuleType.HEADER:
            if not isinstance(self.match, RuleMatch):
                raise RoutingModelError("header rule requires a header match")
        elif self.match is not None:
            raise RoutingModelError("match is only valid for header rules")
        if not isinstance(self.source_folders, (tuple, list)):
            raise RoutingModelError("source_folders must be a sequence")
        folders = tuple(self.source_folders)
        if any(not isinstance(folder, str) or not folder.strip() or folder != folder.strip() for folder in folders):
            raise RoutingModelError(
                "source_folders entries must be non-empty folder names without surrounding whitespace"
            )
        if len(set(folders)) != len(folders):
            raise RoutingModelError("source_folders must not contain duplicates")
        object.__setattr__(self, "source_folders", folders)

    def applies_to_source(self, folder: str) -> bool:
        return not self.source_folders or folder in self.source_folders


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[RoutingRule, ...] = ()
    fallback_destination: str | None = None
    default_match_at: float = 0.90

    def __post_init__(self) -> None:
        if not isinstance(self.rules, (tuple, list)):
            raise RoutingModelError("rules must be a sequence")
        rules = tuple(self.rules)
        if any(not isinstance(rule, RoutingRule) for rule in rules):
            raise RoutingModelError("rules entries must be RoutingRule values")
        rule_ids = [rule.id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise RoutingModelError("duplicate rule id")
        object.__setattr__(self, "rules", rules)
        if self.fallback_destination is not None:
            if not isinstance(self.fallback_destination, str) or not self.fallback_destination.strip():
                raise RoutingModelError("fallback_destination must be a non-empty folder name")
            if self.fallback_destination != self.fallback_destination.strip():
                raise RoutingModelError("fallback_destination must not have surrounding whitespace")
        if isinstance(self.default_match_at, bool) or not isinstance(self.default_match_at, (float, int)):
            raise RoutingModelError("default_match_at must be a probability")
        if not math.isfinite(self.default_match_at) or not 0 <= self.default_match_at <= 1:
            raise RoutingModelError("default_match_at must be between 0 and 1")
        object.__setattr__(self, "default_match_at", float(self.default_match_at))

    def enabled_rules(self, folder: str | None = None) -> tuple[RoutingRule, ...]:
        return tuple(rule for rule in self.rules if rule.enabled and (folder is None or rule.applies_to_source(folder)))

    def move_destinations(self) -> tuple[str, ...]:
        destinations = [rule.destination for rule in self.enabled_rules()]
        if self.fallback_destination is not None:
            destinations.append(self.fallback_destination)
        return tuple(dict.fromkeys(destinations))

    def validate_destinations(self, source_folder: str, *, config_store_folder: str | None = None) -> None:
        if config_store_folder is not None and source_folder == config_store_folder:
            raise RoutingModelError("config-store folder cannot be used as a source")
        for rule in self.enabled_rules(source_folder):
            if rule.destination == source_folder:
                raise RoutingModelError(f"rule {rule.id} destination must not equal the source folder")
            if config_store_folder is not None and rule.destination == config_store_folder:
                raise RoutingModelError("config-store folder cannot be a routing destination")
        if self.fallback_destination == source_folder:
            raise RoutingModelError("fallback destination must not equal the source folder")
        if config_store_folder is not None and self.fallback_destination == config_store_folder:
            raise RoutingModelError("config-store folder cannot be a routing destination")


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rule_id: str
    state: EvaluationState
    confidence: float | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or RULE_ID_PATTERN.fullmatch(self.rule_id) is None:
            raise RoutingModelError("evaluation rule_id is invalid")
        try:
            state = EvaluationState(self.state)
        except (TypeError, ValueError) as exc:
            raise RoutingModelError("evaluation state must be match, no_match, or error") from exc
        object.__setattr__(self, "state", state)
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (float, int)):
                raise RoutingModelError("evaluation confidence must be a probability")
            if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
                raise RoutingModelError("evaluation confidence must be between 0 and 1")
            object.__setattr__(self, "confidence", float(self.confidence))
        if self.detail is not None and not isinstance(self.detail, str):
            raise RoutingModelError("evaluation detail must be a string")


@dataclass(frozen=True, slots=True)
class RoutingPlan:
    folder: str
    uid: int
    rule_results: tuple[RuleEvaluation, ...]
    winner_rule_id: str | None
    destination: str | None
    mode: Literal["full", "single-rule"]
    rules_fingerprint: str
    model: str | None = None
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class RoutingReceipt:
    plan: RoutingPlan
    applied: bool
    confirmed: bool
    detail: str | None = None
