from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from .routing_actions import RuleAction
from .rules import RuleMatch

RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


class RoutingModelError(ValueError):
    """Invalid routing-domain data."""


class RuleType(str, Enum):
    SEMANTIC = "semantic"
    HEADER = "header"
    RECIPE = "recipe"


class EvaluationState(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"


class RoutingAction(str, Enum):
    MOVE = "move"
    DELETE = "delete"
    KEEP_IN_PLACE = "keep_in_place"
    ALREADY_THERE = "already_there"
    DELETED = "deleted"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RoutingRule:
    id: str
    enabled: bool
    type: RuleType
    destination: str | None = None
    description: str | None = None
    match_at: float | None = None
    match: RuleMatch | None = None
    source_folders: tuple[str, ...] = ()
    match_any: tuple[RuleMatch, ...] = ()
    action: RuleAction = RuleAction.MOVE
    recipe: str | None = None
    options: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or RULE_ID_PATTERN.fullmatch(self.id) is None:
            raise RoutingModelError("rule id must match [a-z0-9][a-z0-9-]{0,63}")
        if not isinstance(self.enabled, bool):
            raise RoutingModelError("rule enabled must be a boolean")
        try:
            rule_type = RuleType(self.type)
        except (TypeError, ValueError) as exc:
            raise RoutingModelError("rule type must be semantic, header, or recipe") from exc
        object.__setattr__(self, "type", rule_type)
        try:
            action = RuleAction(self.action)
        except (TypeError, ValueError) as exc:
            raise RoutingModelError("rule action must be move, delete, or keep") from exc
        object.__setattr__(self, "action", action)
        if action is RuleAction.MOVE:
            if not isinstance(self.destination, str) or not self.destination.strip():
                raise RoutingModelError("move action requires a non-empty destination")
            if self.destination != self.destination.strip():
                raise RoutingModelError("rule destination must not have leading or trailing whitespace")
        elif self.destination is not None:
            raise RoutingModelError(f"{action.value} action must not have a destination")
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
        if not isinstance(self.match_any, (tuple, list)):
            raise RoutingModelError("match_any must be a sequence")
        matchers = tuple(self.match_any)
        if any(not isinstance(matcher, RuleMatch) for matcher in matchers):
            raise RoutingModelError("match_any entries must be RuleMatch values")
        if self.match is not None and not isinstance(self.match, RuleMatch):
            raise RoutingModelError("match must be a RuleMatch")
        if self.match is not None:
            if matchers and self.match != matchers[0]:
                raise RoutingModelError("match conflicts with the first match_any entry")
            if not matchers:
                matchers = (self.match,)
        if rule_type is RuleType.HEADER and not matchers:
            raise RoutingModelError("header rule requires at least one matcher")
        if len(set(matchers)) != len(matchers):
            raise RoutingModelError("match_any must not contain duplicates")
        object.__setattr__(self, "match_any", matchers)
        object.__setattr__(self, "match", matchers[0] if len(matchers) == 1 else None)
        if rule_type is RuleType.RECIPE:
            if not isinstance(self.recipe, str) or RULE_ID_PATTERN.fullmatch(self.recipe) is None:
                raise RoutingModelError("recipe rule requires a valid recipe ID")
            if not isinstance(self.options, Mapping):
                raise RoutingModelError("recipe options must be a table")
            object.__setattr__(self, "options", dict(self.options))
        elif self.recipe is not None:
            raise RoutingModelError("recipe is only valid for recipe rules")
        elif self.options:
            raise RoutingModelError("options are only valid for recipe rules")
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
class RuleEvidenceSettings:
    trusted_authserv_ids: tuple[str, ...] = ()
    trusted_provider_headers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("trusted_authserv_ids", "trusted_provider_headers"):
            values = getattr(self, field_name)
            if not isinstance(values, (tuple, list)):
                raise RoutingModelError(f"{field_name} must be a sequence")
            values = tuple(values)
            if any(not isinstance(value, str) or not value.strip() or value != value.strip() for value in values):
                raise RoutingModelError(
                    f"{field_name} entries must be non-empty strings without surrounding whitespace"
                )
            if len(set(values)) != len(values):
                raise RoutingModelError(f"{field_name} must not contain duplicates")
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[RoutingRule, ...] = ()
    fallback_destination: str | None = None
    default_match_at: float = 0.90
    evidence: RuleEvidenceSettings = field(default_factory=RuleEvidenceSettings)

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
        if not isinstance(self.evidence, RuleEvidenceSettings):
            raise RoutingModelError("evidence must be rule evidence settings")

    def enabled_rules(self, folder: str | None = None) -> tuple[RoutingRule, ...]:
        return tuple(rule for rule in self.rules if rule.enabled and (folder is None or rule.applies_to_source(folder)))

    def move_destinations(self) -> tuple[str, ...]:
        destinations = [rule.destination for rule in self.enabled_rules() if rule.action is RuleAction.MOVE]
        return tuple(dict.fromkeys(destination for destination in destinations if destination is not None))

    def validate_destinations(self, source_folder: str, *, config_store_folder: str | None = None) -> None:
        if config_store_folder is None:
            return
        if source_folder == config_store_folder:
            raise RoutingModelError("config-store folder cannot be used as a source")
        for rule in self.enabled_rules(source_folder):
            if rule.action is RuleAction.MOVE and rule.destination == config_store_folder:
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
    configured_action: RuleAction | None = None
    rule_scope: str | None = None
    model: str | None = None
    request_id: str | None = None

    @property
    def action(self) -> RoutingAction:
        if any(result.state is EvaluationState.ERROR for result in self.rule_results):
            return RoutingAction.ERROR
        if self.configured_action is None or self.configured_action is RuleAction.KEEP:
            return RoutingAction.KEEP_IN_PLACE
        if self.configured_action is RuleAction.DELETE:
            return RoutingAction.DELETE
        if self.destination == self.folder:
            return RoutingAction.ALREADY_THERE
        return RoutingAction.MOVE


@dataclass(frozen=True, slots=True)
class RoutingReceipt:
    plan: RoutingPlan
    applied: bool
    confirmed: bool
    detail: str | None = None
