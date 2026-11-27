from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pyjev.decisions import NoulDecision

from ..evidence import MessageEvidence
from ..routing_actions import RuleAction
from ..routing_models import EvaluationState, RoutingRule, RuleType


@dataclass(frozen=True, slots=True)
class RecipeEvaluation:
    state: EvaluationState
    confidence: float | None = None
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", EvaluationState(self.state))
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (float, int)):
                raise ValueError("recipe confidence must be a probability")
            if not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1:
                raise ValueError("recipe confidence must be between 0 and 1")
            object.__setattr__(self, "confidence", float(self.confidence))
        if any(not isinstance(reason, str) or not reason for reason in self.reasons):
            raise ValueError("recipe reasons must be non-empty strings")


@dataclass(frozen=True, slots=True)
class RecipeOptionSpec:
    key: str
    title: str
    description: str
    default: float
    minimum: float = 0.0
    maximum: float = 1.0


@dataclass(frozen=True, slots=True)
class RuleRecipeSpec:
    id: str
    title: str
    category: str
    summary: str
    description: str
    default_rule_id: str
    produces_type: RuleType
    default_action: RuleAction = RuleAction.MOVE
    default_description: str | None = None
    runtime_recipe: str | None = None
    options_schema: tuple[RecipeOptionSpec, ...] = ()
    uses_model: bool = False
    destructive: bool = False
    revision: str | None = None


class RuleRecipe(Protocol):
    spec: RuleRecipeSpec

    def validate_options(self, options: Mapping[str, object]) -> Mapping[str, object]: ...

    def questions(self, *, rule: RoutingRule) -> Mapping[str, NoulDecision]: ...

    def interpret(
        self,
        *,
        rule: RoutingRule,
        results: Mapping[str, float],
        evidence: MessageEvidence,
    ) -> RecipeEvaluation: ...
