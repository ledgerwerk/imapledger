from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from ..message import MailMessage
from ..routing_config import (
    RoutingConfigError,
    RuleMigrationResult,
    migrate_legacy_rules,
    rules_content_fingerprint,
    write_routing_rules,
)
from ..routing_models import RuleSet as RoutingRuleSet
from ..routing_models import RuleType
from ..routing_rule_service import RoutingRuleMutationResult, RoutingRuleService
from ..rule_candidates import RuleCandidate, build_rule_candidates
from ..rule_learning import learn_existing_rule_proposal
from ..rules import RuleMatch


@dataclass(frozen=True, slots=True)
class RuleMigrationPreview:
    source_digest: str
    result: RuleMigrationResult


class RuleMigrationOperation:
    """Preview schema-1 conversion and reject apply if its input changed."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def preview(self) -> RuleMigrationPreview:
        try:
            source = self.path.read_bytes()
            result = migrate_legacy_rules(self.path, apply=False)
            if self.path.read_bytes() != source:
                raise RoutingConfigError("rules file changed during migration preview; preview again")
        except OSError as exc:
            raise RoutingConfigError(f"could not read rules file {self.path}: {exc}") from exc
        return RuleMigrationPreview(sha256(source).hexdigest(), result)

    def apply(self, preview: RuleMigrationPreview) -> RuleMigrationResult:
        try:
            current = self.path.read_bytes()
        except OSError as exc:
            raise RoutingConfigError(f"could not read rules file {self.path}: {exc}") from exc
        if sha256(current).hexdigest() != preview.source_digest:
            raise RoutingConfigError("rules file changed after migration preview; preview again before applying")
        write_routing_rules(preview.result.rules, self.path)
        return RuleMigrationResult(preview.result.rules, preview.result.source_schema, True)


@dataclass(frozen=True, slots=True)
class RuleLearningPreview:
    target_rule_id: str
    base_rules_fingerprint: str
    source_folder: str
    uid: int
    semantic_fit: float | None
    selected_candidate: RuleCandidate | None
    candidate_confidence: float | None
    safe_probability: float | None
    proposed_matcher: RuleMatch | None
    status: Literal["auto", "review", "no-safe-candidate", "message-does-not-fit-rule", "conflict"]
    conflict_rule_id: str | None = None
    model: str | None = None
    request_id: str | None = None


class RuleLearningOperation:
    """Propose and save a safe deterministic matcher for an existing semantic rule."""

    def propose(
        self,
        message: MailMessage,
        *,
        folder: str,
        target_rule_id: str,
        existing_rules: RoutingRuleSet,
        jev_factory: Callable[[], Any] | None = None,
    ) -> RuleLearningPreview:
        target_index = next(
            (index for index, rule in enumerate(existing_rules.rules) if rule.id == target_rule_id),
            None,
        )
        if target_index is None:
            raise RoutingConfigError(f"rule not found: {target_rule_id}")
        target = existing_rules.rules[target_index]
        if target.type is not RuleType.SEMANTIC:
            raise RoutingConfigError("learning can only strengthen an existing semantic rule")
        candidates = tuple(
            candidate for candidate in build_rule_candidates(message) if candidate.match not in target.match_any
        )
        proposal = learn_existing_rule_proposal(
            message=message,
            target_rule=target,
            candidates=candidates,
            match_threshold=target.match_at if target.match_at is not None else existing_rules.default_match_at,
            jev_factory=jev_factory,
        )
        status = proposal.status
        conflict_rule_id = None
        if proposal.candidate is not None and status == "auto":
            for earlier in existing_rules.rules[:target_index]:
                if (
                    earlier.enabled
                    and earlier.applies_to_source(folder)
                    and proposal.candidate.match in earlier.match_any
                ):
                    status = "conflict"
                    conflict_rule_id = earlier.id
                    break
        return RuleLearningPreview(
            target_rule_id=target_rule_id,
            base_rules_fingerprint=rules_content_fingerprint(existing_rules),
            source_folder=folder,
            uid=message.uid,
            semantic_fit=proposal.semantic_fit,
            selected_candidate=proposal.candidate,
            candidate_confidence=proposal.candidate_confidence,
            safe_probability=proposal.safe_probability,
            proposed_matcher=proposal.candidate.match if proposal.candidate is not None else None,
            status=status,
            conflict_rule_id=conflict_rule_id,
            model=proposal.model,
            request_id=proposal.request_id,
        )

    def save(
        self,
        preview: RuleLearningPreview,
        service: RoutingRuleService,
    ) -> RoutingRuleMutationResult:
        if preview.conflict_rule_id is not None:
            raise RoutingConfigError(f"matcher is already attached to higher-priority rule {preview.conflict_rule_id}")
        if preview.status != "auto" or preview.proposed_matcher is None:
            raise RoutingConfigError("only an automatically accepted matcher proposal can be saved")
        return service.add_learned_matcher(
            preview.target_rule_id,
            preview.proposed_matcher,
            source_folder=preview.source_folder,
            expected_rules_fingerprint=preview.base_rules_fingerprint,
        )
