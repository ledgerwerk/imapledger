from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..config import ActionKind, MessageAction
from ..message import MailMessage
from ..routing_config import RoutingConfigError, RuleMigrationResult, migrate_legacy_rules, write_routing_rules
from ..routing_models import RoutingRule, RuleType
from ..routing_models import RuleSet as RoutingRuleSet
from ..routing_rule_service import RoutingRuleMutationResult, RoutingRuleService
from ..rule_candidates import build_rule_candidates
from ..rule_learning import RuleProposal, learn_rule_proposal
from ..rules import generate_rule_id, validate_rule_id


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
    proposal: RuleProposal
    rule: RoutingRule | None
    base_rules: RoutingRuleSet


class RuleLearningOperation:
    """Propose and save one narrow header rule from selected-message evidence."""

    def propose(
        self,
        message: MailMessage,
        *,
        folder: str,
        destination: str,
        existing_rules: RoutingRuleSet,
        name: str | None = None,
        jev_factory: Callable[[], Any] | None = None,
    ) -> RuleLearningPreview:
        if name is not None:
            validate_rule_id(name)
        candidates = build_rule_candidates(message)
        if jev_factory is None:
            from pyjev import Jev

            jev_factory = Jev
        with jev_factory() as jev:
            proposal = learn_rule_proposal(
                jev,
                message=message,
                candidates=candidates,
                requested_action=MessageAction(ActionKind.MOVE, destination),
            )
        rule = None
        if proposal.status == "auto" and proposal.candidate is not None:
            rule_id = name or generate_rule_id(
                proposal.candidate.match,
                [item.id for item in existing_rules.rules],
            )
            rule = RoutingRule(
                id=rule_id,
                enabled=True,
                type=RuleType.HEADER,
                destination=destination,
                description=proposal.candidate.description,
                match=proposal.candidate.match,
                source_folders=(folder,),
            )
        return RuleLearningPreview(proposal, rule, existing_rules)

    def save(
        self,
        preview: RuleLearningPreview,
        service: RoutingRuleService,
    ) -> RoutingRuleMutationResult:
        if preview.rule is None:
            raise RoutingConfigError("only an automatically accepted rule proposal can be saved")
        current = service.load()
        if current != preview.base_rules:
            raise RoutingConfigError("rules changed after proposal; analyze the selected message again")
        if any(
            item.source_folders == preview.rule.source_folders and item.match == preview.rule.match
            for item in current.rules
        ):
            raise RoutingConfigError("an equivalent matcher and source scope already exists")
        return service.add(preview.rule)
