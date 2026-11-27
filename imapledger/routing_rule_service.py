from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .routing_config import (
    RoutingConfigError,
    load_routing_rules,
    rules_content_fingerprint,
    write_routing_rules,
)
from .routing_models import RoutingRule, RuleSet, RuleType
from .rules import RuleMatch


@dataclass(frozen=True, slots=True)
class RoutingRuleMutationResult:
    rules: RuleSet
    changed_rule_id: str | None
    detail: str


class RoutingRuleService:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> RuleSet:
        return load_routing_rules(self.path)

    def add(self, rule: RoutingRule) -> RoutingRuleMutationResult:
        rules = self.load()
        if any(current.id == rule.id for current in rules.rules):
            raise RoutingConfigError(f"duplicate rule ID: {rule.id}")
        return self._save(
            RuleSet(
                (*rules.rules, rule),
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            rule.id,
        )

    def update(self, rule_id: str, replacement: RoutingRule) -> RoutingRuleMutationResult:
        rules = self.load()
        index = self._index(rules, rule_id)
        if replacement.id != rule_id and any(current.id == replacement.id for current in rules.rules):
            raise RoutingConfigError(f"duplicate rule ID: {replacement.id}")
        updated = list(rules.rules)
        updated[index] = replacement
        return self._save(
            RuleSet(
                tuple(updated),
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            replacement.id,
        )

    def add_learned_matcher(
        self,
        rule_id: str,
        matcher: RuleMatch,
        *,
        source_folder: str,
        expected_rules_fingerprint: str,
    ) -> RoutingRuleMutationResult:
        rules = self.load()
        if rules_content_fingerprint(rules) != expected_rules_fingerprint:
            raise RoutingConfigError("rules changed after proposal; analyze the selected message again")
        index = self._index(rules, rule_id)
        current = rules.rules[index]
        if current.type is not RuleType.SEMANTIC:
            raise RoutingConfigError("learned matchers can only be added to semantic rules")
        if matcher in current.match_any:
            raise RoutingConfigError(f"matcher is already attached to rule {rule_id}")
        for earlier in rules.rules[:index]:
            if earlier.enabled and earlier.applies_to_source(source_folder) and matcher in earlier.match_any:
                raise RoutingConfigError(f"matcher is already attached to higher-priority rule {earlier.id}")
        replacement = RoutingRule(
            id=current.id,
            enabled=current.enabled,
            type=current.type,
            action=current.action,
            destination=current.destination,
            description=current.description,
            match_at=current.match_at,
            match=current.match,
            source_folders=current.source_folders,
            match_any=(*current.match_any, matcher),
            recipe=current.recipe,
            options=current.options,
        )
        updated = list(rules.rules)
        updated[index] = replacement
        return self._save(
            RuleSet(
                tuple(updated),
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            rule_id,
            "Saved learned matcher to",
        )

    def set_enabled(self, rule_id: str, enabled: bool) -> RoutingRuleMutationResult:
        rules = self.load()
        index = self._index(rules, rule_id)
        current = rules.rules[index]
        replacement = RoutingRule(
            id=current.id,
            enabled=enabled,
            type=current.type,
            action=current.action,
            destination=current.destination,
            description=current.description,
            match_at=current.match_at,
            match=current.match,
            match_any=current.match_any,
            recipe=current.recipe,
            options=current.options,
            source_folders=current.source_folders,
        )
        updated = list(rules.rules)
        updated[index] = replacement
        action = "Enabled" if enabled else "Disabled"
        return self._save(
            RuleSet(
                tuple(updated),
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            rule_id,
            action,
        )

    def move(self, rule_id: str, offset: int) -> RoutingRuleMutationResult:
        if isinstance(offset, bool) or offset not in {-1, 1}:
            raise RoutingConfigError("rule move offset must be -1 or 1")
        rules = self.load()
        index = self._index(rules, rule_id)
        target = index + offset
        if not 0 <= target < len(rules.rules):
            return RoutingRuleMutationResult(rules, None, f"Rule {rule_id} is already at that end of the order.")
        updated = list(rules.rules)
        updated[index], updated[target] = updated[target], updated[index]
        return self._save(
            RuleSet(
                tuple(updated),
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            rule_id,
        )

    def remove(self, rule_id: str) -> RoutingRuleMutationResult:
        rules = self.load()
        self._index(rules, rule_id)
        updated = tuple(rule for rule in rules.rules if rule.id != rule_id)
        return self._save(
            RuleSet(
                updated,
                rules.fallback_destination,
                rules.default_match_at,
                rules.evidence,
            ),
            rule_id,
            "Removed",
        )

    def set_fallback_destination(self, destination: str | None) -> RoutingRuleMutationResult:
        rules = self.load()
        updated = RuleSet(
            rules.rules,
            destination,
            rules.default_match_at,
            rules.evidence,
        )
        return self._save(updated, None, "Updated fallback destination")

    @staticmethod
    def _index(rules: RuleSet, rule_id: str) -> int:
        for index, rule in enumerate(rules.rules):
            if rule.id == rule_id:
                return index
        raise RoutingConfigError(f"rule not found: {rule_id}")

    def _save(self, rules: RuleSet, rule_id: str | None, action: str = "Updated") -> RoutingRuleMutationResult:
        write_routing_rules(rules, self.path)
        return RoutingRuleMutationResult(rules, rule_id, f"{action} routing rules.")
