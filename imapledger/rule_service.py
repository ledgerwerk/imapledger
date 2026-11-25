from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .rules import MailRule, RuleError, RuleSet, load_rules, validate_rule_id, write_rules


@dataclass(frozen=True, slots=True)
class RuleMutationResult:
    rules: RuleSet
    changed_rule_id: str | None
    detail: str


class RuleService:
    def __init__(
        self,
        path: Path,
        *,
        source_folders: tuple[str, ...],
    ) -> None:
        self.path = path
        self.source_folders = source_folders

    def load(self) -> RuleSet:
        return load_rules(self.path, source_folders=self.source_folders)

    def add(self, rule: MailRule) -> RuleMutationResult:
        rules = self.load()
        self._validate_rule(rule)
        if any(current.id == rule.id for current in rules.rules):
            raise RuleError(f"duplicate rule ID: {rule.id}")
        self._reject_same_match(rules, rule)
        updated = RuleSet((*rules.rules, rule))
        return self._save(updated, rule.id, f"Added rule {rule.id}.")

    def update(self, rule_id: str, replacement: MailRule) -> RuleMutationResult:
        validate_rule_id(rule_id)
        rules = self.load()
        index = self._index(rules, rule_id)
        self._validate_rule(replacement)
        if replacement.id != rule_id and any(current.id == replacement.id for current in rules.rules):
            raise RuleError(f"duplicate rule ID: {replacement.id}")
        self._reject_same_match(rules, replacement, excluding=rule_id)
        updated_rules = list(rules.rules)
        updated_rules[index] = replacement
        return self._save(RuleSet(tuple(updated_rules)), replacement.id, f"Updated rule {replacement.id}.")

    def set_enabled(self, rule_id: str, enabled: bool) -> RuleMutationResult:
        validate_rule_id(rule_id)
        if not isinstance(enabled, bool):
            raise RuleError("rule enabled must be a boolean")
        rules = self.load()
        index = self._index(rules, rule_id)
        current = rules.rules[index]
        updated_rule = MailRule(
            current.id,
            enabled,
            current.source_folders,
            current.action,
            current.match,
        )
        updated = list(rules.rules)
        updated[index] = updated_rule
        verb = "Enabled" if enabled else "Disabled"
        return self._save(RuleSet(tuple(updated)), rule_id, f"{verb} rule {rule_id}.")

    def remove(self, rule_id: str) -> RuleMutationResult:
        validate_rule_id(rule_id)
        rules = self.load()
        self._index(rules, rule_id)
        updated = RuleSet(tuple(rule for rule in rules.rules if rule.id != rule_id))
        return self._save(updated, rule_id, f"Removed rule {rule_id}.")

    def move(self, rule_id: str, offset: int) -> RuleMutationResult:
        validate_rule_id(rule_id)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset not in {-1, 1}:
            raise RuleError("rule move offset must be -1 or 1")
        rules = self.load()
        index = self._index(rules, rule_id)
        target = index + offset
        if not 0 <= target < len(rules.rules):
            return RuleMutationResult(rules, None, f"Rule {rule_id} is already at that end of the order.")
        updated = list(rules.rules)
        updated[index], updated[target] = updated[target], updated[index]
        return self._save(RuleSet(tuple(updated)), rule_id, f"Moved rule {rule_id}.")

    def _validate_rule(self, rule: MailRule) -> None:
        if not isinstance(rule, MailRule):
            raise RuleError("rule must be a MailRule")
        validate_rule_id(rule.id)
        RuleSet((rule,)).validate_source_folders(self.source_folders)

    @staticmethod
    def _index(rules: RuleSet, rule_id: str) -> int:
        for index, rule in enumerate(rules.rules):
            if rule.id == rule_id:
                return index
        raise RuleError(f"rule not found: {rule_id}")

    @staticmethod
    def _reject_same_match(rules: RuleSet, candidate: MailRule, *, excluding: str | None = None) -> None:
        for existing in rules.rules:
            if existing.id == excluding:
                continue
            if existing.source_folders != candidate.source_folders or existing.match != candidate.match:
                continue
            kind = "equivalent" if existing.action == candidate.action else "conflicting"
            raise RuleError(f"{kind} rule already exists: {existing.id}")

    def _save(self, rules: RuleSet, rule_id: str, detail: str) -> RuleMutationResult:
        self._validate_rules(rules)
        write_rules(rules, self.path)
        return RuleMutationResult(rules, rule_id, detail)

    def _validate_rules(self, rules: RuleSet) -> None:
        rules.validate_source_folders(self.source_folders)
