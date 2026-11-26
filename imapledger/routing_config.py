from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text

from .config import ActionKind, default_config_path
from .routing_models import RULE_ID_PATTERN, RoutingModelError, RoutingRule, RuleSet, RuleType
from .rules import RuleError, RuleMatch, load_rules

RULE_SCHEMA = 2

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib


class RoutingConfigError(ValueError):
    """Invalid or unavailable routing configuration."""


@dataclass(frozen=True, slots=True)
class RuleMigrationResult:
    rules: RuleSet
    source_schema: int
    applied: bool
    warnings: tuple[str, ...] = ()


def routing_rules_path_for_config(config_path: Path | None = None) -> Path:
    return (config_path or default_config_path()).with_name("rules.toml")


def load_routing_rules(path: Path | None = None) -> RuleSet:
    rules_path = path or routing_rules_path_for_config()
    try:
        text = rules_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return RuleSet()
    except OSError as exc:
        raise RoutingConfigError(f"could not read rules file {rules_path}: {exc}") from exc
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RoutingConfigError(f"invalid rules TOML in {rules_path}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"rules"}:
        raise RoutingConfigError("rules file must contain only a [rules] table")
    table = payload["rules"]
    if not isinstance(table, dict):
        raise RoutingConfigError("[rules] must be a table")
    unknown = set(table) - {"schema", "fallback_destination", "default_match_at", "rule"}
    if unknown:
        raise RoutingConfigError(f"unknown key in [rules]: {sorted(unknown)[0]}")
    schema = table.get("schema")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != RULE_SCHEMA:
        raise RoutingConfigError(f"rules schema must be {RULE_SCHEMA}; use `imapledger rule migrate` for schema 1")
    fallback = table.get("fallback_destination")
    if fallback is not None and not isinstance(fallback, str):
        raise RoutingConfigError("rules.fallback_destination must be a string")
    default_match_at = table.get("default_match_at", 0.90)
    if isinstance(default_match_at, bool) or not isinstance(default_match_at, (float, int)):
        raise RoutingConfigError("rules.default_match_at must be a probability")
    if not math.isfinite(default_match_at) or not 0 <= default_match_at <= 1:
        raise RoutingConfigError("rules.default_match_at must be between 0 and 1")
    raw_rules = table.get("rule", [])
    if not isinstance(raw_rules, list):
        raise RoutingConfigError("rules.rule must be an array of tables")
    try:
        rules = tuple(_parse_routing_rule(value, index) for index, value in enumerate(raw_rules, start=1))
        return RuleSet(rules, fallback_destination=fallback, default_match_at=float(default_match_at))
    except RoutingModelError as exc:
        raise RoutingConfigError(str(exc)) from exc


def _parse_routing_rule(value: object, index: int) -> RoutingRule:
    label = f"rules.rule[{index}]"
    if not isinstance(value, dict):
        raise RoutingConfigError(f"{label} must be a table")
    allowed = {
        "id",
        "enabled",
        "type",
        "destination",
        "description",
        "match_at",
        "match",
        "source_folders",
    }
    unknown = set(value) - allowed
    if unknown:
        raise RoutingConfigError(f"unknown key in {label}: {sorted(unknown)[0]}")
    rule_id = value.get("id")
    enabled = value.get("enabled", True)
    raw_type = value.get("type")
    destination = value.get("destination")
    if not isinstance(rule_id, str) or RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise RoutingConfigError(f"{label}.id is invalid")
    if not isinstance(enabled, bool):
        raise RoutingConfigError(f"{label}.enabled must be a boolean")
    if not isinstance(raw_type, str):
        raise RoutingConfigError(f"{label}.type must be a string")
    try:
        rule_type = RuleType(raw_type)
    except ValueError as exc:
        raise RoutingConfigError(f"{label}.type must be spam, semantic, or header") from exc
    if not isinstance(destination, str):
        raise RoutingConfigError(f"{label}.destination must be a string")
    description = value.get("description")
    if description is not None and not isinstance(description, str):
        raise RoutingConfigError(f"{label}.description must be a string")
    match_at = value.get("match_at")
    if match_at is not None and (isinstance(match_at, bool) or not isinstance(match_at, (float, int))):
        raise RoutingConfigError(f"{label}.match_at must be a probability")
    match_value = value.get("match")
    if match_value is not None and not isinstance(match_value, dict):
        raise RoutingConfigError(f"{label}.match must be a table")
    match = None
    if match_value is not None:
        unknown_fields = set(match_value) - set(RuleMatch.__dataclass_fields__)
        if unknown_fields:
            raise RoutingConfigError(f"unknown match key in {label}: {sorted(unknown_fields)[0]}")
        if any(not isinstance(item, str) for item in match_value.values()):
            raise RoutingConfigError(f"{label}.match values must be strings")
        try:
            match = RuleMatch(**match_value)
        except (RuleError, TypeError) as exc:
            raise RoutingConfigError(f"invalid matcher in {label}: {exc}") from exc
    source_folders = value.get("source_folders", [])
    if not isinstance(source_folders, list) or any(not isinstance(folder, str) for folder in source_folders):
        raise RoutingConfigError(f"{label}.source_folders must be an array of strings")
    try:
        return RoutingRule(
            id=rule_id,
            enabled=enabled,
            type=rule_type,
            destination=destination,
            description=description,
            match_at=match_at,
            match=match,
            source_folders=tuple(source_folders),
        )
    except RoutingModelError as exc:
        raise RoutingConfigError(f"invalid {label}: {exc}") from exc


def render_routing_rules(rules: RuleSet) -> str:
    lines = ["[rules]", f"schema = {RULE_SCHEMA}", f"default_match_at = {rules.default_match_at:g}"]
    if rules.fallback_destination is not None:
        lines.append(f"fallback_destination = {_toml_string(rules.fallback_destination)}")
    for rule in rules.rules:
        lines.extend(
            (
                "",
                "[[rules.rule]]",
                f"id = {_toml_string(rule.id)}",
                f"enabled = {str(rule.enabled).lower()}",
                f"type = {_toml_string(rule.type.value)}",
                f"destination = {_toml_string(rule.destination)}",
            )
        )
        if rule.description is not None:
            lines.append(f"description = {_toml_string(rule.description)}")
        if rule.match_at is not None:
            lines.append(f"match_at = {rule.match_at:g}")
        if rule.source_folders:
            lines.append(f"source_folders = {_toml_string_array(rule.source_folders)}")
        if rule.match is not None:
            fields = ", ".join(f"{key} = {_toml_string(value)}" for key, value in rule.match.as_dict().items())
            lines.append(f"match = {{ {fields} }}")
    return "\n".join(lines) + "\n"


def write_routing_rules(rules: RuleSet, path: Path | None = None) -> Path:
    rules_path = path or routing_rules_path_for_config()
    try:
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(rules_path, render_routing_rules(rules))
    except (AtomicWriteError, OSError) as exc:
        raise RoutingConfigError(f"could not write rules file {rules_path}: {exc}") from exc
    try:
        rules_path.chmod(0o600)
    except OSError:
        pass
    return rules_path


def rules_fingerprint(
    rules: RuleSet,
    *,
    spam_policy: Mapping[str, object] | None = None,
    spam_evidence_config: Mapping[str, object] | None = None,
) -> str:
    payload = {
        "schema": RULE_SCHEMA,
        "default_match_at": rules.default_match_at,
        "fallback_destination": rules.fallback_destination,
        "rules": [_rule_fingerprint_data(rule) for rule in rules.enabled_rules()],
        "spam_policy": dict(spam_policy or {}),
        "spam_evidence_config": dict(spam_evidence_config or {}),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rule_fingerprint_data(rule: RoutingRule) -> dict[str, object]:
    data: dict[str, object] = {
        "id": rule.id,
        "type": rule.type.value,
        "destination": rule.destination,
        "description": rule.description,
        "match_at": rule.match_at,
        "source_folders": list(rule.source_folders),
    }
    if rule.match is not None:
        data["match"] = rule.match.as_dict()
    return data


def migrate_legacy_rules(path: Path, *, apply: bool = False) -> RuleMigrationResult:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RoutingConfigError(f"rules file not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RoutingConfigError(f"could not read schema-1 rules file {path}: {exc}") from exc
    table = payload.get("rules") if isinstance(payload, dict) else None
    schema = table.get("schema") if isinstance(table, dict) else None
    if isinstance(schema, bool) or schema != 1:
        raise RoutingConfigError("rule migration requires a schema-1 rules file")
    try:
        legacy = load_rules(path)
    except RuleError as exc:
        raise RoutingConfigError(f"invalid schema-1 rules: {exc}") from exc
    converted: list[RoutingRule] = []
    for rule in legacy.rules:
        if rule.action.action is not ActionKind.MOVE or rule.action.destination is None:
            raise RoutingConfigError(
                f"rule {rule.id} uses {rule.action.action.value}; only MOVE rules can be migrated safely"
            )
        converted.append(
            RoutingRule(
                id=rule.id,
                enabled=rule.enabled,
                type=RuleType.HEADER,
                destination=rule.action.destination,
                match=rule.match,
                source_folders=rule.source_folders,
            )
        )
    migrated = RuleSet(tuple(converted))
    if apply:
        write_routing_rules(migrated, path)
    return RuleMigrationResult(migrated, 1, apply)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_string_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"
