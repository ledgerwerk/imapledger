from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ledgercore import AtomicWriteError, atomic_write_text

from .config import default_config_path
from .routing_actions import RuleAction
from .routing_models import (
    RULE_ID_PATTERN,
    RoutingModelError,
    RoutingRule,
    RuleEvidenceSettings,
    RuleSet,
    RuleType,
)
from .rules import RuleError, RuleMatch, load_rules

RULE_SCHEMA = 4

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
    unknown = set(table) - {"schema", "default_match_at", "rule", "evidence"}
    if unknown:
        raise RoutingConfigError(f"unknown key in [rules]: {sorted(unknown)[0]}")
    schema = table.get("schema")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != RULE_SCHEMA:
        raise RoutingConfigError(
            f"rules schema must be {RULE_SCHEMA}; use `imapledger rule migrate --preview` for explicit migration"
        )
    default_match_at = _probability(table.get("default_match_at", 0.90), "rules.default_match_at")
    evidence = _parse_evidence(table.get("evidence", {}))
    raw_rules = table.get("rule", [])
    if not isinstance(raw_rules, list):
        raise RoutingConfigError("rules.rule must be an array of tables")
    try:
        rules = tuple(_parse_routing_rule(value, index) for index, value in enumerate(raw_rules, start=1))
        return RuleSet(rules, default_match_at=default_match_at, evidence=evidence)
    except RoutingModelError as exc:
        raise RoutingConfigError(str(exc)) from exc


def _parse_evidence(value: object) -> RuleEvidenceSettings:
    if not isinstance(value, dict):
        raise RoutingConfigError("[rules.evidence] must be a table")
    unknown = set(value) - {"trusted_authserv_ids", "trusted_provider_headers"}
    if unknown:
        raise RoutingConfigError(f"unknown key in [rules.evidence]: {sorted(unknown)[0]}")
    authserv_ids = value.get("trusted_authserv_ids", [])
    provider_headers = value.get("trusted_provider_headers", [])
    if not isinstance(authserv_ids, list) or any(not isinstance(item, str) for item in authserv_ids):
        raise RoutingConfigError("rules.evidence.trusted_authserv_ids must be an array of strings")
    if not isinstance(provider_headers, list) or any(not isinstance(item, str) for item in provider_headers):
        raise RoutingConfigError("rules.evidence.trusted_provider_headers must be an array of strings")
    try:
        return RuleEvidenceSettings(tuple(authserv_ids), tuple(provider_headers))
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
        "action",
        "destination",
        "description",
        "match_at",
        "match_any",
        "source_folders",
        "recipe",
        "options",
    }
    unknown = set(value) - allowed
    if unknown:
        raise RoutingConfigError(f"unknown key in {label}: {sorted(unknown)[0]}")
    rule_id = value.get("id")
    enabled = value.get("enabled", True)
    raw_type = value.get("type")
    if not isinstance(rule_id, str) or RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise RoutingConfigError(f"{label}.id is invalid")
    if not isinstance(enabled, bool):
        raise RoutingConfigError(f"{label}.enabled must be a boolean")
    if not isinstance(raw_type, str):
        raise RoutingConfigError(f"{label}.type must be a string")
    try:
        rule_type = RuleType(raw_type)
    except ValueError as exc:
        raise RoutingConfigError(f"{label}.type must be semantic, header, or recipe") from exc
    destination = value.get("destination")
    if destination is not None and not isinstance(destination, str):
        raise RoutingConfigError(f"{label}.destination must be a string")
    if "action" in value:
        try:
            action = RuleAction(value["action"])
        except (TypeError, ValueError) as exc:
            raise RoutingConfigError(f"{label}.action must be move, delete, or keep") from exc
    elif destination is not None:
        action = RuleAction.MOVE
    else:
        raise RoutingConfigError(f"{label} requires an action or destination")
    description = value.get("description")
    if description is not None and not isinstance(description, str):
        raise RoutingConfigError(f"{label}.description must be a string")
    match_at = value.get("match_at")
    if match_at is not None:
        match_at = _probability(match_at, f"{label}.match_at")
    raw_matchers = value.get("match_any", [])
    if not isinstance(raw_matchers, list):
        raise RoutingConfigError(f"{label}.match_any must be an array of tables")
    matchers = tuple(
        _parse_matcher(raw, f"{label}.match_any[{matcher_index}]") for matcher_index, raw in enumerate(raw_matchers, 1)
    )
    source_folders = value.get("source_folders", [])
    if not isinstance(source_folders, list) or any(not isinstance(folder, str) for folder in source_folders):
        raise RoutingConfigError(f"{label}.source_folders must be an array of strings")
    recipe = value.get("recipe")
    if recipe is not None and not isinstance(recipe, str):
        raise RoutingConfigError(f"{label}.recipe must be a string")
    if rule_type is RuleType.RECIPE and (not isinstance(recipe, str) or not recipe.strip()):
        raise RoutingConfigError(f"{label}.recipe requires a valid recipe ID")
    options = value.get("options", {})
    if not isinstance(options, dict):
        raise RoutingConfigError(f"{label}.options must be a table")
    if rule_type is RuleType.RECIPE:
        from .rule_recipes import get_runtime_recipe

        try:
            get_runtime_recipe(recipe or "").validate_options(options)
        except (TypeError, ValueError) as exc:
            raise RoutingConfigError(f"invalid options for recipe {recipe!r}: {exc}") from exc
    try:
        return RoutingRule(
            id=rule_id,
            enabled=enabled,
            type=rule_type,
            action=action,
            destination=destination,
            description=description,
            match_at=match_at,
            match_any=matchers,
            source_folders=tuple(source_folders),
            recipe=recipe,
            options=options,
        )
    except RoutingModelError as exc:
        raise RoutingConfigError(f"invalid {label}: {exc}") from exc


def _parse_matcher(value: object, label: str) -> RuleMatch:
    if not isinstance(value, dict):
        raise RoutingConfigError(f"{label} must be a table")
    unknown_fields = set(value) - set(RuleMatch.__dataclass_fields__)
    if unknown_fields:
        raise RoutingConfigError(f"unknown match key in {label}: {sorted(unknown_fields)[0]}")
    if any(not isinstance(item, str) for item in value.values()):
        raise RoutingConfigError(f"{label} values must be strings")
    try:
        return RuleMatch(**value)
    except (RuleError, TypeError) as exc:
        raise RoutingConfigError(f"invalid matcher in {label}: {exc}") from exc


def _probability(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise RoutingConfigError(f"{label} must be a probability")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise RoutingConfigError(f"{label} must be between 0 and 1")
    return float(value)


def render_routing_rules(rules: RuleSet) -> str:
    lines = ["[rules]", f"schema = {RULE_SCHEMA}", f"default_match_at = {rules.default_match_at:g}"]
    if rules.evidence.trusted_authserv_ids or rules.evidence.trusted_provider_headers:
        lines.extend(
            (
                "",
                "[rules.evidence]",
                f"trusted_authserv_ids = {_toml_array(rules.evidence.trusted_authserv_ids)}",
                f"trusted_provider_headers = {_toml_array(rules.evidence.trusted_provider_headers)}",
            )
        )
    for rule in rules.rules:
        lines.extend(
            (
                "",
                "[[rules.rule]]",
                f"id = {_toml_string(rule.id)}",
                f"enabled = {str(rule.enabled).lower()}",
                f"type = {_toml_string(rule.type.value)}",
                f"action = {_toml_string(rule.action.value)}",
            )
        )
        if rule.destination is not None:
            lines.append(f"destination = {_toml_string(rule.destination)}")
        if rule.recipe is not None:
            lines.append(f"recipe = {_toml_string(rule.recipe)}")
        if rule.description is not None:
            lines.append(f"description = {_toml_string(rule.description)}")
        if rule.match_at is not None:
            lines.append(f"match_at = {rule.match_at:g}")
        if rule.source_folders:
            lines.append(f"source_folders = {_toml_array(rule.source_folders)}")
        if rule.match_any:
            matchers = []
            for matcher in rule.match_any:
                fields = ", ".join(f"{key} = {_toml_string(value)}" for key, value in matcher.as_dict().items())
                matchers.append("{ " + fields + " }")
            lines.append("match_any = [" + ", ".join(matchers) + "]")
        if rule.options:
            lines.extend(("", "[rules.rule.options]"))
            lines.extend(f"{key} = {_toml_value(value)}" for key, value in rule.options.items())
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


def rules_fingerprint(rules: RuleSet) -> str:
    payload = {
        "schema": RULE_SCHEMA,
        "default_match_at": rules.default_match_at,
        "evidence": {
            "trusted_authserv_ids": list(rules.evidence.trusted_authserv_ids),
            "trusted_provider_headers": list(rules.evidence.trusted_provider_headers),
        },
        "rules": [_rule_fingerprint_data(rule) for rule in rules.enabled_rules()],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def rules_content_fingerprint(rules: RuleSet) -> str:
    payload = {
        "schema": RULE_SCHEMA,
        "default_match_at": rules.default_match_at,
        "evidence": {
            "trusted_authserv_ids": list(rules.evidence.trusted_authserv_ids),
            "trusted_provider_headers": list(rules.evidence.trusted_provider_headers),
        },
        "rules": [{"enabled": rule.enabled, **_rule_fingerprint_data(rule)} for rule in rules.rules],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rule_fingerprint_data(rule: RoutingRule) -> dict[str, object]:
    revision = None
    if rule.type is RuleType.RECIPE:
        from .rule_recipes import get_runtime_recipe

        revision = get_runtime_recipe(rule.recipe or "").spec.revision
    return {
        "id": rule.id,
        "type": rule.type.value,
        "recipe": rule.recipe,
        "recipe_revision": revision,
        "options": dict(rule.options),
        "action": rule.action.value,
        "destination": rule.destination,
        "description": rule.description,
        "match_at": rule.match_at,
        "source_folders": list(rule.source_folders),
        "match_any": [matcher.as_dict() for matcher in rule.match_any],
    }


def migrate_legacy_rules(
    path: Path,
    *,
    apply: bool = False,
    spam_destination: str | None = None,
    allow_delete: bool = False,
) -> RuleMigrationResult:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RoutingConfigError(f"rules file not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RoutingConfigError(f"could not read rules file {path}: {exc}") from exc
    table = payload.get("rules") if isinstance(payload, dict) else None
    schema = table.get("schema") if isinstance(table, dict) else None
    if isinstance(schema, bool) or schema not in {1, 2, 3}:
        raise RoutingConfigError("rule migration requires a schema-1, schema-2, or schema-3 rules file")

    migration_warnings: list[str] = []
    if schema == 1:
        try:
            legacy = load_rules(path)
        except RuleError as exc:
            raise RoutingConfigError(f"invalid schema-1 rules: {exc}") from exc
        converted: list[RoutingRule] = []
        for old_rule in legacy.rules:
            if old_rule.action.action is not RuleAction.MOVE or old_rule.action.destination is None:
                raise RoutingConfigError(
                    f"rule {old_rule.id} uses {old_rule.action.action.value}; only MOVE rules can be migrated safely"
                )
            converted.append(
                RoutingRule(
                    id=old_rule.id,
                    enabled=old_rule.enabled,
                    type=RuleType.HEADER,
                    action=RuleAction.MOVE,
                    destination=old_rule.action.destination,
                    match_any=(old_rule.match,),
                    source_folders=old_rule.source_folders,
                )
            )
        default_match_at = 0.90
        evidence = RuleEvidenceSettings()
    else:
        if not isinstance(table, dict):
            raise RoutingConfigError("legacy [rules] must be a table")
        raw_rules = table.get("rule", [])
        if not isinstance(raw_rules, list):
            raise RoutingConfigError("rules.rule must be an array of tables")
        converted = [
            _parse_legacy_routing_rule(value, index, schema=schema) for index, value in enumerate(raw_rules, start=1)
        ]
        default_match_at = _probability(table.get("default_match_at", 0.90), "rules.default_match_at")
        evidence = RuleEvidenceSettings()
        if schema == 2:
            fallback = table.get("fallback_destination")
            if fallback is not None:
                if not isinstance(fallback, str):
                    raise RoutingConfigError("rules.fallback_destination must be a string")
                migration_warnings.append(
                    f"Old fallback destination {fallback} is not used by the new rule model. "
                    "Unmatched messages will stay in their current folder."
                )

    if spam_destination is not None:
        if not isinstance(spam_destination, str) or not spam_destination.strip():
            raise RoutingConfigError("Spam rule destination must be a non-empty folder name")
        if not any(rule.id == "spam" for rule in converted):
            converted.insert(
                0,
                RoutingRule(
                    id="spam",
                    enabled=True,
                    type=RuleType.RECIPE,
                    recipe="spam",
                    action=RuleAction.MOVE,
                    destination=spam_destination,
                ),
            )
            migration_warnings.append(
                f"Migrated the legacy Spam MOVE destination into an ordinary Spam recipe rule: {spam_destination}."
            )
    if apply and any(rule.action is RuleAction.DELETE for rule in converted) and not allow_delete:
        raise RoutingConfigError(
            "migration creates a destructive DELETE rule; re-run with explicit delete authorization"
        )
    try:
        migrated = RuleSet(tuple(converted), default_match_at=default_match_at, evidence=evidence)
    except (RoutingModelError, TypeError, ValueError) as exc:
        raise RoutingConfigError(f"invalid rules during migration: {exc}") from exc
    if apply:
        write_routing_rules(migrated, path)
    return RuleMigrationResult(migrated, schema, apply, tuple(migration_warnings))


def _parse_legacy_routing_rule(value: object, index: int, *, schema: int) -> RoutingRule:
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
        "match_any",
        "source_folders",
    }
    unknown = set(value) - allowed
    if unknown:
        raise RoutingConfigError(f"unknown key in {label}: {sorted(unknown)[0]}")
    raw_type = value.get("type")
    rule_id = value.get("id")
    enabled = value.get("enabled", True)
    destination = value.get("destination")
    if not isinstance(rule_id, str) or RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise RoutingConfigError(f"{label}.id is invalid")
    if not isinstance(enabled, bool):
        raise RoutingConfigError(f"{label}.enabled must be a boolean")
    if not isinstance(raw_type, str):
        raise RoutingConfigError(f"{label}.type must be a string")
    if not isinstance(destination, str):
        raise RoutingConfigError(f"{label}.destination must be a string")
    description = value.get("description")
    match_at = value.get("match_at")
    if description is not None and not isinstance(description, str):
        raise RoutingConfigError(f"{label}.description must be a string")
    if match_at is not None:
        match_at = _probability(match_at, f"{label}.match_at")
    if schema == 2:
        if "match_any" in value:
            raise RoutingConfigError(f"{label}.match_any is only valid in schema 3")
        raw_matchers = [value["match"]] if "match" in value else []
    else:
        if "match" in value:
            raise RoutingConfigError(f"{label}.match is only valid in schema 2")
        raw_matchers = value.get("match_any", [])
    if not isinstance(raw_matchers, list):
        raise RoutingConfigError(f"{label}.match_any must be an array of tables")
    matchers = tuple(
        _parse_matcher(raw_matcher, f"{label}.match_any[{matcher_index}]")
        for matcher_index, raw_matcher in enumerate(raw_matchers, 1)
    )
    source_folders = value.get("source_folders", [])
    if not isinstance(source_folders, list) or any(not isinstance(folder, str) for folder in source_folders):
        raise RoutingConfigError(f"{label}.source_folders must be an array of strings")
    try:
        if raw_type == "spam":
            recipe_fields = {"recipe": "spam"}
            rule_type = RuleType.RECIPE
            if matchers:
                raise RoutingConfigError(f"{label} legacy spam rules cannot contain deterministic matchers")
        else:
            recipe_fields = {}
            rule_type = RuleType(raw_type)
        return RoutingRule(
            id=rule_id,
            enabled=enabled,
            type=rule_type,
            action=RuleAction.MOVE,
            destination=destination,
            description=description,
            match_at=match_at,
            match_any=matchers,
            source_folders=tuple(source_folders),
            **recipe_fields,
        )
    except (RoutingModelError, ValueError) as exc:
        raise RoutingConfigError(f"invalid {label}: {exc}") from exc


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return _toml_string(value)
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, Mapping):
        fields = ", ".join(f"{key} = {_toml_value(item)}" for key, item in value.items())
        return "{ " + fields + " }"
    raise RoutingConfigError(f"unsupported recipe option value: {value!r}")
