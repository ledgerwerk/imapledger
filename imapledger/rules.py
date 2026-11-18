from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ledgercore import AtomicWriteError, atomic_write_text

from .config import ActionKind, ConfigError, MessageAction, default_config_path
from .evidence import normalize_domain

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

if TYPE_CHECKING:
    from .message import MailMessage


RULE_SCHEMA = 1
RULE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
MATCH_FIELDS = (
    "from_address",
    "from_domain",
    "return_path",
    "return_path_domain",
    "list_id",
    "auto_submitted",
    "subject",
    "subject_prefix",
)


class RuleError(ValueError):
    """Invalid or unavailable routing rule data."""


@dataclass(frozen=True, slots=True)
class RuleMatch:
    from_address: str | None = None
    from_domain: str | None = None
    return_path: str | None = None
    return_path_domain: str | None = None
    list_id: str | None = None
    auto_submitted: str | None = None
    subject: str | None = None
    subject_prefix: str | None = None

    def __post_init__(self) -> None:
        for field_name in MATCH_FIELDS:
            value = getattr(self, field_name)
            if value is None:
                continue
            if not isinstance(value, str) or not value.strip():
                raise RuleError(f"matcher {field_name} must be a non-empty string")
            if field_name in {"from_address", "return_path"}:
                normalized = _normalize_address(value)
                if normalized is None:
                    raise RuleError(f"matcher {field_name} must be a valid email address")
            elif field_name in {"from_domain", "return_path_domain"}:
                normalized = normalize_domain(value)
                if normalized is None:
                    raise RuleError(f"matcher {field_name} must be a valid domain")
            elif field_name == "list_id":
                normalized = value.strip()
            elif field_name == "auto_submitted":
                normalized = value.strip().casefold()
            else:
                normalized = value
            object.__setattr__(self, field_name, normalized)
        if not any(getattr(self, field_name) is not None for field_name in MATCH_FIELDS):
            raise RuleError("rule match must contain at least one field")

    def matches(self, message: MailMessage) -> bool:
        if self.from_address is not None and _normalize_address(message.from_address) != self.from_address:
            return False
        if self.from_domain is not None and _address_domain(message.from_address) != self.from_domain:
            return False
        if self.return_path is not None and _normalize_address(message.return_path) != self.return_path:
            return False
        if self.return_path_domain is not None and _address_domain(message.return_path) != self.return_path_domain:
            return False
        if self.list_id is not None and message.list_id.strip() != self.list_id:
            return False
        if self.auto_submitted is not None and message.auto_submitted.strip().casefold() != self.auto_submitted:
            return False
        if self.subject is not None and message.subject.casefold() != self.subject.casefold():
            return False
        if self.subject_prefix is not None and not message.subject.casefold().startswith(
            self.subject_prefix.casefold()
        ):
            return False
        return True

    def as_dict(self) -> dict[str, str]:
        return {field_name: value for field_name in MATCH_FIELDS if (value := getattr(self, field_name)) is not None}


@dataclass(frozen=True, slots=True)
class MailRule:
    id: str
    enabled: bool
    source_folders: tuple[str, ...]
    action: MessageAction
    match: RuleMatch

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or RULE_ID_PATTERN.fullmatch(self.id) is None:
            raise RuleError("rule id must match [a-z0-9][a-z0-9-]{0,63}")
        if not isinstance(self.enabled, bool):
            raise RuleError("rule enabled must be a boolean")
        if not isinstance(self.source_folders, (tuple, list)) or not self.source_folders:
            raise RuleError("rule source_folders must be a non-empty list of folder names")
        folders = tuple(self.source_folders)
        if any(not isinstance(folder, str) or not folder.strip() for folder in folders):
            raise RuleError("rule source_folders entries must be non-empty strings")
        if any(folder != folder.strip() for folder in folders):
            raise RuleError("rule source_folders entries must not have surrounding whitespace")
        if len(set(folders)) != len(folders):
            raise RuleError("rule source_folders must not contain duplicates")
        object.__setattr__(self, "source_folders", folders)
        if not isinstance(self.action, MessageAction):
            raise RuleError("rule action must be a MessageAction")
        if self.action.action not in {ActionKind.KEEP, ActionKind.MOVE}:
            raise RuleError("routing rules support only keep and move actions")
        if self.action.action is ActionKind.MOVE and self.action.destination in folders:
            raise RuleError("rule destination must not be a source folder")
        if not isinstance(self.match, RuleMatch):
            raise RuleError("rule match must be a RuleMatch")

    def matches(self, folder: str, message: MailMessage) -> bool:
        return self.enabled and folder in self.source_folders and self.match.matches(message)


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[MailRule, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rules, (tuple, list)):
            raise RuleError("rules must be a sequence")
        rules = tuple(self.rules)
        if any(not isinstance(rule, MailRule) for rule in rules):
            raise RuleError("rules entries must be MailRule values")
        ids = [rule.id for rule in rules]
        if len(set(ids)) != len(ids):
            raise RuleError("duplicate rule id")
        object.__setattr__(self, "rules", rules)

    def first_match(self, folder: str, message: MailMessage) -> MailRule | None:
        return next((rule for rule in self.rules if rule.matches(folder, message)), None)

    def move_destinations(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                rule.action.destination
                for rule in self.rules
                if rule.enabled and rule.action.action is ActionKind.MOVE and rule.action.destination is not None
            )
        )

    def validate_source_folders(self, configured_folders: tuple[str, ...] | list[str]) -> None:
        allowed = set(configured_folders)
        for rule in self.rules:
            outside = set(rule.source_folders) - allowed
            if outside:
                folder = sorted(outside)[0]
                raise RuleError(f"rule {rule.id} source folder is not configured in spam.folders: {folder}")
            if rule.action.action is ActionKind.MOVE and rule.action.destination in allowed:
                raise RuleError(f"rule {rule.id} destination must not be a configured spam source folder")


def rules_path_for_config(config_path: Path | None = None) -> Path:
    return (config_path or default_config_path()).with_name("rules.toml")


def load_rules(
    path: Path | None = None,
    *,
    source_folders: tuple[str, ...] | list[str] | None = None,
) -> RuleSet:
    rules_path = path or rules_path_for_config()
    try:
        text = rules_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return RuleSet()
    except OSError as exc:
        raise RuleError(f"could not read rules file {rules_path}: {exc}") from exc
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"invalid rules TOML in {rules_path}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"rules"}:
        raise RuleError("rules file must contain only a [rules] table")
    table = payload["rules"]
    if not isinstance(table, dict):
        raise RuleError("[rules] must be a table")
    unknown = set(table) - {"schema", "rule"}
    if unknown:
        raise RuleError(f"unknown key in [rules]: {sorted(unknown)[0]}")
    schema = table.get("schema")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != RULE_SCHEMA:
        raise RuleError(f"rules schema must be {RULE_SCHEMA}")
    raw_rules = table.get("rule", [])
    if not isinstance(raw_rules, list):
        raise RuleError("rules.rule must be an array of tables")
    rules = RuleSet(tuple(_parse_rule(value, index) for index, value in enumerate(raw_rules, start=1)))
    if source_folders is not None:
        rules.validate_source_folders(source_folders)
    return rules


def _parse_rule(value: object, index: int) -> MailRule:
    label = f"rules.rule[{index}]"
    if not isinstance(value, dict):
        raise RuleError(f"{label} must be a table")
    unknown = set(value) - {"id", "enabled", "source_folders", "action", "destination", "match"}
    if unknown:
        raise RuleError(f"unknown key in {label}: {sorted(unknown)[0]}")
    rule_id = value.get("id")
    enabled = value.get("enabled", True)
    folders = value.get("source_folders")
    action_value = value.get("action")
    match_value = value.get("match")
    if not isinstance(rule_id, str):
        raise RuleError(f"{label}.id must be a string")
    if not isinstance(enabled, bool):
        raise RuleError(f"{label}.enabled must be a boolean")
    if not isinstance(folders, list) or any(not isinstance(folder, str) for folder in folders):
        raise RuleError(f"{label}.source_folders must be an array of strings")
    if not isinstance(action_value, str):
        raise RuleError(f"{label}.action must be a string")
    try:
        kind = ActionKind(action_value)
    except ValueError as exc:
        raise RuleError(f"unknown action in {label}: {action_value!r}") from exc
    destination = value.get("destination")
    if kind is ActionKind.MOVE:
        if not isinstance(destination, str):
            raise RuleError(f"move action in {label} requires a destination")
        try:
            action = MessageAction(kind, destination)
        except ConfigError as exc:
            raise RuleError(f"invalid action in {label}: {exc}") from exc
    else:
        if "destination" in value:
            raise RuleError(f"{kind.value} action in {label} must not have a destination")
        if kind is ActionKind.DELETE:
            raise RuleError("routing rules support only keep and move actions")
        action = MessageAction(kind)
    if not isinstance(match_value, dict):
        raise RuleError(f"{label}.match must be a table")
    unknown_match_fields = set(match_value) - set(MATCH_FIELDS)
    if unknown_match_fields:
        raise RuleError(f"unknown match key in {label}: {sorted(unknown_match_fields)[0]}")
    if any(not isinstance(match_field, str) for match_field in match_value.values()):
        raise RuleError(f"{label}.match values must be strings")
    try:
        match = RuleMatch(**match_value)
        return MailRule(rule_id, enabled, tuple(folders), action, match)
    except (ConfigError, TypeError, RuleError) as exc:
        raise RuleError(f"invalid {label}: {exc}") from exc


def render_rules(rules: RuleSet) -> str:
    lines = ["[rules]", f"schema = {RULE_SCHEMA}"]
    for rule in rules.rules:
        lines.extend(
            (
                "",
                "[[rules.rule]]",
                f"id = {_toml_string(rule.id)}",
                f"enabled = {str(rule.enabled).lower()}",
                f"source_folders = {_toml_string_array(rule.source_folders)}",
                f"action = {_toml_string(rule.action.action.value)}",
            )
        )
        if rule.action.destination is not None:
            lines.append(f"destination = {_toml_string(rule.action.destination)}")
        match = ", ".join(f"{key} = {_toml_string(value)}" for key, value in rule.match.as_dict().items())
        lines.append(f"match = {{ {match} }}")
    return "\n".join(lines) + "\n"


def write_rules(rules: RuleSet, path: Path | None = None) -> Path:
    rules_path = path or rules_path_for_config()
    try:
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(rules_path, render_rules(rules))
    except (AtomicWriteError, OSError) as exc:
        raise RuleError(f"could not write rules file {rules_path}: {exc}") from exc
    try:
        rules_path.chmod(0o600)
    except OSError:
        pass
    return rules_path


def generate_rule_id(match: RuleMatch, existing_ids: tuple[str, ...] | list[str] = ()) -> str:
    identity = match.from_address or match.list_id or match.return_path or next(
        value for value in match.as_dict().values()
    )
    base = re.sub(r"[^a-z0-9]+", "-", identity.casefold()).strip("-") or "rule"
    base = base[:64].rstrip("-") or "rule"
    used = set(existing_ids)
    candidate = base
    suffix = 2
    while candidate in used:
        ending = f"-{suffix}"
        candidate = f"{base[: 64 - len(ending)].rstrip('-')}{ending}"
        suffix += 1
    return candidate


def validate_rule_id(value: str) -> str:
    if not isinstance(value, str) or RULE_ID_PATTERN.fullmatch(value) is None:
        raise RuleError("rule id must match [a-z0-9][a-z0-9-]{0,63}")
    return value


def describe_match(match: RuleMatch) -> str:
    labels = {
        "from_address": "from",
        "from_domain": "from-domain",
        "return_path": "return-path",
        "return_path_domain": "return-path-domain",
        "list_id": "list-id",
        "auto_submitted": "auto-submitted",
        "subject": "subject",
        "subject_prefix": "subject-prefix",
    }
    return " AND ".join(f"{labels[key]}={value}" for key, value in match.as_dict().items())


def _normalize_address(value: str) -> str | None:
    address = value.strip()
    if address.count("@") != 1:
        return None
    local, domain = address.rsplit("@", 1)
    normalized_domain = normalize_domain(domain)
    if not local or normalized_domain is None or any(char.isspace() for char in local):
        return None
    return f"{local.casefold()}@{normalized_domain}"


def _address_domain(value: str) -> str | None:
    normalized = _normalize_address(value)
    return normalized.rsplit("@", 1)[1] if normalized is not None else None


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_string_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"
