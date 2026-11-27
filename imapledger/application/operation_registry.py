from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ContextRequirement(str, Enum):
    CONFIG = "config"
    CREDENTIAL = "credential"
    CONNECTED = "connected"
    SELECTED_FOLDER = "selected_folder"
    SELECTED_MESSAGE = "selected_message"
    ROUTING_RULES = "routing_rules"
    CONFIG_STORE = "config_store"


class OperationMutability(str, Enum):
    READ_ONLY = "read-only"
    LOCAL_CONFIG = "local config"
    LOCAL_STATE = "local state"
    CREDENTIAL = "credential"
    MAILBOX = "mailbox"
    LOCAL_FILE = "local file"
    REMOTE_CONFIG_LEDGER = "remote config ledger"


@dataclass(frozen=True, slots=True)
class OperationContext:
    config: bool = False
    credential: bool = False
    connected: bool = False
    selected_folder: bool = False
    selected_message: bool = False
    routing_rules: bool = False
    config_store: bool = False

    def has(self, requirement: ContextRequirement) -> bool:
        return bool(getattr(self, requirement.value))


@dataclass(frozen=True, slots=True)
class OperationSpec:
    id: str
    cli_path: tuple[str, ...]
    title: str
    group: str
    mutability: OperationMutability
    required_context: frozenset[ContextRequirement]
    tui_partner: str | None

    def unavailable_reason(self, context: OperationContext) -> str | None:
        missing = self.required_context.difference(
            requirement for requirement in self.required_context if context.has(requirement)
        )
        if not missing:
            return None
        requirement = next(item for item in ContextRequirement if item in missing)
        return {
            ContextRequirement.CONFIG: "load a valid configuration",
            ContextRequirement.CREDENTIAL: "configure or unlock credentials",
            ContextRequirement.CONNECTED: "connect to IMAP",
            ContextRequirement.SELECTED_FOLDER: "select a real folder",
            ContextRequirement.SELECTED_MESSAGE: "select a message",
            ContextRequirement.ROUTING_RULES: "load routing rules",
            ContextRequirement.CONFIG_STORE: "enable the Config Ledger in configuration",
        }[requirement]


def _spec(
    operation_id: str,
    cli_path: str,
    title: str,
    group: str,
    mutability: OperationMutability,
    partner: str | None,
    *requirements: ContextRequirement,
) -> OperationSpec:
    return OperationSpec(
        id=operation_id,
        cli_path=tuple(cli_path.split()),
        title=title,
        group=group,
        mutability=mutability,
        required_context=frozenset(requirements),
        tui_partner=partner,
    )


OPERATION_SPECS = (
    _spec(
        "init",
        "init",
        "Setup or edit connection",
        "System",
        OperationMutability.LOCAL_CONFIG,
        "System setup wizard",
    ),
    _spec(
        "config.show",
        "config show",
        "Show effective configuration",
        "System",
        OperationMutability.READ_ONLY,
        "Effective Config viewer",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "folders",
        "folders",
        "Browse folders",
        "Mail",
        OperationMutability.READ_ONLY,
        "Mail folder browser",
        ContextRequirement.CONNECTED,
    ),
    _spec(
        "doctor",
        "doctor",
        "Connection diagnostics",
        "System",
        OperationMutability.READ_ONLY,
        "Doctor screen",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
    ),
    _spec(
        "explain",
        "explain",
        "Explain selected message",
        "Mail",
        OperationMutability.READ_ONLY,
        "Read-only explanation",
        ContextRequirement.SELECTED_MESSAGE,
    ),
    _spec(
        "auth.set",
        "auth set",
        "Set or replace credential",
        "System",
        OperationMutability.CREDENTIAL,
        "Credential setup dialog",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "auth.status",
        "auth status",
        "Inspect credential status",
        "System",
        OperationMutability.READ_ONLY,
        "System credential status",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "auth.delete",
        "auth delete",
        "Delete stored credential",
        "System",
        OperationMutability.CREDENTIAL,
        "Confirmed credential deletion",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "auth.change_passphrase",
        "auth change-passphrase",
        "Change vault passphrase",
        "System",
        OperationMutability.CREDENTIAL,
        "Vault passphrase dialog",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "rule.preview",
        "rule preview",
        "Preview rules on the next 10 messages",
        "Rules",
        OperationMutability.READ_ONLY,
        "Preview 10",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_FOLDER,
    ),
    _spec(
        "rule.apply",
        "rule apply",
        "Apply rules to a folder",
        "Rules",
        OperationMutability.MAILBOX,
        "Apply rules dialog",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_FOLDER,
    ),
    _spec(
        "rule.evaluate",
        "rule evaluate",
        "Evaluate rules for the selected message",
        "Rules",
        OperationMutability.READ_ONLY,
        "Evaluate rules",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_MESSAGE,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.migrate",
        "rule migrate",
        "Preview legacy rule migration",
        "Rules",
        OperationMutability.LOCAL_CONFIG,
        "Rules migration preview",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "rule.list",
        "rule list",
        "Browse routing rules",
        "Rules",
        OperationMutability.READ_ONLY,
        "Rules workbench",
        ContextRequirement.CONFIG,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.show",
        "rule show",
        "Show routing rule",
        "Rules",
        OperationMutability.READ_ONLY,
        "Rule detail screen",
        ContextRequirement.CONFIG,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.add",
        "rule add",
        "Add a routing rule",
        "Rules",
        OperationMutability.LOCAL_CONFIG,
        "Rules workbench and presets",
        ContextRequirement.CONFIG,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.edit",
        "rule edit",
        "Edit a routing rule",
        "Rules",
        OperationMutability.LOCAL_CONFIG,
        "Rules workbench editor",
        ContextRequirement.CONFIG,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.remove",
        "rule remove",
        "Remove routing rule",
        "Rules",
        OperationMutability.LOCAL_CONFIG,
        "Rules workbench delete",
        ContextRequirement.CONFIG,
        ContextRequirement.ROUTING_RULES,
    ),
    _spec(
        "rule.learn",
        "rule learn",
        "Learn rule from selected message",
        "Rules",
        OperationMutability.LOCAL_CONFIG,
        "Learn rule preview and save",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.ROUTING_RULES,
        ContextRequirement.SELECTED_MESSAGE,
    ),
    _spec(
        "rule.test",
        "rule test",
        "Test routing rule",
        "Rules",
        OperationMutability.READ_ONLY,
        "Rule test dialog",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.ROUTING_RULES,
        ContextRequirement.SELECTED_MESSAGE,
    ),
    _spec(
        "progress.list",
        "progress list",
        "Show progress runs",
        "Jobs",
        OperationMutability.READ_ONLY,
        "Progress screen",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "progress.show",
        "progress show",
        "Show progress run",
        "Jobs",
        OperationMutability.READ_ONLY,
        "Progress run detail",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "progress.errors",
        "progress errors",
        "Show progress errors",
        "Jobs",
        OperationMutability.READ_ONLY,
        "Progress error list",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "progress.reset",
        "progress reset",
        "Reset progress",
        "Jobs",
        OperationMutability.LOCAL_STATE,
        "Confirmed progress reset",
        ContextRequirement.CONFIG,
    ),
    _spec(
        "state.status",
        "state status",
        "Inspect classification state",
        "Mail",
        OperationMutability.READ_ONLY,
        "Classification State screen",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
    ),
    _spec(
        "state.reset",
        "state reset",
        "Preview or reset classification state",
        "Mail",
        OperationMutability.MAILBOX,
        "State reset preview and apply",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
    ),
    _spec(
        "mail.list",
        "mail list",
        "Browse messages",
        "Mail",
        OperationMutability.READ_ONLY,
        "Paged Messages pane",
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_FOLDER,
    ),
    _spec(
        "mail.show",
        "mail show",
        "Show selected message",
        "Mail",
        OperationMutability.READ_ONLY,
        "Message detail pane",
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_MESSAGE,
    ),
    _spec(
        "mail.classify",
        "mail classify",
        "Classify selected message",
        "Mail",
        OperationMutability.MAILBOX,
        "Classify selected message",
        ContextRequirement.CONNECTED,
        ContextRequirement.SELECTED_MESSAGE,
    ),
    _spec(
        "review.list",
        "review list",
        "Browse review queue",
        "Mail",
        OperationMutability.READ_ONLY,
        "Review smart view",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
    ),
    _spec(
        "config_ledger.list",
        "config list",
        "List Config Ledger tools",
        "Config Ledger",
        OperationMutability.READ_ONLY,
        "Config Ledger workspace",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec(
        "config_ledger.versions",
        "config versions",
        "Browse Config Ledger versions",
        "Config Ledger",
        OperationMutability.READ_ONLY,
        "Version history",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec(
        "config_ledger.push",
        "config push",
        "Push a configuration snapshot",
        "Config Ledger",
        OperationMutability.REMOTE_CONFIG_LEDGER,
        "Push snapshot preview and confirmation",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec(
        "config_ledger.pull",
        "config pull",
        "Pull a configuration snapshot",
        "Config Ledger",
        OperationMutability.LOCAL_FILE,
        "Pull diff and overwrite confirmation",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec(
        "config_ledger.diff",
        "config diff",
        "Compare local and stored configuration",
        "Config Ledger",
        OperationMutability.READ_ONLY,
        "Config diff viewer",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec(
        "config_ledger.cat",
        "config cat",
        "View stored configuration snapshot",
        "Config Ledger",
        OperationMutability.READ_ONLY,
        "Snapshot viewer",
        ContextRequirement.CONFIG,
        ContextRequirement.CONNECTED,
        ContextRequirement.CONFIG_STORE,
        ContextRequirement.CREDENTIAL,
    ),
    _spec("ui", "ui", "Open the TUI", "System", OperationMutability.READ_ONLY, None),
)

OPERATION_BY_ID = {spec.id: spec for spec in OPERATION_SPECS}
