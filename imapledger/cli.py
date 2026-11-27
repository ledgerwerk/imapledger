from __future__ import annotations

import getpass
import traceback
from collections.abc import Iterable
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .action_service import ActionService
from .analysis_service import AnalysisService
from .application.browsing import ReviewOperation, ReviewRequest
from .application.doctor import DoctorOperation, DoctorRequest
from .application.progress import ProgressOperation
from .application.rule_run import RuleEvaluationOperation, RuleRunOperation, RuleRunRequest
from .application.rules import RuleLearningOperation, RuleMigrationOperation
from .application.state import StateOperation, StateResetRequest
from .classification_state import all_state_keywords
from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, MessageResult
from .config import (
    ActionKind,
    AuthSource,
    ClassificationStateBackend,
    ClassificationStateSettings,
    ConfigError,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    action_for_outcome,
    default_config_path,
    load_imap_settings,
    load_settings,
    render_settings,
    write_settings,
)
from .config_errors import ConfigLedgerError, ConfigStoreFolderMissingError
from .config_mailbox import ConfigStoreMailbox, ConfigStoreOperationError
from .config_store_cli import register_config_store_commands
from .credential_service import configure_stored_credential, remove_stored_credential
from .credentials import (
    CredentialError,
    CredentialRef,
    change_credential_vault_passphrase,
    credential_backend_for,
    credential_backend_for_storage,
    credential_status,
    default_credential_vault_path,
    resolve_credential,
)
from .evidence import build_message_evidence, redact_urls
from .mail_service import MailService
from .mailbox import (
    FolderCatalog,
    FolderInfo,
    ImapOperationError,
    MailboxError,
    MailboxSnapshot,
    MessageSelection,
    MessageSort,
    ScopedMailbox,
)
from .processing_engine import ProcessedMessage, ProcessingError
from .progress_store import ProgressStoreError, default_progress_path
from .routing_config import (
    RoutingConfigError,
    load_routing_rules,
    routing_rules_path_for_config,
)
from .routing_models import RoutingRule, RuleType
from .routing_models import RuleSet as RoutingRuleSet
from .routing_rule_service import RoutingRuleService
from .rules import (
    RuleError,
    RuleMatch,
    RuleSet,
    describe_match,
    load_rules,
    rules_path_for_config,
)

app = typer.Typer(no_args_is_help=True, help="Security-scoped IMAP mail classification and cleaning.")
config_app = typer.Typer(help="Inspect imapledger configuration.")
app.add_typer(config_app, name="config")
auth_app = typer.Typer(help="Store and inspect IMAP credentials.")
app.add_typer(auth_app, name="auth")
rule_app = typer.Typer(help="Manage global routing rules, previews, apply, and learning.")
app.add_typer(rule_app, name="rule")
state_app = typer.Typer(help="Inspect and reset persisted classification state.")
app.add_typer(state_app, name="state")
progress_app = typer.Typer(help="Inspect, retry, and reset resumable routing progress.")
app.add_typer(progress_app, name="progress")
review_app = typer.Typer(help="Inspect the persisted review queue.")
app.add_typer(review_app, name="review")
mail_app = typer.Typer(help="Browse and analyze mailbox messages.")
app.add_typer(mail_app, name="mail")
console = Console()
err_console = Console(stderr=True)


@config_app.command("show")
def config_show(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Print the validated effective configuration without connecting to IMAP."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print(f"config: {config}", markup=False)
    console.print(render_settings(settings), markup=False)


@app.command("init")
def init_config(
    host: str = typer.Option(..., prompt=True, help="IMAP host"),
    username: str = typer.Option(..., prompt=True, help="IMAP username"),
    folders: list[str] = typer.Option(  # noqa: B008
        [], "--folder", help="Source folder. Repeat to configure multiple folders."
    ),
    spam_action: ActionKind = typer.Option(  # noqa: B008
        ActionKind.DELETE, "--spam-action", help="Action for spam outcomes"
    ),
    spam_destination: str | None = typer.Option(None, "--spam-destination", help="Destination for spam moves"),
    not_spam_action: ActionKind = typer.Option(  # noqa: B008
        ActionKind.KEEP, "--not-spam-action", help="Action for not-spam outcomes"
    ),
    not_spam_destination: str | None = typer.Option(
        None, "--not-spam-destination", help="Destination for not-spam moves"
    ),
    port: int = typer.Option(993, help="IMAPS port"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config"),
) -> None:
    """Write non-secret configuration. The IMAP password is never stored."""
    source_folders = folders or [typer.prompt("Initial source folder", default="Spam")]
    try:
        path = write_settings(
            Settings(
                imap=ImapSettings(host=host, port=port, username=username),
                spam=SpamSettings(
                    folders=tuple(source_folders),
                    state=ClassificationStateSettings(ClassificationStateBackend.IMAP_KEYWORDS),
                    actions=SpamActions(
                        spam=MessageAction(spam_action, spam_destination),
                        not_spam=MessageAction(not_spam_action, not_spam_destination),
                    ),
                ),
            ),
            config,
            overwrite=force,
        )
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Wrote {path}")
    console.print("No IMAP password was stored.")


def _load_auth_settings(config: Path) -> Settings:
    try:
        return load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _resolve_password(imap: ImapSettings) -> str:
    try:
        return resolve_credential(imap).password
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc


register_config_store_commands(config_app, resolve_password=lambda imap: _resolve_password(imap))


@auth_app.command("set")
def auth_set(
    storage: str = typer.Option(
        "auto",
        "--storage",
        help="Credential storage: auto (default), keyring, or vault (encrypted-file alias)",
    ),
    replace_existing: bool = typer.Option(
        False,
        "--replace",
        help="Replace this account's credential in the selected backend",
    ),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Store an IMAP password in the selected secure backend and update its source."""
    settings = _load_auth_settings(config)
    vault_path = None
    if storage in {"vault", "encrypted-file"}:
        vault_path = settings.imap.auth.vault_path or default_credential_vault_path()
    try:
        backend = credential_backend_for_storage(
            storage,
            vault_path=vault_path,
            vault_min_passphrase_length=settings.imap.auth.vault_min_passphrase_length,
        )
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    source = backend.source
    password = getpass.getpass("IMAP password: ")
    if not password:
        err_console.print("Credential error: IMAP password must not be empty", markup=False)
        raise typer.Exit(2)

    master_passphrase: str | None = None
    if source is AuthSource.VAULT:
        new_vault = not backend.vault_path.exists()
        if new_vault:
            prompt = f"Choose master passphrase (minimum {settings.imap.auth.vault_min_passphrase_length} characters): "
        else:
            prompt = "Credential vault passphrase: "
        master_passphrase = getpass.getpass(prompt)
        if not master_passphrase:
            err_console.print("Credential error: credential vault master passphrase is required", markup=False)
            raise typer.Exit(2)
        if new_vault:
            confirmation = getpass.getpass("Confirm master passphrase: ")
            if master_passphrase != confirmation:
                err_console.print("Credential error: master passphrases did not match", markup=False)
                raise typer.Exit(2)
    try:
        configure_stored_credential(
            config_path=config,
            config=settings,
            backend=backend,
            ref=CredentialRef(settings.imap.host, settings.imap.port, settings.imap.username),
            password=password,
            passphrase=master_passphrase,
            replace=replace_existing,
        )
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    if source is AuthSource.KEYRING:
        console.print("Stored IMAP credential in OS keyring.", markup=False)
    else:
        console.print(f"Stored encrypted IMAP credential in {backend.vault_path}", markup=False)


@auth_app.command("status")
def auth_status(
    verbose: bool = typer.Option(False, "--verbose", help="Show safe vault metadata and backend diagnostics"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Show safe diagnostics for the configured credential source."""
    settings = _load_auth_settings(config)
    imap = settings.imap
    source = imap.auth.source
    console.print(f"account: {imap.username} @ {imap.host}:{imap.port}", markup=False)
    console.print(f"configured source: {source.value}", markup=False)

    if source is AuthSource.PROMPT:
        console.print("stored credential: no", markup=False)
        return

    if source is AuthSource.VAULT and verbose:
        console.print(
            f"new-passphrase minimum: {imap.auth.vault_min_passphrase_length} characters (local config)",
            markup=False,
        )

    try:
        status = credential_status(imap)
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    if source is AuthSource.KEYRING:
        if not status.backend_available:
            console.print("available: no", markup=False)
            console.print(f"reason: {status.reason or 'the OS keyring is unavailable'}", markup=False)
            console.print("hint: pip install 'imapledger[keyring]'", markup=False)
            console.print("alternative: imapledger auth set --storage vault", markup=False)
            return
        console.print(f"backend: {status.backend_name or 'unknown'}", markup=False)
        console.print("available: yes", markup=False)
        console.print(f"credential present: {'yes' if status.available else 'no'}", markup=False)
        return

    console.print(f"vault: {status.vault_path}", markup=False)
    if status.vault_format is None:
        console.print("available: no", markup=False)
        return
    console.print("available: yes", markup=False)
    if status.available is None:
        console.print("account credential: unknown until unlock", markup=False)
    else:
        console.print(f"account credential: {'present' if status.available else 'absent'}", markup=False)
    if verbose:
        console.print(f"format: {status.vault_format}", markup=False)
        console.print(f"KDF: {status.kdf_name}", markup=False)
        console.print(f"memory: {status.memlimit_bytes // (1024 * 1024)} MiB", markup=False)
        console.print(f"operations: {status.opslimit}", markup=False)
        console.print(f"entry count: {status.entry_count}", markup=False)


@auth_app.command("delete")
def auth_delete(
    yes: bool = typer.Option(False, "--yes", help="Delete without confirmation"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Delete this account's stored credential and return configuration to prompt mode."""
    settings = _load_auth_settings(config)
    source = settings.imap.auth.source
    if source is AuthSource.PROMPT:
        console.print("No stored IMAP credential is configured.", markup=False)
        return
    if not yes and not typer.confirm(
        f"Delete the {source.value} credential for this IMAP account?",
        default=False,
    ):
        console.print("No credential was deleted.", markup=False)
        return

    vault_path = None
    if source is AuthSource.VAULT:
        vault_path = settings.imap.auth.vault_path or default_credential_vault_path()
    backend = credential_backend_for(
        source,
        vault_path=vault_path,
        vault_min_passphrase_length=settings.imap.auth.vault_min_passphrase_length,
    )
    master_passphrase = None
    if source is AuthSource.VAULT:
        master_passphrase = getpass.getpass("Credential vault passphrase: ")

    try:
        deleted = remove_stored_credential(
            config_path=config,
            config=settings,
            backend=backend,
            ref=CredentialRef(settings.imap.host, settings.imap.port, settings.imap.username),
            passphrase=master_passphrase,
        )
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    if deleted:
        console.print(f"Deleted IMAP credential from {source.value} storage.", markup=False)
    else:
        console.print("No stored IMAP credential was found; prompt mode is now active.", markup=False)


@auth_app.command("change-passphrase")
def auth_change_passphrase(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Change the passphrase protecting the configured encrypted credential vault."""
    settings = _load_auth_settings(config)
    if settings.imap.auth.source is not AuthSource.VAULT:
        err_console.print("Credential error: configured source is not vault", markup=False)
        raise typer.Exit(2)

    old_passphrase = getpass.getpass("Current master passphrase: ")
    new_passphrase = getpass.getpass(
        f"New master passphrase (minimum {settings.imap.auth.vault_min_passphrase_length} characters): "
    )
    confirmation = getpass.getpass("Confirm new master passphrase: ")
    if new_passphrase != confirmation:
        err_console.print("Credential error: new passphrases did not match", markup=False)
        raise typer.Exit(2)
    try:
        change_credential_vault_passphrase(
            old_passphrase,
            new_passphrase,
            vault_path=settings.imap.auth.vault_path,
            min_passphrase_length=settings.imap.auth.vault_min_passphrase_length,
        )
    except CredentialError as exc:
        err_console.print(f"Credential error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print("Changed encrypted credential vault passphrase.", markup=False)


@rule_app.command("migrate")
def rule_migrate(
    apply: bool = typer.Option(False, "--apply", help="Write the schema-3 conversion to rules.toml."),
    preview: bool = typer.Option(False, "--preview", help="Preview the conversion without writing."),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Explicitly migrate legacy routing rules to schema 3."""
    if apply and preview:
        err_console.print("Usage error: --preview and --apply cannot be combined.")
        raise typer.Exit(2)
    path = routing_rules_path_for_config(config)
    operation = RuleMigrationOperation(path)
    try:
        preview_result = operation.preview()
        result = operation.apply(preview_result) if apply else preview_result.result
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"rules: {path}", markup=False)
    console.print(f"schema: {result.source_schema} -> 3", markup=False)
    console.print(f"converted rules: {len(result.rules.rules)}", markup=False)
    for warning in result.warnings:
        console.print(f"warning: {warning}", markup=False)
    console.print(
        "Migration applied." if apply else "Preview only. Re-run with --apply to write schema-3 rules.",
        markup=False,
    )


def _load_routing_rules_for_cli(config: Path) -> RoutingRuleSet:
    try:
        return load_routing_rules(routing_rules_path_for_config(config))
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc


def _parse_rule_matchers(values: list[str]) -> tuple[RuleMatch, ...]:
    matchers = []
    fields = set(RuleMatch.__dataclass_fields__)
    for value in values:
        field, separator, expected = value.partition("=")
        if not separator or field not in fields or not expected:
            raise typer.BadParameter("matchers must use field=value with a supported matcher field")
        try:
            matchers.append(RuleMatch(**{field: expected}))
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    return tuple(matchers)


@rule_app.command("list")
def rule_list(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """List locally stored routing rules without connecting to IMAP."""
    rules = _load_routing_rules_for_cli(config)
    if not rules.rules:
        console.print("No routing rules.", markup=False)
        return
    table = Table(title="Routing rules")
    for column in ("ID", "Enabled", "Type", "Scope", "Destination", "Match"):
        table.add_column(column)
    for rule in rules.rules:
        scope = ", ".join(rule.source_folders) if rule.source_folders else "All folders"
        match = " OR ".join(describe_match(item) for item in rule.match_any) or "semantic"
        table.add_row(
            rule.id,
            "yes" if rule.enabled else "no",
            rule.type.value,
            scope,
            rule.destination,
            match,
        )
    console.print(table, markup=False)


@rule_app.command("show")
def rule_show(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Show one locally stored routing rule without connecting to IMAP."""
    rules = _load_routing_rules_for_cli(config)
    rule = next((item for item in rules.rules if item.id == rule_id), None)
    if rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    console.print(f"id: {rule.id}", markup=False)
    console.print(f"enabled: {str(rule.enabled).lower()}", markup=False)
    console.print(f"type: {rule.type.value}", markup=False)
    console.print(f"scope: {', '.join(rule.source_folders) if rule.source_folders else 'all folders'}", markup=False)
    console.print(f"destination: {rule.destination}", markup=False)
    if rule.description is not None:
        console.print(f"description: {_safe_text(rule.description)}", markup=False)
    if rule.match_any:
        console.print("match any:", markup=False)
        for matcher in rule.match_any:
            console.print(f"  - {describe_match(matcher)}", markup=False)


@rule_app.command("add")
def rule_add(
    rule_id: str = typer.Argument(..., help="New rule ID"),
    rule_type: RuleType = typer.Option(..., "--type", help="Rule type: semantic or header"),  # noqa: B008
    destination: str = typer.Option(..., "--destination", help="Destination folder"),
    description: str | None = typer.Option(None, "--description", help="Rule description"),
    matcher_values: list[str] = typer.Option([], "--match", help="Matcher field=value; repeat for OR alternatives"),  # noqa: B008
    source_folders: list[str] = typer.Option(  # noqa: B008
        [], "--source-folder", help="Restrict rule to a source folder; repeatable"
    ),  # noqa: B008
    match_at: float | None = typer.Option(None, "--match-at", min=0, max=1, help="Semantic match threshold"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Add a global-by-default semantic or header routing rule."""
    if rule_type is RuleType.SPAM:
        raise typer.BadParameter("the built-in Spam rule cannot be added manually")
    matchers = _parse_rule_matchers(matcher_values)
    try:
        rule = RoutingRule(
            id=rule_id,
            enabled=True,
            type=rule_type,
            destination=destination,
            description=description,
            match_at=match_at,
            source_folders=tuple(source_folders),
            match_any=matchers,
        )
        result = RoutingRuleService(routing_rules_path_for_config(config)).add(rule)
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"Added rule {result.changed_rule_id}", markup=False)


@rule_app.command("edit")
def rule_edit(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    destination: str | None = typer.Option(None, "--destination", help="Destination folder"),
    description: str | None = typer.Option(None, "--description", help="Rule description"),
    matcher_values: list[str] = typer.Option([], "--match", help="Replace matchers; repeat for OR alternatives"),  # noqa: B008
    source_folders: list[str] = typer.Option([], "--source-folder", help="Replace source scope; repeatable"),  # noqa: B008
    global_scope: bool = typer.Option(False, "--global", help="Make the rule apply to all folders"),
    match_at: float | None = typer.Option(None, "--match-at", min=0, max=1, help="Semantic match threshold"),
    enable: bool = typer.Option(False, "--enable", help="Enable the rule"),
    disable: bool = typer.Option(False, "--disable", help="Disable the rule"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Edit a local rule without connecting to IMAP."""
    if enable and disable:
        raise typer.BadParameter("--enable and --disable cannot be combined")
    service = RoutingRuleService(routing_rules_path_for_config(config))
    try:
        rules = service.load()
        current = next((item for item in rules.rules if item.id == rule_id), None)
        if current is None:
            raise RoutingConfigError(f"rule not found: {rule_id}")
        if current.built_in and (
            description is not None or matcher_values or source_folders or global_scope or match_at is not None
        ):
            raise RoutingConfigError("the built-in Spam rule only supports destination and enabled-state edits")
        matchers = _parse_rule_matchers(matcher_values) if matcher_values else current.match_any
        scope = () if global_scope else (tuple(source_folders) if source_folders else current.source_folders)
        replacement = RoutingRule(
            id=current.id,
            enabled=False if disable else (True if enable else current.enabled),
            type=current.type,
            destination=destination or current.destination,
            description=description or current.description,
            match_at=match_at if match_at is not None else current.match_at,
            match_any=matchers,
            source_folders=scope,
            built_in=current.built_in,
        )
        result = service.update(rule_id, replacement)
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"Updated rule {result.changed_rule_id}", markup=False)


@rule_app.command("remove")
def rule_remove(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    yes: bool = typer.Option(False, "--yes", help="Remove without confirmation"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Remove a locally stored routing rule without connecting to IMAP."""
    service = RoutingRuleService(routing_rules_path_for_config(config))
    try:
        rules = service.load()
        rule = next((item for item in rules.rules if item.id == rule_id), None)
        if rule is None:
            raise RoutingConfigError(f"rule not found: {rule_id}")
        if rule.built_in:
            raise RoutingConfigError("the built-in Spam rule cannot be removed")
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    if not yes and not typer.confirm(f"Remove rule {rule_id}?", default=False):
        console.print("No rule was removed.", markup=False)
        return
    try:
        service.remove(rule_id)
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    console.print(f"Removed rule {rule_id}", markup=False)


def _execute_rule_run(
    *,
    folder: str | None,
    all_folders: bool,
    apply: bool,
    limit: int,
    rule_scope: str | None,
    sort: MessageSort,
    new_run: bool,
    retry_errors: bool,
    progress_db: Path,
    config: Path,
    verbose: bool,
    yes: bool = False,
) -> None:
    if all_folders == (folder is not None):
        raise typer.BadParameter("specify exactly one folder or --all-folders")
    if new_run and retry_errors:
        raise typer.BadParameter("--new-run cannot be combined with --retry-errors")
    if retry_errors and not apply:
        raise typer.BadParameter("--retry-errors requires --apply")
    if apply and not yes and not typer.confirm("Apply routing rules to the selected folder scope?", default=False):
        console.print("No mailbox changes made.", markup=False)
        return
    try:
        settings = load_settings(config)
        rules = load_routing_rules(routing_rules_path_for_config(config))
        operation = RuleRunOperation(settings, rules)
        if rule_scope is not None and not any(rule.id == rule_scope for rule in rules.rules):
            raise RoutingConfigError(f"rule not found: {rule_scope}")
        password = ""
        if all_folders:
            password = _resolve_password(settings.imap)
            with FolderCatalog(
                host=settings.imap.host,
                port=settings.imap.port,
                username=settings.imap.username,
                password=password,
                event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            ) as catalog:
                rows = catalog.list_folders(include_counts=False)
            selected_folders = operation.selectable_folders(rows)
            if not selected_folders:
                raise MailboxError("no selectable mail folders were found")
        else:
            selected_folders = (folder,)
        request = RuleRunRequest(
            folders=selected_folders,
            apply=apply,
            limit=limit,
            sort=sort.value,
            rule_scope=rule_scope,
            new_run=new_run,
            retry_errors=retry_errors,
            progress_db=progress_db,
        )
        operation.preflight(request)
        if not all_folders:
            password = _resolve_password(settings.imap)

        def display_result(current_folder, message, _run):
            console.print(f"folder={current_folder}", markup=False)
            _print_processing_message(message, preview=not apply)

        result = operation.run(
            request,
            password=password,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            on_result=display_result,
        )
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except (MailboxError, ProcessingError, ProgressStoreError) as exc:
        _print_failure(exc, debug=False, command="rule apply" if apply else "rule preview")
        raise typer.Exit(1) from exc
    except Exception as exc:
        _print_failure(exc, debug=False, command="rule apply" if apply else "rule preview")
        raise typer.Exit(1) from exc
    finally:
        password = ""
    for current_folder, run in result.progress:
        console.print(
            f"folder={current_folder} run={run.id} status={run.status} scanned={run.scanned_count} "
            f"matched={run.match_count} moved={run.moved_count} no_match={run.no_match_count} errors={run.error_count}",
            markup=False,
        )
    if not apply:
        console.print("Preview only. No mailbox or per-message progress state was changed.", markup=False)
    if any(message.outcome == "error" for _, message in result.messages):
        raise typer.Exit(1)


@rule_app.command("preview")
def rule_preview(
    folder: str | None = typer.Argument(None, help="Source folder; omit when using --all-folders"),  # noqa: B008
    all_folders: bool = typer.Option(False, "--all-folders", help="Preview every selectable mail folder"),
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum messages per folder"),
    rule_scope: str | None = typer.Option(None, "--rule", help="Evaluate only this rule"),
    sort: MessageSort = typer.Option(MessageSort.OLDEST, "--sort", help="Mailbox-local UID ordering"),  # noqa: B008
    new_run: bool = typer.Option(False, "--new-run", help="Start a fresh preview scan"),
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Preview the ordered global routing rules without changing mail."""
    _execute_rule_run(
        folder=folder,
        all_folders=all_folders,
        apply=False,
        limit=limit,
        rule_scope=rule_scope,
        sort=sort,
        new_run=new_run,
        retry_errors=False,
        progress_db=progress_db,
        config=config,
        verbose=verbose,
    )


@rule_app.command("apply")
def rule_apply(
    folder: str | None = typer.Argument(None, help="Source folder; omit when using --all-folders"),  # noqa: B008
    all_folders: bool = typer.Option(False, "--all-folders", help="Apply to every selectable mail folder"),
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum messages per folder"),
    rule_scope: str | None = typer.Option(None, "--rule", help="Apply only this rule"),
    sort: MessageSort = typer.Option(MessageSort.OLDEST, "--sort", help="Mailbox-local UID ordering"),  # noqa: B008
    new_run: bool = typer.Option(False, "--new-run", help="Supersede active progress and start a fresh scan"),
    retry_errors: bool = typer.Option(False, "--retry-errors", help="Retry stored errors from the matching run"),
    yes: bool = typer.Option(False, "--yes", help="Apply without confirmation"),
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Apply ordered routing rules after mailbox preflight and confirmation."""
    _execute_rule_run(
        folder=folder,
        all_folders=all_folders,
        apply=True,
        limit=limit,
        rule_scope=rule_scope,
        sort=sort,
        new_run=new_run,
        retry_errors=retry_errors,
        progress_db=progress_db,
        config=config,
        verbose=verbose,
        yes=yes,
    )


@rule_app.command("learn")
def rule_learn(
    rule_id: str = typer.Argument(..., help="Existing semantic rule to strengthen"),
    folder: str = typer.Option(..., "--folder", help="Folder containing the exact message UID"),
    uid: int = typer.Option(..., "--uid", min=1, help="Exact message UID to learn from"),
    preview_only: bool = typer.Option(False, "--preview", help="Show the proposal without saving"),
    yes: bool = typer.Option(False, "--yes", help="Save without confirmation"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Strengthen an existing semantic rule with one safe deterministic matcher."""
    if uid < 1:
        raise typer.BadParameter("UID must be a positive integer")
    try:
        settings = load_settings(config)
        rules = load_routing_rules(routing_rules_path_for_config(config))
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    if settings.config_store is not None and folder == settings.config_store.folder:
        raise typer.BadParameter("Config Ledger cannot be used as a learning source")
    target_rule = next((rule for rule in rules.rules if rule.id == rule_id), None)
    if target_rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    if target_rule.type is not RuleType.SEMANTIC:
        raise typer.BadParameter("learning can only strengthen an existing semantic rule")

    password = _resolve_password(settings.imap)
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            item = mailbox.fetch_uid(uid)
            if item.message is None:
                raise MailboxError(f"Could not read UID {uid}: {item.skip_reason or 'message unavailable'}")
            message = item.message
        operation = RuleLearningOperation()
        proposal = operation.propose(
            message,
            folder=folder,
            target_rule_id=rule_id,
            existing_rules=rules,
        )
    except (MailboxError, RoutingConfigError, ValueError) as exc:
        _print_failure(exc, debug=False, command="rule learn")
        raise typer.Exit(1) from exc
    except Exception as exc:
        _print_failure(exc, debug=False, command="rule learn")
        raise typer.Exit(1) from exc
    finally:
        password = ""

    console.print(f"example {folder} UID {uid}", markup=False)
    console.print(f"target rule: {rule_id}", markup=False)
    console.print(f"From: {_safe_text(message.sender)}", markup=False)
    console.print(f"Subject: {_safe_text(message.subject)}", markup=False)
    if proposal.semantic_fit is not None:
        console.print(f"semantic fit: {proposal.semantic_fit:.2f}", markup=False)
    if proposal.selected_candidate is not None:
        console.print(f"Candidate: {proposal.selected_candidate.description}", markup=False)
    if proposal.candidate_confidence is not None:
        console.print(f"Candidate confidence: {proposal.candidate_confidence:.2f}", markup=False)
    if proposal.safe_probability is not None:
        console.print(f"Generalization safety: {proposal.safe_probability:.2f}", markup=False)
    if proposal.proposed_matcher is not None:
        console.print(f"Proposed matcher: {describe_match(proposal.proposed_matcher)}", markup=False)
    console.print(f"Proposal status: {proposal.status}", markup=False)
    if proposal.status == "conflict" and proposal.conflict_rule_id is not None:
        console.print(f"Matcher conflicts with higher-priority rule {proposal.conflict_rule_id}.", markup=False)
    if proposal.status != "auto" or proposal.proposed_matcher is None:
        console.print("No matcher was saved.", markup=False)
        return
    if preview_only:
        console.print("Preview only. No matcher was saved.", markup=False)
        return
    if not yes and not typer.confirm("Save matcher to this rule?", default=False):
        console.print("No matcher was saved.", markup=False)
        return
    try:
        result = operation.save(proposal, RoutingRuleService(routing_rules_path_for_config(config)))
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    console.print(f"Saved matcher to rule {result.changed_rule_id}", markup=False)


@rule_app.command("evaluate")
def rule_evaluate(
    folder: str = typer.Option(..., "--folder", help="Folder containing the exact message UID"),
    uid: int = typer.Option(..., "--uid", min=1, help="Exact message UID to evaluate"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Evaluate all enabled rules for one exact message without applying actions."""
    try:
        settings = load_settings(config)
        rules = load_routing_rules(routing_rules_path_for_config(config))
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    if settings.config_store is not None and folder == settings.config_store.folder:
        raise typer.BadParameter("Config Ledger cannot be used as a rule source")
    password = _resolve_password(settings.imap)
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            item = mailbox.fetch_uid(uid)
            if item.message is None:
                raise MailboxError(f"Could not read UID {uid}: {item.skip_reason or 'message unavailable'}")
            plan = RuleEvaluationOperation(settings, rules).evaluate(folder, item.message)
    except (MailboxError, ProcessingError, RoutingConfigError) as exc:
        _print_failure(exc, debug=False, command="rule evaluate")
        raise typer.Exit(1) from exc
    except Exception as exc:
        _print_failure(exc, debug=False, command="rule evaluate")
        raise typer.Exit(1) from exc
    finally:
        password = ""
    console.print(
        f"Folder={folder} UID {uid} winner={plan.winner_rule_id or '-'} destination={plan.destination or '-'}",
        markup=False,
    )
    for result in plan.rule_results:
        confidence = f" confidence={result.confidence:.3f}" if result.confidence is not None else ""
        console.print(f"  {result.rule_id}: {result.state.value}{confidence}", markup=False)
    console.print("Read-only; no actions were executed.", markup=False)


@rule_app.command("test")
def rule_test(
    rule_id: str = typer.Argument(..., help="Rule ID to test"),
    folder: str = typer.Option(..., "--folder", help="Folder containing the exact message UID"),
    uid: int = typer.Option(..., "--uid", min=1, help="Exact message UID to evaluate"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Evaluate one exact message with the selected rule, without applying actions."""
    try:
        settings = load_settings(config)
        rules = load_routing_rules(routing_rules_path_for_config(config))
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    rule = next((item for item in rules.rules if item.id == rule_id), None)
    if rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    if settings.config_store is not None and folder == settings.config_store.folder:
        raise typer.BadParameter("Config Ledger cannot be used as a rule source")
    password = _resolve_password(settings.imap)
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            item = mailbox.fetch_uid(uid)
            if item.message is None:
                raise MailboxError(f"Could not read UID {uid}: {item.skip_reason or 'message unavailable'}")
            plan = RuleEvaluationOperation(settings, rules).evaluate(folder, item.message, rule_scope=rule_id)
    except (MailboxError, ProcessingError, RoutingConfigError) as exc:
        _print_failure(exc, debug=False, command="rule test")
        raise typer.Exit(1) from exc
    except Exception as exc:
        _print_failure(exc, debug=False, command="rule test")
        raise typer.Exit(1) from exc
    finally:
        password = ""
    matched = plan.winner_rule_id == rule_id
    console.print(
        f"Folder={folder} UID {uid} {'MATCH' if matched else 'NO MATCH'} "
        f"winner={plan.winner_rule_id or '-'} destination={plan.destination or '-'}",
        markup=False,
    )
    for result in plan.rule_results:
        confidence = f" confidence={result.confidence:.3f}" if result.confidence is not None else ""
        console.print(f"  {result.rule_id}: {result.state.value}{confidence}", markup=False)
    console.print("Read-only; no actions were executed.", markup=False)


@app.command()
def folders(
    config: Path = typer.Option(default_config_path(), "--config", help="Config file, ignored in direct mode"),  # noqa: B008
    host: str | None = typer.Option(None, "--host", help="IMAP host for direct connection mode"),
    username: str | None = typer.Option(None, "--username", help="IMAP username for direct connection mode"),
    port: int | None = typer.Option(None, "--port", help="IMAPS port for direct connection mode (default: 993)"),
    counts: bool = typer.Option(True, "--counts/--no-counts", help="Read aggregate message and unread counts"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """List IMAP folders and counts without reading message contents or mutating mail."""
    try:
        imap = _resolve_folder_imap_settings(config, host=host, username=username, port=port)
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    password = _resolve_password(imap)

    rows: tuple[FolderInfo, ...] = ()
    try:
        with FolderCatalog(
            host=imap.host,
            port=imap.port,
            username=imap.username,
            password=password,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as catalog:
            rows = catalog.list_folders(include_counts=counts)
    except MailboxError as exc:
        _print_failure(exc, debug=False, command="folders")
        raise typer.Exit(1) from exc

    _print_folder_table(rows, show_counts=counts)
    errors = [row.status_error for row in rows if row.status_error is not None]
    for error in errors:
        _print_failure(error, debug=False, command="folders")
    if errors:
        raise typer.Exit(1)


def _resolve_folder_imap_settings(
    config: Path,
    *,
    host: str | None,
    username: str | None,
    port: int | None,
) -> ImapSettings:
    direct_mode = host is not None or username is not None or port is not None
    if not direct_mode:
        return load_imap_settings(config)
    if host is None or username is None:
        raise ConfigError("direct connection mode requires both --host and --username")
    return ImapSettings(host=host, username=username, port=993 if port is None else port)


def _print_folder_table(rows: tuple[FolderInfo, ...], *, show_counts: bool) -> None:
    table = Table(title="IMAP folders")
    table.add_column("Folder")
    table.add_column("Exact IMAP name")
    table.add_column("Total", justify="right")
    table.add_column("Read", justify="right")
    table.add_column("Unread", justify="right")
    table.add_column("Role")
    table.add_column("Flags")

    roles = (
        (b"\\INBOX", "Inbox"),
        (b"\\JUNK", "Junk"),
        (b"\\TRASH", "Trash"),
        (b"\\SENT", "Sent"),
        (b"\\DRAFTS", "Drafts"),
        (b"\\ARCHIVE", "Archive"),
        (b"\\ALL", "All"),
    )
    for row in rows:
        label = row.name
        if row.delimiter:
            parts = row.name.split(row.delimiter)
            label = "  " * (len(parts) - 1) + parts[-1]
        role = ", ".join(label for flag, label in roles if flag in row.flags) or "-"
        if not show_counts or not row.selectable:
            total = read = unread = "-"
        elif row.status_error is not None or row.total is None or row.unread is None or row.read is None:
            total = read = unread = "?"
        else:
            total, read, unread = (f"{value:,}" for value in (row.total, row.read, row.unread))
        flags = " ".join(flag.decode("utf-8", errors="replace") for flag in sorted(row.flags)) or "-"
        table.add_row(Text(label), Text(row.name), total, read, unread, role, Text(flags))
    console.print(table, markup=False)


@app.command()
def doctor(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Probe each configured IMAP source and action precondition without mutating mail."""
    console.print("imapledger doctor")
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print("config: OK")

    if not settings.spam.folders:
        err_console.print("Configuration error: doctor requires at least one spam.folders source.", markup=False)
        raise typer.Exit(2)

    try:
        rules = load_rules(rules_path_for_config(config), source_folders=settings.spam.folders)
    except RuleError as exc:
        err_console.print(f"[red]Rules error:[/red] {exc}")
        raise typer.Exit(2) from exc
    try:
        _validate_config_store_cleaning(settings, rules)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    password = _resolve_password(settings.imap)

    actions = settings.spam.actions
    destinations = _move_destinations(actions, rules)
    requires_delete = any(
        action.action is ActionKind.DELETE for action in (actions.spam, actions.not_spam, actions.review)
    )
    failed = False
    doctor_operation = DoctorOperation(settings, mailbox_factory=ScopedMailbox)
    try:
        for folder in settings.spam.folders:
            console.print(f"folder: {folder} (read-only)", markup=False)
            result = doctor_operation.run(
                DoctorRequest(
                    folder=folder,
                    destinations=tuple(destinations),
                    requires_delete=requires_delete,
                    require_state_persistence=(settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS),
                    deep_probe=True,
                ),
                password=password,
                event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            )
            _print_state_preflight(result, clean_apply=False)
            if result.opened:
                console.print("source: EXISTS")
                console.print("select: OK")
                console.print("TLS connect: OK")
                console.print("login: OK")
                probe = result.probe
                if probe is not None:
                    console.print(f"UIDVALIDITY: {probe.uidvalidity}")
                    console.print(f"messages: {probe.message_count}")
                    if probe.uid_min is not None and probe.uid_max is not None:
                        console.print(f"UID range: {probe.uid_min}..{probe.uid_max}")
                    if probe.size_fetch_uid is None:
                        console.print("FETCH RFC822.SIZE (1 UID): SKIPPED (mailbox is empty)")
                    else:
                        console.print("FETCH RFC822.SIZE (1 UID): OK")
                    if probe.body_fetch_uid is not None:
                        console.print("FETCH BODY.PEEK[] (1 UID): OK")
                    else:
                        console.print(f"FETCH BODY.PEEK[]: SKIPPED ({probe.body_skip_reason})", markup=False)

                for capability, required in ((b"MOVE", bool(destinations)), (b"UIDPLUS", requires_delete)):
                    if required:
                        state = "OK" if capability in result.capabilities else "MISSING"
                        console.print(f"required capability {capability.decode()}: {state}")
                for destination, exists in result.destinations:
                    if exists is not None:
                        state = "OK" if exists else "MISSING"
                        console.print(f"destination {destination}: {state}", markup=False)
            else:
                error = result.errors[0] if result.errors else None
                operation = error.operation if isinstance(error, ImapOperationError) else None
                if operation == "imap_source_folder_missing":
                    console.print("source: MISSING")
                    console.print("select: SKIPPED")
                    console.print("destination checks: SKIPPED for this source session")
                elif operation == "imap_select_folder":
                    console.print("source: EXISTS")
                    console.print("select: FAILED")
                elif operation == "imap_source_folder_exists":
                    console.print("source: UNVERIFIED")
                    console.print("select: SKIPPED")
                else:
                    console.print("source: NOT CHECKED")
                    console.print("select: SKIPPED")

            for error in result.errors:
                _print_failure(error, debug=False, command="doctor")
            failed = failed or not result.ok

        if settings.config_store is not None:
            store = settings.config_store
            try:
                with ConfigStoreMailbox(
                    host=settings.imap.host,
                    port=settings.imap.port,
                    username=settings.imap.username,
                    password=password,
                    folder=store.folder,
                    max_file_bytes=store.max_file_bytes,
                    writable=False,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                ):
                    pass
            except ConfigStoreFolderMissingError as exc:
                err_console.print(str(exc), markup=False)
                console.print(f"config store folder: {store.folder}: MISSING", markup=False)
                failed = True
            except ConfigStoreOperationError as exc:
                _print_failure(exc, debug=False, command="doctor")
                console.print(f"config store folder: {store.folder}: FAILED", markup=False)
                failed = True
            except ConfigLedgerError as exc:
                err_console.print(f"Configuration store error: {exc}", markup=False)
                console.print(f"config store folder: {store.folder}: FAILED", markup=False)
                failed = True
            else:
                console.print(f"config store folder: {store.folder}: OK", markup=False)

    finally:
        password = ""
    if failed:
        console.print("result: IMAP read/action preflight has failures")
        raise typer.Exit(1)
    console.print("result: IMAP read/action preflight is healthy")


@app.command()
def clean(
    folder: str = typer.Argument(..., help="Source folder to process with the unified rules system"),
    apply: bool = typer.Option(False, "--apply", help="Apply routing actions; preview is the default"),
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum messages to inspect"),
    sort: MessageSort = typer.Option(MessageSort.OLDEST, "--sort", help="Mailbox-local UID ordering"),  # noqa: B008
    rule: str | None = typer.Option(None, "--rule", help="Evaluate only this rule"),
    new_run: bool = typer.Option(False, "--new-run", help="Supersede active progress and start a fresh scan"),
    retry_errors: bool = typer.Option(False, "--retry-errors", help="Retry stored errors from the matching run"),
    yes: bool = typer.Option(False, "--yes", help="Apply without confirmation"),
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Deprecated alias for rule preview/apply on one folder."""
    console.print(
        "Deprecation warning: `clean` is a compatibility alias. Use `rule preview` or `rule apply`.",
        markup=False,
    )
    _execute_rule_run(
        folder=folder,
        all_folders=False,
        apply=apply,
        limit=limit,
        rule_scope=rule,
        sort=sort,
        new_run=new_run,
        retry_errors=retry_errors,
        progress_db=progress_db,
        config=config,
        verbose=verbose,
        yes=yes,
    )


def _print_processing_message(message: ProcessedMessage, *, preview: bool) -> None:
    plan = message.plan
    states = "-"
    if plan is not None and plan.rule_results:
        states = ",".join(
            f"{result.rule_id}:{result.state.value}"
            + (f"({result.confidence:.3f})" if result.confidence is not None else "")
            for result in plan.rule_results
        )
    destination = message.destination or "-"
    rule_id = plan.winner_rule_id if plan is not None and plan.winner_rule_id is not None else "-"
    if message.outcome == "no_match":
        action = "keep-in-place"
    elif message.outcome == "already_there":
        action = "already-there"
    elif preview:
        action = "would-move" if message.destination else "keep-in-place"
    else:
        action = "moved" if message.confirmed else "not-moved"
    error = f" error={message.error_code}" if message.error_code else ""
    console.print(
        f"uid={message.uid} outcome={message.outcome} rule={rule_id} destination={destination} "
        f"evaluations={states} action={action}{error}",
        markup=False,
    )


def _progress_context(config: Path, progress_db: Path) -> ProgressOperation:
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    try:
        return ProgressOperation(settings, progress_db)
    except Exception as exc:
        _print_failure(exc, debug=False, command="progress")
        raise typer.Exit(1) from exc


@progress_app.command("list")
def progress_list(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database."),  # noqa: B008
) -> None:
    """List resumable runs for the configured IMAP account."""
    progress = _progress_context(config, progress_db)
    runs = progress.list_runs()
    table = Table(title="Routing progress")
    for column in ("Folder", "Mode", "Scope", "Sort", "Status", "Cursor", "Scanned", "Errors", "Run"):
        table.add_column(column)
    for run in runs:
        table.add_row(
            run.source_folder,
            run.mode,
            run.rule_scope or "-",
            run.sort_direction,
            run.status,
            str(run.cursor_uid) if run.cursor_uid is not None else "-",
            str(run.scanned_count),
            str(run.error_count),
            run.id,
        )
    console.print(table)
    console.print(f"database: {progress_db}", markup=False)


@progress_app.command("show")
def progress_show(
    folder: str = typer.Argument(..., help="Source folder."),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database."),  # noqa: B008
) -> None:
    """Show the most recent run for one source folder."""
    progress = _progress_context(config, progress_db)
    runs = progress.list_runs(folder=folder, limit=1000)
    if not runs:
        console.print(f"No progress recorded for {folder}.", markup=False)
        return
    run = runs[0]
    console.print(
        f"run={run.id} folder={run.source_folder} mode={run.mode} scope={run.rule_scope or '-'} "
        f"status={run.status} sort={run.sort_direction} uidvalidity={run.uidvalidity} "
        f"range=({run.lower_bound_uid},{run.high_watermark_uid}] cursor={run.cursor_uid or '-'} "
        f"scanned={run.scanned_count} matched={run.match_count} moved={run.moved_count} "
        f"no_match={run.no_match_count} errors={run.error_count}",
        markup=False,
    )
    console.print(f"database: {progress_db}", markup=False)


@progress_app.command("errors")
def progress_errors(
    folder: str = typer.Argument(..., help="Source folder."),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database."),  # noqa: B008
) -> None:
    """List retryable UID error codes from the most recent run with errors."""
    progress = _progress_context(config, progress_db)
    run = progress.latest_run_with_errors(folder)
    if run is None:
        console.print(f"No stored errors for {folder}.", markup=False)
        return
    for result in progress.errors(run.id):
        console.print(f"folder={folder} uid={result.uid} error={result.error_code or 'unknown'}", markup=False)


@progress_app.command("reset")
def progress_reset(
    folder: str = typer.Argument(..., help="Source folder."),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    progress_db: Path = typer.Option(default_progress_path(), "--progress-db", help="Progress SQLite database."),  # noqa: B008
) -> None:
    """Delete all saved progress runs for one source folder after confirmation."""
    progress = _progress_context(config, progress_db)
    runs = progress.list_runs(folder=folder, limit=1000)
    if not runs:
        console.print(f"No progress recorded for {folder}.", markup=False)
        return
    if not typer.confirm(f"Delete all progress runs for {folder}?", default=False):
        console.print("Progress reset cancelled.", markup=False)
        return
    deleted = progress.reset_folder(folder)
    console.print(f"Deleted {deleted} progress run(s) for {folder}.", markup=False)


@state_app.command("status")
def state_status(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Show persisted state counts for configured sources without fetching message bodies."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    password = _resolve_password(settings.imap)
    console.print("Classification state", markup=False)
    failed = False
    operation = StateOperation(settings, mailbox_factory=ScopedMailbox)
    try:
        for folder in settings.spam.folders:
            try:
                result = operation.status(
                    folder,
                    password=password,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                )
                console.print(
                    f"folder={folder} uidvalidity={result.uidvalidity} "
                    f"backend={result.backend.value} keyword_persistence={result.keyword_persistence} "
                    f"total={result.total} spam={result.spam} notspam={result.notspam} review={result.review} "
                    f"unclassified={result.unclassified} conflicts={result.conflicts}",
                    markup=False,
                )
            except Exception as exc:
                failed = True
                console.print(f"folder={folder} backend={settings.spam.state.backend.value} status=ERROR", markup=False)
                _print_failure(exc, debug=False, command="state")
    finally:
        password = ""
    if failed:
        raise typer.Exit(1)


@state_app.command("reset")
def state_reset(
    folder: str | None = typer.Option(None, "--folder", help="Configured source folder to reset"),
    uid: int | None = typer.Option(None, "--uid", min=1, help="Reset one exact folder-scoped UID"),
    reset_all: bool = typer.Option(False, "--all", help="Reset all marked UIDs in the selected folder scope"),
    all_folders: bool = typer.Option(False, "--all-folders", help="Include every configured source folder"),
    apply: bool = typer.Option(False, "--apply", help="Remove the selected state keywords"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Dry-run by default. Remove only imapledger state keywords from configured sources."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if uid is not None and reset_all:
        err_console.print("Usage error: --uid and --all cannot be combined.")
        raise typer.Exit(2)
    if all_folders and folder is not None:
        err_console.print("Usage error: --all-folders cannot be combined with --folder.")
        raise typer.Exit(2)
    if all_folders and not reset_all:
        err_console.print("Usage error: --all-folders requires --all.")
        raise typer.Exit(2)
    if not all_folders and folder is None:
        err_console.print("Usage error: specify --folder, or use --all-folders --all.")
        raise typer.Exit(2)
    if folder is not None and folder not in settings.spam.folders:
        err_console.print(f"Usage error: source folder is not configured: {folder}", markup=False)
        raise typer.Exit(2)
    if uid is None and not reset_all:
        err_console.print("Usage error: an unbounded reset requires --all.")
        raise typer.Exit(2)

    request = StateResetRequest(
        folder=folder,
        uid=uid,
        reset_all=reset_all,
        all_folders=all_folders,
        apply=apply,
    )
    operation = StateOperation(settings, mailbox_factory=ScopedMailbox)
    folders = operation.reset_folders(request)
    password = _resolve_password(settings.imap)
    failed = False
    try:
        for source_folder in folders:
            try:
                result = operation.reset_folder(
                    source_folder,
                    request,
                    password=password,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                )
                if uid is not None:
                    markers = dict(result.markers).get(uid, ())
                    console.print(
                        f"folder={source_folder} uid={uid} markers={','.join(markers) or 'none'} "
                        f"action={'remove' if apply else 'would remove'}",
                        markup=False,
                    )
                else:
                    console.print(
                        f"folder={source_folder} targeted_uids={len(result.targeted_uids)} "
                        f"markers={result.marker_count} action={'remove' if apply else 'would remove'}",
                        markup=False,
                    )
            except Exception as exc:
                failed = True
                _print_failure(exc, debug=False, command="state")
    finally:
        password = ""
    if failed:
        raise typer.Exit(1)
    if not apply:
        console.print("Dry-run only. Re-run with --apply to remove the listed classification keywords.")


@app.command()
def explain(
    uid: int = typer.Argument(..., help="Folder-scoped message UID"),
    folder: str = typer.Option(..., "--folder", help="Configured source folder"),
    reclassify: bool = typer.Option(False, "--reclassify", help="Run current classification even if state is stored"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Explain persisted state or the current read-only classification of one message."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if folder not in settings.spam.folders:
        err_console.print(f"Usage error: source folder is not configured: {folder}", markup=False)
        raise typer.Exit(2)
    try:
        rules = load_rules(rules_path_for_config(config), source_folders=settings.spam.folders)
    except RuleError as exc:
        err_console.print(f"[red]Rules error:[/red] {exc}")
        raise typer.Exit(2) from exc
    password = _resolve_password(settings.imap)
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            state = mailbox.classification_state(uid)
            state_label = state.outcome.value.upper() if state.outcome is not None else "UNCLASSIFIED"
            cached_state = state.outcome is not None and not reclassify
            if cached_state:
                message = mailbox.fetch_headers(uid)
                if message is None:
                    raise MailboxError("message headers are not available for explanation")
            else:
                item = mailbox.fetch_uid(uid)
                if item.message is None:
                    raise MailboxError(item.skip_reason or "message is not available for explanation")
                message = item.message
            evidence = build_message_evidence(
                message,
                trusted_authserv_ids=settings.spam.trusted_authserv_ids,
                trusted_provider_headers=settings.spam.trusted_provider_headers,
            )
            console.print(f"Folder={folder} UID={uid} persisted_state={state_label}", markup=False)
            console.print(
                f"From={_safe_text(message.sender)} Subject={_safe_text(message.subject)} "
                f"Date={_safe_text(message.date)} Message-ID={_safe_text(message.message_id)}",
                markup=False,
            )
            console.print(
                f"Normalized sender={_safe_text(evidence.from_address.address)} "
                f"domain={evidence.from_address.domain or '-'} "
                f"organizational_domain={evidence.from_address.organizational_domain or '-'}",
                markup=False,
            )
            if cached_state:
                console.print(
                    "Authentication evidence=not fetched (stored state contains only the outcome)",
                    markup=False,
                )
                console.print(
                    "Provider spam evidence=not fetched (stored state contains only the outcome)",
                    markup=False,
                )
                action = getattr(settings.spam.actions, state.outcome.value)
                console.print("Classifier: NOT RUN (pass --reclassify to evaluate current policy)", markup=False)
                console.print(f"Configured action={_action_description(action)}", markup=False)
                return
            analysis = AnalysisService(settings, rules, classifier_factory=PyJevSpamClassifier).analyze(
                folder,
                message,
                persisted_outcome=state.outcome,
                reclassify=reclassify,
                use_routing_filters=True,
            )
            evidence = analysis.evidence
            if evidence is None:
                raise MailboxError("message analysis did not return evidence")
            authentication = evidence.authentication
            console.print(
                f"Authentication trusted={authentication.trusted} authserv_id={authentication.authserv_id or '-'} "
                f"spf={authentication.spf or '-'} dkim={','.join(item.result for item in authentication.dkim) or '-'} "
                f"dmarc={authentication.dmarc or '-'} arc={authentication.arc or '-'}",
                markup=False,
            )
            provider = evidence.provider
            console.print(
                f"Provider spam_flag={provider.spam_flag} spam_status={_safe_text(provider.spam_status or '-')} "
                f"spam_score={provider.spam_score} trusted_spam={provider.trusted_spam} "
                f"spam_marker={provider.spam_marker}",
                markup=False,
            )
            if analysis.rule_id is not None:
                console.print(
                    f"Rule={analysis.rule_id} action={_action_description(analysis.configured_action)}",
                    markup=False,
                )
                console.print("Classifier: NOT RUN (a deterministic rule matches)", markup=False)
                return
            signals = analysis.signals
            if signals is None or analysis.verdict is None or analysis.outcome is None:
                raise MailboxError("message analysis did not return a classification")
            console.print(
                "Signals "
                f"bulk={signals.unsolicited_bulk:.2f} phishing={signals.phishing_or_scam:.2f} "
                f"identity={signals.identity_deception:.2f} legitimate={signals.legitimate_expected:.2f} "
                f"delete_safe={signals.delete_safe:.2f}",
                markup=False,
            )
            console.print(
                f"Policy verdict={analysis.verdict.name} reasons={','.join(analysis.reasons)}",
                markup=False,
            )
            console.print(f"Configured action={_action_description(analysis.configured_action)}", markup=False)
    except Exception as exc:
        _print_failure(exc, debug=False, command="explain")
        raise typer.Exit(1) from exc
    finally:
        password = ""


@mail_app.command("list")
def mail_list(
    folder: str = typer.Option(..., "--folder", help="Exact IMAP folder name"),
    limit: int = typer.Option(50, "--limit", min=1),
    offset: int = typer.Option(0, "--offset", min=0),
    sort: MessageSort = typer.Option(MessageSort.NEWEST, "--sort"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config"),  # noqa: B008
) -> None:
    """List a page of message headers without fetching message bodies."""
    settings = _load_auth_settings(config)
    password = _resolve_password(settings.imap)
    service = MailService(settings, password)
    try:
        page = service.list_messages(folder, limit=limit, offset=offset, sort=sort)
        title = f"{folder} | {sort.value} | {offset + 1}..{offset + len(page.items)} of {page.total}"
        table = Table(title=title)
        for column in ("State", "UID", "From", "Subject", "Date", "Size"):
            table.add_column(column)
        for item in page.items:
            state = item.persisted_state.value.upper() if item.persisted_state is not None else "?"
            if b"\\Seen" not in item.flags and "\\Seen" not in item.flags:
                state = "● " + state
            table.add_row(
                state,
                str(item.uid),
                _safe_text(item.sender),
                _safe_text(item.subject),
                _safe_text(item.date),
                str(item.size_bytes) if item.size_bytes is not None else "-",
            )
        console.print(table, markup=False)
    except Exception as exc:
        _print_failure(exc, debug=False, command="mail list")
        raise typer.Exit(1) from exc
    finally:
        service.close()
        password = ""


@mail_app.command("show")
def mail_show(
    uid: int = typer.Argument(..., help="Folder-scoped message UID"),
    folder: str = typer.Option(..., "--folder", help="Exact IMAP folder name"),
    config: Path = typer.Option(default_config_path(), "--config"),  # noqa: B008
) -> None:
    """Read one message using BODY.PEEK without marking it seen."""
    settings = _load_auth_settings(config)
    password = _resolve_password(settings.imap)
    service = MailService(settings, password)
    try:
        detail = service.get_message(folder, uid)
        message = detail.item.message
        if message is None:
            raise MailboxError(detail.item.skip_reason or "message is not available")
        console.print(f"Folder: {folder}\nUID: {uid}", markup=False)
        console.print(f"From: {_safe_text(message.sender)}", markup=False)
        console.print(f"To: {_safe_text(', '.join(message.recipients))}", markup=False)
        console.print(f"Date: {_safe_text(message.date)}", markup=False)
        console.print(f"Subject: {_safe_text(message.subject)}", markup=False)
        console.print(f"Message-ID: {_safe_text(message.message_id)}", markup=False)
        console.print(message.body, markup=False)
        state = detail.persisted_state.outcome.value.upper() if detail.persisted_state else "UNCLASSIFIED"
        console.print(f"State: {state}", markup=False)
        console.print(f"Body source: {message.body_source}", markup=False)
        if message.body_truncated:
            console.print(f"Body truncated at max_body_chars={settings.spam.max_body_chars}.", markup=False)
        if message.has_attachments:
            console.print(f"Attachments: {message.attachment_count} (not opened by imapledger)", markup=False)
        if detail.persisted_state and detail.persisted_state.outcome:
            outcome = detail.persisted_state.outcome
            action = action_for_outcome(settings, outcome)
            console.print(f"Persisted category: {outcome.value.upper()}", markup=False)
            console.print(f"Configured action: {_action_description(action)}", markup=False)
        clean_scope = "enabled" if folder in settings.spam.folders else "disabled"
        console.print(f"Batch clean for this folder: {clean_scope}", markup=False)
    except Exception as exc:
        _print_failure(exc, debug=False, command="mail show")
        raise typer.Exit(1) from exc
    finally:
        service.close()
        password = ""


@mail_app.command("classify")
def mail_classify(
    uid: int = typer.Argument(..., help="Folder-scoped message UID"),
    folder: str = typer.Option(..., "--folder", help="Any selectable mailbox folder containing the UID"),
    apply: bool = typer.Option(False, "--apply", help="Apply the category's configured action to this exact message"),
    reclassify: bool = typer.Option(False, "--reclassify", help="Ignore persisted state and classify again"),
    config: Path = typer.Option(default_config_path(), "--config"),  # noqa: B008
) -> None:
    """Classify one message in any folder; --apply uses its configured category action."""
    settings = _load_auth_settings(config)
    try:
        rules = load_rules(rules_path_for_config(config), source_folders=settings.spam.folders)
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    password = _resolve_password(settings.imap)
    mail_service = MailService(settings, password)
    try:
        detail = mail_service.get_message(folder, uid)
        message = detail.item.message
        if message is None:
            raise MailboxError(detail.item.skip_reason or "message is not available")
        persisted = detail.persisted_state.outcome if detail.persisted_state is not None else None
        analysis = AnalysisService(settings, rules, classifier_factory=PyJevSpamClassifier).analyze(
            folder,
            message,
            persisted_outcome=persisted,
            reclassify=reclassify,
            use_routing_filters=False,
        )
        console.print(f"Outcome: {analysis.outcome.value.upper() if analysis.outcome else 'RULE'}", markup=False)
        console.print(f"Decision source: {analysis.decision_source}", markup=False)
        if analysis.rule_id:
            console.print(f"Rule: {analysis.rule_id}", markup=False)
        if analysis.reasons:
            console.print(f"Reasons: {', '.join(analysis.reasons)}", markup=False)
        if analysis.configured_action:
            console.print(f"Action: {_action_description(analysis.configured_action)}", markup=False)
        if not apply:
            console.print("Result: Not applied (preview)", markup=False)
            return
        receipt = ActionService(settings, password).apply(
            analysis,
            uidvalidity=detail.uidvalidity,
            confirmed_by_user=True,
        )
        result = "Applied and confirmed" if receipt.applied and receipt.confirmed else "Not applied"
        console.print(f"Result: {result}", markup=False)
        if receipt.detail:
            console.print(receipt.detail, markup=False)
    except Exception as exc:
        _print_failure(exc, debug=False, command="mail classify")
        raise typer.Exit(1) from exc
    finally:
        mail_service.close()
        password = ""


@app.command("ui")
def ui(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Launch the interactive terminal mail review console."""
    from .tui.app import run

    run(config)


@review_app.command("list")
def review_list(
    folder: str | None = typer.Option(None, "--folder", help="Configured source folder; default is all sources"),
    limit: int | None = typer.Option(None, "--limit", min=1, help="Maximum review rows per source"),
    offset: int = typer.Option(0, "--offset", min=0, help="Skip review rows per source"),
    sort: MessageSort = typer.Option(MessageSort.NEWEST, "--sort", help="Order by mailbox UID"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """List review-marked messages using a bounded header-only fetch."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if folder is not None and folder not in settings.spam.folders:
        err_console.print(f"Usage error: source folder is not configured: {folder}", markup=False)
        raise typer.Exit(2)
    password = _resolve_password(settings.imap)
    table = Table(title="Review queue")
    for column in ("Folder", "UID", "From", "Subject", "Date", "Message-ID"):
        table.add_column(column)
    operation = ReviewOperation(settings, mailbox_factory=ScopedMailbox)
    request = ReviewRequest(folder=folder, limit=limit, offset=offset, sort=sort)
    try:
        page = operation.run(
            request,
            password=password,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        )
        for _, exc in page.errors:
            _print_failure(exc, debug=False, command="review")
        for source_folder, message in page.items:
            table.add_row(
                source_folder,
                str(message.uid),
                _safe_text(message.sender),
                _safe_text(message.subject),
                _safe_text(message.date),
                _safe_text(message.message_id),
            )
    finally:
        password = ""
    console.print(table, markup=False)
    if page.errors:
        raise typer.Exit(1)


def _present_state_keywords(flags: Iterable[bytes | str]) -> tuple[str, ...]:
    normalized = {
        flag.decode("ascii", errors="replace").casefold() if isinstance(flag, bytes) else flag.casefold()
        for flag in flags
    }
    return tuple(keyword for keyword in all_state_keywords() if keyword.casefold() in normalized)


def _keyword_persistence_label(backend: ClassificationStateBackend, snapshot: MailboxSnapshot) -> str:
    if backend is ClassificationStateBackend.NONE:
        return "NOT CONFIGURED"
    if not snapshot.permanent_flags_known:
        return "UNKNOWN"
    if all(snapshot.supports_persistent_keyword(keyword) for keyword in all_state_keywords()):
        return "OK"
    return "UNSUPPORTED"


def _action_description(action: MessageAction) -> str:
    if action.action is ActionKind.KEEP:
        return "keep"
    if action.action is ActionKind.MOVE:
        return f"move -> {action.destination}"
    return "delete"


def _selection_summary(
    *,
    folder: str,
    total_messages: int,
    selected_count: int,
    selection: MessageSelection,
    unclassified_count: int | None = None,
) -> str:
    limit = "all" if selection.limit is None else str(selection.limit)
    unclassified = f" unclassified={unclassified_count}" if unclassified_count is not None else ""
    return (
        f"folder={folder} messages={total_messages}{unclassified} selected={selected_count} "
        f"sort={selection.sort.value} offset={selection.offset} limit={limit}"
    )


def _print_state_preflight(result, *, clean_apply: bool) -> None:
    console.print(f"classification state backend: {result.state_backend.value}")
    if result.permanent_flags_known:
        flags = " ".join(flag.decode("utf-8", errors="replace") for flag in sorted(result.permanent_flags)) or "-"
        console.print(f"PERMANENTFLAGS: {flags}", markup=False)
    else:
        console.print("PERMANENTFLAGS: UNKNOWN")
    if result.keyword_persistence == "supported":
        console.print("custom keyword persistence: OK")
    elif result.keyword_persistence == "unsupported":
        missing = ", ".join(result.unsupported_keywords)
        console.print(f"custom keyword persistence: UNSUPPORTED ({missing})", markup=False)
    elif result.keyword_persistence == "unknown":
        message = "custom keyword persistence: UNKNOWN in read-only probe"
        if clean_apply:
            message += "; writable source session will verify before classification"
        console.print(message, markup=False)
    else:
        console.print("custom keyword persistence: NOT CONFIGURED")


def _move_destinations(actions: SpamActions, rules: RuleSet | None = None) -> tuple[str, ...]:
    destinations = [
        action.destination
        for action in (actions.spam, actions.not_spam, actions.review)
        if action.action is ActionKind.MOVE and action.destination is not None
    ]
    if rules is not None:
        destinations.extend(rules.move_destinations())
    return tuple(dict.fromkeys(destinations))


def _validate_config_store_cleaning(settings: Settings, rules: RuleSet) -> None:
    store = settings.config_store
    if store is None:
        return
    if store.folder in settings.spam.folders:
        raise ConfigError("config-store folder must not be a spam source folder")
    if store.folder in _move_destinations(settings.spam.actions, rules):
        raise ConfigError("config-store folder must not be a cleaning move destination")


def _signal_summary(row: MessageResult) -> str:
    if row.signals is None:
        return "-"
    signals = row.signals
    return (
        f"bulk={signals.unsolicited_bulk:.2f} phishing={signals.phishing_or_scam:.2f} "
        f"identity={signals.identity_deception:.2f} legit={signals.legitimate_expected:.2f} "
        f"delete={signals.delete_safe:.2f}"
    )


def _safe_text(value: str) -> str:
    return redact_urls(value)[:200]


def _state_display(row: MessageResult, *, apply: bool) -> str:
    if row.state_source != "imap-keyword":
        return "-"
    if row.state_persisted:
        return "STORED"
    return "NOT CONFIRMED" if apply else "NOT STORED"


def _print_result(
    row: MessageResult,
    *,
    folder: str,
    position: int,
    total: int,
    apply: bool,
    verbose: bool = True,
) -> None:
    action = _final_action_label(row, apply=apply)
    if not verbose:
        outcome = row.outcome.value.upper() if row.outcome is not None else row.status.upper()
        details = f" | {row.detail}" if row.detail else ""
        console.print(
            (
                f"[{position}/{total}] {outcome} | {action} | {_safe_text(row.sender)} | "
                f"{_safe_text(row.subject)}{details}"
            ),
            markup=False,
        )
        return
    if row.matched_rule_id is not None:
        details = f"  Detail={row.detail}" if row.detail else ""
        console.print(
            f"[{position}/{total}] Folder={folder} UID {row.uid}  Action={action}  Rule={row.matched_rule_id}  "
            f"From={_safe_text(row.sender)}  Subject={_safe_text(row.subject)}{details}",
            markup=False,
        )
        return
    reasons = ",".join(row.reasons) or (row.detail or "-")
    verdict = row.verdict.name if row.verdict else "-"
    outcome = row.outcome.value.upper() if row.outcome else "-"
    state = _state_display(row, apply=apply)
    state_text = f"  State={state}" if state != "-" else ""
    details = f"  Detail={row.detail}" if row.detail else ""
    console.print(
        f"[{position}/{total}] Folder={folder} UID {row.uid}  {action}  Outcome={outcome}  Verdict={verdict}"
        f"{state_text}  Signals={_signal_summary(row)}  Reasons={reasons}  "
        f"From={_safe_text(row.sender)}  Subject={_safe_text(row.subject)}{details}",
        markup=False,
    )


def _classification_action_label(row: MessageResult, *, apply: bool) -> str:
    if row.status == "error":
        return "ERROR / KEEP"
    if row.status == "skip":
        return "SKIP / KEEP"
    if row.action.action is ActionKind.KEEP:
        return "KEEP"
    if row.action.action is ActionKind.MOVE:
        prefix = "MOVE" if apply else "WOULD MOVE"
        return f"{prefix} -> {row.action.destination}"
    return "DELETE" if apply else "WOULD DELETE"


def _final_action_label(row: MessageResult, *, apply: bool) -> str:
    if row.status == "error":
        return "ERROR / KEEP"
    if row.status == "skip":
        return "SKIP / KEEP"
    if row.action.action is ActionKind.KEEP:
        return "KEEP"
    if not apply:
        return _classification_action_label(row, apply=False)
    if row.action_applied:
        if row.action.action is ActionKind.MOVE:
            return f"MOVED -> {row.action.destination}"
        return "DELETED"
    if row.detail and "not attempted" in row.detail:
        if row.action.action is ActionKind.MOVE:
            return f"MOVE NOT ATTEMPTED -> {row.action.destination}"
        return "DELETE NOT ATTEMPTED"
    if row.action.action is ActionKind.MOVE:
        return f"MOVE NOT CONFIRMED -> {row.action.destination}"
    return "DELETE NOT CONFIRMED"


def _action_summary(report: CleanReport) -> str:
    counts: dict[tuple[ActionKind, str | None], int] = {}
    for row in report.results:
        if row.action.action is ActionKind.KEEP:
            continue
        if row.decision_source != "rule" and row.outcome is None:
            continue
        if report.apply and not row.action_applied:
            continue
        key = (row.action.action, row.action.destination)
        counts[key] = counts.get(key, 0) + 1

    actions = []
    for (kind, destination), count in counts.items():
        if kind is ActionKind.MOVE:
            verb = "moved" if report.apply else "would move"
            actions.append(f"{verb} {count} -> {destination}")
        else:
            verb = "deleted" if report.apply else "would delete"
            actions.append(f"{verb} {count}")
    actions.append(f"kept {report.kept_in_place}")
    return "Actions: " + "; ".join(actions) + "."


def _print_summary(report: CleanReport) -> None:
    state_summary = (
        f"; state_stored={report.state_stored}"
        if any(row.state_source == "imap-keyword" for row in report.results)
        else ""
    )
    console.print(
        f"Scanned {report.scanned}; rules {report.rule_matches}; spam {report.spam}; "
        f"not-spam {report.not_spam}; review {report.review}; "
        f"skipped {report.skipped}; errors {report.errors}{state_summary}."
    )
    console.print(_action_summary(report))
    if not report.apply:
        console.print("Dry-run only. Re-run with --apply to execute configured actions.")
    if report.partial_move_error is not None:
        console.print(
            f"Partial move to {report.partial_move_error.destination}: "
            f"{len(report.partial_move_error.moved)} confirmed; "
            f"{len(report.partial_move_error.pending)} pending."
        )
    if report.partial_delete_error is not None:
        console.print(
            f"Partial deletion: {len(report.partial_delete_error.deleted)} confirmed; "
            f"{len(report.partial_delete_error.pending)} pending."
        )


def _print_aggregate_summary(reports: list[CleanReport]) -> None:
    state_summary = (
        f"; state_stored={sum(report.state_stored for report in reports)}"
        if any(row.state_source == "imap-keyword" for report in reports for row in report.results)
        else ""
    )
    console.print(
        f"Aggregate across {len(reports)} folders (UIDs remain folder-scoped): "
        f"scanned {sum(report.scanned for report in reports)}; "
        f"rules {sum(report.rule_matches for report in reports)}; "
        f"spam {sum(report.spam for report in reports)}; "
        f"not-spam {sum(report.not_spam for report in reports)}; "
        f"review {sum(report.review for report in reports)}; "
        f"skipped {sum(report.skipped for report in reports)}; "
        f"errors {sum(report.errors for report in reports)}; "
        f"moved {sum(report.moved for report in reports)}; "
        f"deleted {sum(report.deleted for report in reports)}; "
        f"kept {sum(report.kept_in_place for report in reports)}{state_summary}."
    )


def _print_failure(exc: Exception, *, debug: bool, command: str | None = None) -> None:
    if isinstance(exc, ImapOperationError):
        err_console.print(str(exc), markup=False)
        if exc.operation == "imap_source_folder_missing":
            err_console.print(
                "hint: verify the exact mailbox name in spam.folders; imapledger does not create source folders"
            )
        elif exc.operation == "imap_select_folder":
            err_console.print(
                "hint: the mailbox exists but SELECT/EXAMINE failed; "
                "check mailbox flags, permissions, and exact server-side naming"
            )
        elif exc.operation == "imap_source_folder_exists":
            err_console.print(
                "hint: could not verify the exact configured source name; "
                "check server mailbox metadata access and permissions"
            )
        elif command not in {"doctor", "folders"}:
            err_console.print("hint: run imapledger doctor --verbose")
    elif isinstance(exc, MailboxError):
        err_console.print(f"{type(exc).__name__}: {exc}", markup=False)
    else:
        err_console.print(f"{type(exc).__name__}: operation failed")

    if debug:
        err_console.print("Traceback (most recent call last):")
        for frame in traceback.extract_tb(exc.__traceback__):
            err_console.print(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}', markup=False)
        cause = exc.__cause__ or exc.__context__
        while cause is not None:
            err_console.print(f"Caused by: {type(cause).__name__}")
            cause = cause.__cause__ or cause.__context__


def _print_report(report: CleanReport) -> None:
    table = Table(title=f"imapledger | {report.folder} ({'APPLY' if report.apply else 'DRY RUN'})")
    table.add_column("Source")
    table.add_column("UID", justify="right")
    table.add_column("Outcome")
    table.add_column("Verdict")
    table.add_column("Signals")
    table.add_column("Reasons")
    table.add_column("Action")
    table.add_column("State")
    table.add_column("Rule")
    table.add_column("From")
    table.add_column("Subject")
    table.add_column("Detail")
    for row in report.results:
        table.add_row(
            report.folder,
            str(row.uid),
            row.outcome.value.upper() if row.outcome else "-",
            row.verdict.name if row.verdict else "-",
            _signal_summary(row),
            ",".join(row.reasons) or "-",
            _final_action_label(row, apply=report.apply),
            _state_display(row, apply=report.apply),
            row.matched_rule_id or "-",
            _safe_text(row.sender),
            _safe_text(row.subject),
            row.detail or "",
        )
    console.print(table, markup=False)
    _print_summary(report)
