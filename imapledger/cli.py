from __future__ import annotations

import getpass
import traceback
from dataclasses import replace
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .application.doctor import DoctorOperation, DoctorRequest
from .application.progress import ProgressOperation
from .application.rule_run import RuleEvaluationOperation, RuleRunOperation, RuleRunRequest
from .application.rules import RuleLearningOperation, RuleMigrationOperation
from .config import (
    AuthSource,
    ConfigError,
    ImapSettings,
    Settings,
    default_config_path,
    load_imap_settings,
    load_legacy_settings_for_migration,
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
from .evidence import redact_urls
from .mailbox import (
    FolderCatalog,
    FolderInfo,
    ImapOperationError,
    MailboxError,
    MessageSort,
    ScopedMailbox,
)
from .processing_engine import ProcessedMessage, ProcessingError
from .progress_store import ProgressStoreError, default_progress_path
from .routing_actions import RuleAction
from .routing_config import (
    RoutingConfigError,
    load_routing_rules,
    routing_rules_path_for_config,
    write_routing_rules,
)
from .routing_models import RoutingRule, RuleEvidenceSettings, RuleType
from .routing_models import RuleSet as RoutingRuleSet
from .routing_rule_service import RoutingRuleService
from .rule_recipes import get_recipe, list_recipes, materialize_recipe
from .rules import RuleMatch, describe_match

app = typer.Typer(no_args_is_help=True, help="Manage IMAP connections and ordered mail rules.")
config_app = typer.Typer(help="Inspect imapledger configuration.")
app.add_typer(config_app, name="config")
auth_app = typer.Typer(help="Store and inspect IMAP credentials.")
app.add_typer(auth_app, name="auth")
rule_app = typer.Typer(help="Manage ordered mail rules and their actions.")
app.add_typer(rule_app, name="rule")
recipe_app = typer.Typer(help="Discover and add rules from the shared recipe catalog.")
rule_app.add_typer(recipe_app, name="recipe")
progress_app = typer.Typer(help="Inspect and reset resumable routing progress.")
app.add_typer(progress_app, name="progress")
mail_app = typer.Typer(help="Deprecated category-classification commands.")
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
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"config: {config}", markup=False)
    console.print(render_settings(settings), markup=False)


@app.command("init")
def init_config(
    host: str = typer.Option(..., prompt=True, help="IMAP host"),
    username: str = typer.Option(..., prompt=True, help="IMAP username"),
    port: int = typer.Option(993, help="IMAPS port"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config"),
) -> None:
    """Write connection and authentication settings without creating mail rules."""
    try:
        path = write_settings(
            Settings(imap=ImapSettings(host=host, port=port, username=username)),
            config,
            overwrite=force,
        )
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Connection configuration written: {path}", markup=False)
    console.print("No mail rules are configured.", markup=False)
    console.print("Run `imapledger rule recipe list` or open `imapledger ui` to add rules.", markup=False)


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



def _safe_text(value: str) -> str:
    return redact_urls(value)[:200]

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


def _legacy_config_migration(
    config: Path,
    *,
    apply: bool,
    allow_delete: bool,
) -> bool:
    if not config.exists():
        return False
    settings, legacy = load_legacy_settings_for_migration(config)
    if legacy is None:
        return False

    rules_path = routing_rules_path_for_config(config)
    source_schema = 4
    try:
        rules = load_routing_rules(rules_path)
    except RoutingConfigError:
        migration = RuleMigrationOperation(rules_path).preview().result
        rules = migration.rules
        source_schema = migration.source_schema

    warnings: list[str] = []
    rules_list = list(rules.rules)
    spam_action = legacy.actions.get("spam")
    if spam_action is not None:
        options = {
            target: legacy.policy[source]
            for source, target in (
                ("legitimate_veto_at", "legitimate_veto_at"),
                ("phishing_delete_at", "phishing_match_at"),
                ("identity_deception_at", "identity_deception_at"),
                ("unsolicited_bulk_at", "unsolicited_bulk_at"),
                ("delete_safe_at", "action_safe_at"),
                ("provider_junk_support_at", "provider_junk_support_at"),
            )
            if source in legacy.policy
        }
        existing_index = next((index for index, rule in enumerate(rules_list) if rule.id == "spam"), None)
        existing = rules_list[existing_index] if existing_index is not None else None
        if existing is not None and (existing.type is not RuleType.RECIPE or existing.recipe != "spam"):
            raise RoutingConfigError(
                "cannot migrate legacy Spam settings because rule ID 'spam' is already used by another rule"
            )
        if existing is not None:
            options = {**dict(existing.options), **options}
        migrated_rule = materialize_recipe(
            "spam",
            rule_id="spam",
            action=spam_action.action,
            destination=spam_action.destination,
            options=options,
            source_folders=legacy.folders,
            match_any=existing.match_any if existing is not None else (),
        )
        if existing is None:
            rules_list.insert(0, migrated_rule)
        else:
            rules_list[existing_index] = replace(migrated_rule, enabled=existing.enabled)
        if legacy.folders:
            warnings.append(
                "The old global spam.folders restriction was converted into this rule's source_folders. "
                "Remove source_folders if you want Spam detection globally."
            )
        if spam_action.action is RuleAction.DELETE:
            warnings.append("Migration creates a destructive DELETE rule and requires --allow-delete with --apply.")
        elif spam_action.action is RuleAction.KEEP:
            warnings.append("The migrated Spam recipe uses terminal KEEP and may prevent later rules from matching.")
    else:
        warnings.append("No Spam recipe rule was created because no legacy spam action was configured.")

    if "not_spam" in legacy.actions or "review" in legacy.actions:
        warnings.append(
            "Legacy not_spam/review category actions are not migrated automatically. "
            "A Spam recipe only acts on positive Spam matches. "
            "Create separate ordinary rules for any desired non-Spam routing behavior."
        )

    evidence = RuleEvidenceSettings(
        trusted_authserv_ids=tuple(
            dict.fromkeys((*rules.evidence.trusted_authserv_ids, *legacy.trusted_authserv_ids))
        ),
        trusted_provider_headers=tuple(
            dict.fromkeys((*rules.evidence.trusted_provider_headers, *legacy.trusted_provider_headers))
        ),
    )
    migrated_rules = RoutingRuleSet(
        rules=tuple(rules_list),
        default_match_at=rules.default_match_at,
        evidence=evidence,
    )
    if apply and spam_action is not None and spam_action.action is RuleAction.DELETE and not allow_delete:
        raise RoutingConfigError(
            "migration creates a destructive DELETE rule; re-run with --apply --allow-delete"
        )

    console.print(f"legacy config: {config}", markup=False)
    console.print(f"rules: {rules_path}", markup=False)
    console.print(f"schema: {source_schema} -> 4", markup=False)
    console.print(f"converted rules: {len(migrated_rules.rules)}", markup=False)
    for warning in warnings:
        console.print(f"warning: {warning}", markup=False)
    if apply:
        write_routing_rules(migrated_rules, rules_path)
        write_settings(settings, config, overwrite=True)
        console.print("Migration applied.", markup=False)
    else:
        console.print(
            "Preview only. Re-run with --apply to write schema-4 rules and remove [spam] from config.",
            markup=False,
        )
    return True


@rule_app.command("migrate")
def rule_migrate(
    apply: bool = typer.Option(False, "--apply", help="Write the schema-4 conversion to config and rules."),
    preview: bool = typer.Option(False, "--preview", help="Preview the conversion without writing."),
    allow_delete: bool = typer.Option(False, "--allow-delete", help="Authorize migration that creates a DELETE rule"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Explicitly migrate legacy configuration and routing rules to schema 4."""
    if apply and preview:
        err_console.print("Usage error: --preview and --apply cannot be combined.")
        raise typer.Exit(2)
    if allow_delete and not apply:
        raise typer.BadParameter("--allow-delete requires --apply")
    path = routing_rules_path_for_config(config)
    try:
        if _legacy_config_migration(config, apply=apply, allow_delete=allow_delete):
            return
        operation = RuleMigrationOperation(path)
        preview_result = operation.preview()
        result = operation.apply(preview_result, allow_delete=allow_delete) if apply else preview_result.result
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"rules: {path}", markup=False)
    console.print(f"schema: {result.source_schema} -> 4", markup=False)
    console.print(f"converted rules: {len(result.rules.rules)}", markup=False)
    for warning in result.warnings:
        console.print(f"warning: {warning}", markup=False)
    console.print(
        "Migration applied." if apply else "Preview only. Re-run with --apply to write schema-4 rules.",
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




def _parse_recipe_options(values: list[str]) -> dict[str, float]:
    options: dict[str, float] = {}
    for value in values:
        key, separator, raw_value = value.partition("=")
        if not separator or not key or not raw_value:
            raise typer.BadParameter("recipe options must use key=value")
        if key in options:
            raise typer.BadParameter(f"duplicate recipe option: {key}")
        try:
            options[key] = float(raw_value)
        except ValueError as exc:
            raise typer.BadParameter(f"recipe option {key} must be numeric") from exc
    return options


@recipe_app.command("list")
def recipe_list(
    category: str | None = typer.Option(None, "--category", help="Filter by category"),
    search: str | None = typer.Option(None, "--search", help="Search recipe names and descriptions"),
) -> None:
    """List the shared rule recipe catalog."""
    recipes = list_recipes(category=category, search=search)
    if not recipes:
        console.print("No recipes found.", markup=False)
        return
    table = Table(title="Rule recipes")
    for column in ("ID", "Title", "Category", "Rule type", "Action", "Model", "Summary"):
        table.add_column(column)
    for recipe in recipes:
        table.add_row(
            recipe.id,
            recipe.title,
            recipe.category,
            recipe.produces_type.value,
            recipe.default_action.value,
            "yes" if recipe.uses_model else "no",
            recipe.summary,
        )
    console.print(table, markup=False)


@recipe_app.command("show")
def recipe_show(recipe_id: str = typer.Argument(..., help="Recipe ID")) -> None:
    """Show recipe behavior, defaults, and configurable options."""
    try:
        recipe = get_recipe(recipe_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"id: {recipe.id}", markup=False)
    console.print(f"title: {recipe.title}", markup=False)
    console.print(f"category: {recipe.category}", markup=False)
    console.print(f"description: {recipe.description}", markup=False)
    console.print(f"produces: {recipe.produces_type.value}", markup=False)
    console.print(f"recommended action: {recipe.default_action.value}", markup=False)
    console.print(f"model evaluation: {'yes' if recipe.uses_model else 'no'}", markup=False)
    if recipe.runtime_recipe is not None:
        console.print(f"runtime recipe: {recipe.runtime_recipe}", markup=False)
    if recipe.options_schema:
        console.print("options:", markup=False)
        for option in recipe.options_schema:
            console.print(f"  {option.key}={option.default:g}: {option.description}", markup=False)
    else:
        console.print("options: none", markup=False)


@recipe_app.command("add")
def recipe_add(
    recipe_id: str = typer.Argument(..., help="Recipe ID to materialize"),
    rule_id: str | None = typer.Option(None, "--id", help="Rule ID; defaults to the recipe's suggested ID"),
    action: RuleAction | None = typer.Option(None, "--action", help="Override the recommended action"),  # noqa: B008
    destination: str | None = typer.Option(None, "--destination", help="Destination for MOVE actions"),
    description: str | None = typer.Option(None, "--description", help="Override the recipe description"),
    matcher_values: list[str] = typer.Option([], "--match", help="Matcher field=value; repeat for OR alternatives"),  # noqa: B008
    source_folders: list[str] = typer.Option([], "--source-folder", help="Restrict rule scope; repeatable"),  # noqa: B008
    match_at: float | None = typer.Option(None, "--match-at", min=0, max=1, help="Semantic match threshold"),
    option_values: list[str] = typer.Option([], "--option", help="Recipe option key=value; repeatable"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Materialize a catalog recipe as an ordinary ordered rule."""
    try:
        rule = materialize_recipe(
            recipe_id,
            rule_id=rule_id,
            action=action,
            destination=destination,
            description=description,
            match_at=match_at,
            options=_parse_recipe_options(option_values),
            source_folders=tuple(source_folders),
            match_any=_parse_rule_matchers(matcher_values),
        )
        result = RoutingRuleService(routing_rules_path_for_config(config)).add(rule)
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"Added rule {result.changed_rule_id} from recipe {recipe_id}", markup=False)

@rule_app.command("list")
def rule_list(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """List ordered rules without connecting to IMAP."""
    rules = _load_routing_rules_for_cli(config)
    if not rules.rules:
        console.print("No mail rules are configured. No automatic mail actions will run.", markup=False)
        return
    table = Table(title="Ordered mail rules")
    for column in ("Order", "Enabled", "ID", "Type", "Recipe", "Action", "Destination", "Scope"):
        table.add_column(column)
    for order, rule in enumerate(rules.rules, start=1):
        table.add_row(
            str(order),
            "yes" if rule.enabled else "no",
            rule.id,
            rule.type.value,
            rule.recipe or "-",
            rule.action.value.upper(),
            rule.destination or "-",
            ", ".join(rule.source_folders) if rule.source_folders else "All folders",
        )
    console.print(table, markup=False)

@rule_app.command("show")
def rule_show(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Show one ordinary routing rule without connecting to IMAP."""
    rules = _load_routing_rules_for_cli(config)
    rule = next((item for item in rules.rules if item.id == rule_id), None)
    if rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    console.print(f"id: {rule.id}", markup=False)
    console.print(f"enabled: {str(rule.enabled).lower()}", markup=False)
    console.print(f"type: {rule.type.value}", markup=False)
    if rule.recipe is not None:
        console.print(f"recipe: {rule.recipe}", markup=False)
    console.print(f"action: {rule.action.value}", markup=False)
    console.print(f"destination: {rule.destination or '-'}", markup=False)
    console.print(f"scope: {', '.join(rule.source_folders) if rule.source_folders else 'all folders'}", markup=False)
    if rule.description is not None:
        console.print(f"description: {_safe_text(rule.description)}", markup=False)
    if rule.options:
        console.print(f"options: {dict(rule.options)}", markup=False)
    if rule.match_any:
        console.print("match any:", markup=False)
        for matcher in rule.match_any:
            console.print(f"  - {describe_match(matcher)}", markup=False)

@rule_app.command("add")
def rule_add(
    rule_id: str = typer.Argument(..., help="New rule ID"),
    rule_type: RuleType = typer.Option(..., "--type", help="Rule type: semantic, header, or recipe"),  # noqa: B008
    action: RuleAction = typer.Option(RuleAction.MOVE, "--action", help="Action: move, keep, or delete"),  # noqa: B008
    destination: str | None = typer.Option(None, "--destination", help="Destination for MOVE actions"),
    description: str | None = typer.Option(None, "--description", help="Semantic rule description"),
    recipe: str | None = typer.Option(None, "--recipe", help="Runtime recipe ID for recipe rules"),
    matcher_values: list[str] = typer.Option([], "--match", help="Matcher field=value; repeat for OR alternatives"),  # noqa: B008
    source_folders: list[str] = typer.Option([], "--source-folder", help="Restrict rule scope; repeatable"),  # noqa: B008
    match_at: float | None = typer.Option(None, "--match-at", min=0, max=1, help="Semantic match threshold"),
    option_values: list[str] = typer.Option([], "--option", help="Recipe option key=value; repeatable"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Add an ordinary semantic, header, or recipe rule."""
    try:
        rule = RoutingRule(
            id=rule_id,
            enabled=True,
            type=rule_type,
            action=action,
            destination=destination,
            description=description,
            recipe=recipe,
            options=_parse_recipe_options(option_values),
            match_at=match_at,
            source_folders=tuple(source_folders),
            match_any=_parse_rule_matchers(matcher_values),
        )
        result = RoutingRuleService(routing_rules_path_for_config(config)).add(rule)
    except (RoutingConfigError, ValueError) as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(f"Added rule {result.changed_rule_id}", markup=False)


@rule_app.command("move")
def rule_move(
    rule_id: str = typer.Argument(..., help="Rule ID to reorder"),
    direction: str = typer.Argument(..., help="Move up or down by one position"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Move a rule one position in the first-match-wins order."""
    if direction not in {"up", "down"}:
        raise typer.BadParameter("direction must be 'up' or 'down'")
    try:
        result = RoutingRuleService(routing_rules_path_for_config(config)).move(
            rule_id,
            -1 if direction == "up" else 1,
        )
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print(result.detail, markup=False)

@rule_app.command("edit")
def rule_edit(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    action: RuleAction | None = typer.Option(None, "--action", help="Replace the configured action"),  # noqa: B008
    destination: str | None = typer.Option(None, "--destination", help="Destination for MOVE actions"),
    clear_destination: bool = typer.Option(False, "--clear-destination", help="Clear the existing destination"),
    description: str | None = typer.Option(None, "--description", help="Replace the rule description"),
    recipe: str | None = typer.Option(None, "--recipe", help="Replace the runtime recipe ID"),
    matcher_values: list[str] = typer.Option([], "--match", help="Replace matchers; repeat for OR alternatives"),  # noqa: B008
    source_folders: list[str] = typer.Option([], "--source-folder", help="Replace source scope; repeatable"),  # noqa: B008
    global_scope: bool = typer.Option(False, "--global", help="Make the rule apply to all folders"),
    match_at: float | None = typer.Option(None, "--match-at", min=0, max=1, help="Semantic match threshold"),
    option_values: list[str] = typer.Option([], "--option", help="Replace recipe options with key=value values"),  # noqa: B008
    enable: bool = typer.Option(False, "--enable", help="Enable the rule"),
    disable: bool = typer.Option(False, "--disable", help="Disable the rule"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Edit any ordinary rule without connecting to IMAP."""
    if enable and disable:
        raise typer.BadParameter("--enable and --disable cannot be combined")
    service = RoutingRuleService(routing_rules_path_for_config(config))
    try:
        rules = service.load()
        current = next((item for item in rules.rules if item.id == rule_id), None)
        if current is None:
            raise RoutingConfigError(f"rule not found: {rule_id}")
        selected_action = action or current.action
        if clear_destination and destination is not None:
            raise RoutingConfigError("--clear-destination cannot be combined with --destination")
        selected_destination = destination if destination is not None else current.destination
        if selected_action is not RuleAction.MOVE or clear_destination:
            selected_destination = None
        matchers = _parse_rule_matchers(matcher_values) if matcher_values else current.match_any
        scope = () if global_scope else (tuple(source_folders) if source_folders else current.source_folders)
        replacement = RoutingRule(
            id=current.id,
            enabled=False if disable else (True if enable else current.enabled),
            type=current.type,
            action=selected_action,
            destination=selected_destination,
            description=description if description is not None else current.description,
            recipe=recipe if recipe is not None else current.recipe,
            options=_parse_recipe_options(option_values) if option_values else current.options,
            match_at=match_at if match_at is not None else current.match_at,
            match_any=matchers,
            source_folders=scope,
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
    """Remove any locally stored rule without connecting to IMAP."""
    service = RoutingRuleService(routing_rules_path_for_config(config))
    try:
        rules = service.load()
        if not any(rule.id == rule_id for rule in rules.rules):
            raise RoutingConfigError(f"rule not found: {rule_id}")
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
    allow_delete: bool = False,
    yes: bool = False,
) -> None:
    if all_folders == (folder is not None):
        raise typer.BadParameter("specify exactly one folder or --all-folders")
    if new_run and retry_errors:
        raise typer.BadParameter("--new-run cannot be combined with --retry-errors")
    if allow_delete and not apply:
        raise typer.BadParameter("--allow-delete requires --apply")
    if retry_errors and not apply:
        raise typer.BadParameter("--retry-errors requires --apply")
    if apply and not yes:
        prompt = (
            "Apply routing rules to the selected folder scope, including permanent DELETE actions?"
            if allow_delete
            else "Apply routing rules to the selected folder scope?"
        )
        if not typer.confirm(prompt, default=False):
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
            allow_delete=allow_delete,
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
            f"matched={run.match_count} acted={run.acted_count} moved={run.moved_count} "
            f"deleted={run.deleted_count} kept={run.kept_count} no_match={run.no_match_count} errors={run.error_count}",
            markup=False,
        )
    if not apply:
        console.print("Preview only. No mailbox or per-message progress state was changed.", markup=False)
    if any(message.outcome in {"error", "blocked"} for _, message in result.messages):
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
    allow_delete: bool = typer.Option(False, "--allow-delete", help="Authorize explicit DELETE rules for this apply"),
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
        allow_delete=allow_delete,
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
            max_message_bytes=settings.mail.max_message_bytes,
            max_body_chars=settings.mail.max_body_chars,
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
            max_message_bytes=settings.mail.max_message_bytes,
            max_body_chars=settings.mail.max_body_chars,
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
        f"Folder={folder} UID {uid} winner={plan.winner_rule_id or '-'} "
        f"action={plan.configured_action.value if plan.configured_action is not None else '-'} "
        f"destination={plan.destination or '-'}",
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
            max_message_bytes=settings.mail.max_message_bytes,
            max_body_chars=settings.mail.max_body_chars,
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
        f"winner={plan.winner_rule_id or '-'} "
        f"action={plan.configured_action.value if plan.configured_action is not None else '-'} "
        f"destination={plan.destination or '-'}",
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
    """Check IMAP access and requirements of the configured rules."""
    console.print("imapledger doctor")
    try:
        settings = load_settings(config)
        rules = load_routing_rules(routing_rules_path_for_config(config))
    except ConfigError as exc:
        err_console.print(f"Configuration error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    except RoutingConfigError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    console.print("config: OK", markup=False)
    if not rules.rules:
        console.print("rules: OK — no rules configured; no automatic mail actions will run", markup=False)

    password = _resolve_password(settings.imap)
    failed = False
    config_store_folder = settings.config_store.folder if settings.config_store is not None else None
    try:
        with FolderCatalog(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as catalog:
            folders = catalog.list_folders(include_counts=False)
        selectable = tuple(
            row.name for row in folders if row.selectable and row.name != config_store_folder
        )
        selectable_set = set(selectable)
        missing_sources = {
            source
            for rule in rules.enabled_rules()
            for source in rule.source_folders
            if source not in selectable_set
        }
        for source in sorted(missing_sources):
            console.print(f"rule source {source}: MISSING or not selectable", markup=False)
            failed = True

        doctor_operation = DoctorOperation(settings, mailbox_factory=ScopedMailbox)
        for folder in selectable:
            active_rules = rules.enabled_rules(folder)
            destinations = tuple(
                dict.fromkeys(
                    rule.destination
                    for rule in active_rules
                    if rule.action is RuleAction.MOVE
                    and rule.destination is not None
                    and rule.destination != folder
                )
            )
            requires_delete = any(rule.action is RuleAction.DELETE for rule in active_rules)
            console.print(f"folder: {folder} (read-only)", markup=False)
            try:
                result = doctor_operation.run(
                    DoctorRequest(
                        folder=folder,
                        destinations=destinations,
                        requires_delete=requires_delete,
                        deep_probe=True,
                    ),
                    password=password,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                )
            except Exception as exc:
                _print_failure(exc, debug=False, command="doctor")
                failed = True
                continue
            if result.opened:
                console.print("source/select/login: OK", markup=False)
                if result.probe is not None:
                    console.print(f"UIDVALIDITY: {result.probe.uidvalidity}", markup=False)
                for capability, required in ((b"MOVE", bool(destinations)), (b"UIDPLUS", requires_delete)):
                    if required:
                        state = "OK" if capability in result.capabilities else "MISSING"
                        console.print(f"required capability {capability.decode()}: {state}", markup=False)
                for destination, exists in result.destinations:
                    if exists is not None:
                        state = "OK" if exists else "MISSING"
                        console.print(f"destination {destination}: {state}", markup=False)
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
            except (ConfigStoreFolderMissingError, ConfigStoreOperationError, ConfigLedgerError) as exc:
                _print_failure(exc, debug=False, command="doctor")
                console.print(f"config store folder: {store.folder}: FAILED", markup=False)
                failed = True
            else:
                console.print(f"config store folder: {store.folder}: OK", markup=False)
    except MailboxError as exc:
        _print_failure(exc, debug=False, command="doctor")
        raise typer.Exit(1) from exc
    finally:
        password = ""
    if failed:
        console.print("result: IMAP or rule preflight has failures", markup=False)
        raise typer.Exit(1)
    console.print("result: IMAP connection and rule preflight are healthy", markup=False)

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
    allow_delete: bool = typer.Option(False, "--allow-delete", help="Authorize explicit DELETE rules for apply"),
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
        allow_delete=allow_delete,
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
            + (f"[{result.detail}]" if result.detail else "")
            for result in plan.rule_results
        )
    destination = message.destination or "-"
    rule_id = plan.winner_rule_id if plan is not None and plan.winner_rule_id is not None else "-"
    action = "NO MATCH"
    if plan is not None and plan.configured_action is not None:
        if plan.configured_action is RuleAction.KEEP:
            action = "KEEP"
        elif plan.configured_action is RuleAction.MOVE:
            action = ("WOULD MOVE" if preview else "MOVED" if message.confirmed else "MOVE NOT CONFIRMED")
        elif message.outcome == "blocked":
            action = "DELETE BLOCKED"
        else:
            action = "WOULD DELETE" if preview else "DELETED" if message.confirmed else "DELETE NOT CONFIRMED"
    error = f" error={message.error_code}" if message.error_code else ""
    detail = f" detail={message.detail}" if message.detail else ""
    console.print(
        f"uid={message.uid} outcome={message.outcome} rule={rule_id} destination={destination} "
        f"evaluations={states} action={action}{error}{detail}",
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
    for column in (
        "Folder", "Mode", "Scope", "Sort", "Status", "Cursor", "Scanned", "Acted", "Moved",
        "Deleted", "Kept", "Errors", "Run",
    ):
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
            str(run.acted_count),
            str(run.moved_count),
            str(run.deleted_count),
            str(run.kept_count),
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
        f"scanned={run.scanned_count} matched={run.match_count} acted={run.acted_count} "
        f"moved={run.moved_count} deleted={run.deleted_count} kept={run.kept_count} "
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




@app.command("explain")
def explain(
    uid: int = typer.Argument(..., help="Folder-scoped message UID"),
    folder: str = typer.Option(..., "--folder", help="Exact source folder"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Explain that legacy category classification has been replaced by rules."""
    err_console.print(
        "`explain` was removed. Use `imapledger rule evaluate --folder FOLDER --uid UID`.",
        markup=False,
    )
    raise typer.Exit(2)


@mail_app.command("classify")
def mail_classify(
    uid: int = typer.Argument(..., help="Folder-scoped message UID"),
    folder: str = typer.Option(..., "--folder", help="Exact source folder"),
    apply: bool = typer.Option(False, "--apply", help="No longer supported"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Guide users from the retired category classifier to ordered rules."""
    err_console.print(
        "`imapledger mail classify` was removed. Use `imapledger rule evaluate`, `rule preview`, or `rule apply`.",
        markup=False,
    )
    raise typer.Exit(2)


@app.command("ui")
def ui(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Launch the interactive terminal mail review console."""
    from .tui.app import run

    run(config)




def _print_failure(exc: Exception, *, debug: bool, command: str | None = None) -> None:
    if isinstance(exc, ImapOperationError):
        err_console.print(str(exc), markup=False)
        if exc.operation == "imap_source_folder_missing":
            err_console.print(
                "hint: verify the exact source folder name in the rules file; imapledger does not create source folders"
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
