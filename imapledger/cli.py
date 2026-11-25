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
from .classification_state import all_state_keywords
from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, MessageResult, SpamCleaner
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
from .preflight import preflight_source
from .rule_candidates import build_rule_candidates
from .rule_learning import RuleProposal, learn_rule_proposal
from .rules import (
    RuleError,
    RuleSet,
    describe_match,
    generate_rule_id,
    load_rules,
    rules_path_for_config,
    validate_rule_id,
    write_rules,
)

app = typer.Typer(no_args_is_help=True, help="Security-scoped IMAP mail classification and cleaning.")
config_app = typer.Typer(help="Inspect imapledger configuration.")
app.add_typer(config_app, name="config")
auth_app = typer.Typer(help="Store and inspect IMAP credentials.")
app.add_typer(auth_app, name="auth")
rule_app = typer.Typer(help="Manage optional advanced routing filters for batch clean.")
app.add_typer(rule_app, name="rule")
state_app = typer.Typer(help="Inspect and reset persisted classification state.")
app.add_typer(state_app, name="state")
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


@rule_app.command("list")
def rule_list(
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """List locally stored routing rules without connecting to IMAP."""
    try:
        rules = load_rules(rules_path_for_config(config))
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    if not rules.rules:
        console.print("No routing rules.", markup=False)
        return

    table = Table(title="Routing rules")
    table.add_column("ID")
    table.add_column("Enabled")
    table.add_column("Sources")
    table.add_column("Match")
    table.add_column("Action")
    for rule in rules.rules:
        action = "keep" if rule.action.action is ActionKind.KEEP else f"move -> {rule.action.destination}"
        table.add_row(
            rule.id,
            "yes" if rule.enabled else "no",
            ", ".join(rule.source_folders),
            describe_match(rule.match),
            action,
        )
    console.print(table, markup=False)


@rule_app.command("show")
def rule_show(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Show one locally stored routing rule without connecting to IMAP."""
    try:
        rules = load_rules(rules_path_for_config(config))
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    rule = next((item for item in rules.rules if item.id == rule_id), None)
    if rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    console.print(f"id: {rule.id}", markup=False)
    console.print(f"enabled: {str(rule.enabled).lower()}", markup=False)
    console.print("sources:", markup=False)
    for folder in rule.source_folders:
        console.print(f"  - {folder}", markup=False)
    console.print("match:", markup=False)
    for key, value in rule.match.as_dict().items():
        console.print(f"  {key}: {_safe_text(value)}", markup=False)
    if rule.action.action is ActionKind.KEEP:
        console.print("action: keep", markup=False)
    else:
        console.print(f"action: move -> {rule.action.destination}", markup=False)


@rule_app.command("remove")
def rule_remove(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    yes: bool = typer.Option(False, "--yes", help="Remove without confirmation"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
) -> None:
    """Remove a locally stored routing rule without connecting to IMAP."""
    path = rules_path_for_config(config)
    try:
        rules = load_rules(path)
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    if not any(rule.id == rule_id for rule in rules.rules):
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    if not yes and not typer.confirm(f"Remove rule {rule_id}?", default=False):
        console.print("No rule was removed.", markup=False)
        return
    try:
        write_rules(RuleSet(tuple(rule for rule in rules.rules if rule.id != rule_id)), path)
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    console.print(f"Removed rule {rule_id}", markup=False)


@rule_app.command("learn")
def rule_learn(
    uid: int = typer.Argument(..., help="Folder-scoped message UID to learn from"),
    folder: str = typer.Option(..., "--folder", help="Configured source folder containing the UID"),
    move: str = typer.Option(..., "--move", help="Explicit move destination for the learned rule"),
    name: str | None = typer.Option(None, "--name", help="Optional safe rule ID"),
    preview: bool = typer.Option(False, "--preview", help="Show a proposal without saving it"),
    yes: bool = typer.Option(False, "--yes", help="Accept the proposed rule without prompting"),
    apply_current: bool = typer.Option(
        False,
        "--apply-current",
        help="Move the referenced UID after the rule is successfully saved",
    ),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Learn a narrow routing rule from one explicitly scoped message UID."""
    if uid < 1:
        raise typer.BadParameter("UID must be a positive integer")
    if preview and apply_current:
        raise typer.BadParameter("--preview cannot be combined with --apply-current")
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if folder not in settings.spam.folders:
        err_console.print(f"Source folder is not configured in spam.folders: {folder}", markup=False)
        raise typer.Exit(2)
    if move in settings.spam.folders:
        err_console.print("Move destination must not be a configured spam source folder.", markup=False)
        raise typer.Exit(2)
    rules_path = rules_path_for_config(config)
    try:
        existing = load_rules(rules_path, source_folders=settings.spam.folders)
        if name is not None:
            validate_rule_id(name)
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc

    password = _resolve_password(settings.imap)
    rule_saved = False
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=folder,
            writable=apply_current,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            allowed_destinations=(move,),
            allow_delete=False,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            if not mailbox.destination_exists(move):
                err_console.print(f"Move destination does not exist: {move}", markup=False)
                raise typer.Exit(1)
            item = mailbox.fetch_uid(uid)
            if item.message is None:
                err_console.print(
                    f"Could not read UID {uid}: {item.skip_reason or 'message unavailable'}",
                    markup=False,
                )
                raise typer.Exit(1)
            message = item.message
            candidates = build_rule_candidates(message)
            from pyjev import Jev

            with Jev() as jev:
                proposal = learn_rule_proposal(
                    jev,
                    message=message,
                    candidates=candidates,
                    requested_action=MessageAction(ActionKind.MOVE, move),
                )

            console.print(f"example {folder} UID {uid}", markup=False)
            console.print(f"From: {_safe_text(message.sender)}", markup=False)
            console.print(f"Subject: {_safe_text(message.subject)}", markup=False)
            _print_rule_proposal(proposal)
            if proposal.status != "auto" or proposal.candidate is None:
                console.print("No rule was saved.", markup=False)
                raise typer.Exit(2)

            rule_id = name or generate_rule_id(proposal.candidate.match, [rule.id for rule in existing.rules])
            proposed = proposal.to_rule(
                id=rule_id,
                source_folders=(folder,),
                action=MessageAction(ActionKind.MOVE, move),
            )
            console.print(f"Proposed rule: {proposed.id}", markup=False)
            console.print(f"  source: {folder}", markup=False)
            console.print(f"  match: {describe_match(proposed.match)}", markup=False)
            console.print(f"  action: move -> {move}", markup=False)
            if preview:
                console.print("Preview only. No rule was saved.", markup=False)
                return

            for current in existing.rules:
                if current.source_folders != proposed.source_folders or current.match != proposed.match:
                    continue
                if current.action == proposed.action:
                    console.print(f"Equivalent rule already exists: {current.id}", markup=False)
                    console.print("No rule was added.", markup=False)
                    return
                err_console.print(
                    "A rule with the same matcher and scope already exists with a different action:",
                    markup=False,
                )
                existing_action = (
                    "keep" if current.action.action is ActionKind.KEEP else f"move -> {current.action.destination}"
                )
                err_console.print(f"  existing: {existing_action}", markup=False)
                err_console.print(f"  proposed: move -> {move}", markup=False)
                err_console.print("No rule was changed.", markup=False)
                raise typer.Exit(2)
            if any(rule.id == proposed.id for rule in existing.rules):
                err_console.print(f"Rule ID already exists: {proposed.id}", markup=False)
                raise typer.Exit(2)
            if not yes and not typer.confirm("Save rule?", default=False):
                console.print("No rule was saved.", markup=False)
                return
            write_rules(RuleSet((*existing.rules, proposed)), rules_path)
            rule_saved = True
            console.print(f"Saved rule {proposed.id}", markup=False)
            console.print(f"rules: {rules_path}", markup=False)
            if apply_current:
                result = mailbox.move_uid(uid, move)
                if uid not in result.moved:
                    raise MailboxError("current UID move was not confirmed")
                console.print(f"MOVED current UID {uid} -> {move}", markup=False)
    except typer.Exit:
        raise
    except Exception as exc:
        if apply_current and rule_saved:
            err_console.print("The rule was saved, but applying it to the current UID failed.", markup=False)
        _print_failure(exc, debug=False, command="rule learn")
        raise typer.Exit(1) from exc


def _print_rule_proposal(proposal: RuleProposal) -> None:
    if proposal.candidate is not None:
        console.print("Candidate selected:", markup=False)
        console.print(f"  {proposal.candidate.description}", markup=False)
    if proposal.candidate_confidence is not None:
        console.print(f"Jev confidence: {proposal.candidate_confidence:.2f}", markup=False)
    if proposal.safe_probability is not None:
        console.print(f"Generalization safety: {proposal.safe_probability:.2f}", markup=False)
    if proposal.status == "none":
        console.print("Could not derive a sufficiently safe rule.", markup=False)
    elif proposal.status == "review":
        console.print("The candidate did not meet the automatic acceptance thresholds.", markup=False)


@rule_app.command("test")
def rule_test(
    rule_id: str = typer.Argument(..., help="Rule ID to test"),
    limit: int = typer.Option(20, min=1, help="Maximum messages inspected per source folder"),
    offset: int = typer.Option(0, min=0, help="Skip this many messages in each source folder"),
    sort: MessageSort = typer.Option(MessageSort.NEWEST, "--sort", help="Mailbox-local UID ordering"),  # noqa: B008
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
) -> None:
    """Inspect a bounded read-only window for messages matching one routing rule."""
    try:
        settings = load_settings(config)
        rules = load_rules(rules_path_for_config(config), source_folders=settings.spam.folders)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except RuleError as exc:
        err_console.print(f"Rules error: {exc}", markup=False)
        raise typer.Exit(2) from exc
    rule = next((item for item in rules.rules if item.id == rule_id), None)
    if rule is None:
        err_console.print(f"Rule not found: {rule_id}", markup=False)
        raise typer.Exit(2)
    selection = MessageSelection(limit=limit, offset=offset, sort=sort)
    password = _resolve_password(settings.imap)
    try:
        for folder in rule.source_folders:
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
                inspected = mailbox.selected_count(selection)
                console.print(f"rule={rule.id} source={folder} inspected={inspected}", markup=False)
                matched = 0
                for item in mailbox.iter_messages(selection):
                    if item.message is None or not rule.match.matches(item.message):
                        continue
                    matched += 1
                    console.print(
                        f"[{matched}] Folder={folder} UID {item.uid} MATCH From={_safe_text(item.message.sender)} "
                        f"Subject={_safe_text(item.message.subject)}",
                        markup=False,
                    )
                console.print(f"Matched {matched} in inspected window.", markup=False)
    except Exception as exc:
        _print_failure(exc, debug=False, command="rule test")
        raise typer.Exit(1) from exc
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
    failed = False
    try:
        for folder in settings.spam.folders:
            console.print(f"folder: {folder} (read-only)", markup=False)
            result = preflight_source(
                settings,
                folder,
                password=password,
                destinations=destinations,
                requires_delete=requires_delete,
                require_state_persistence=(settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS),
                deep_probe=True,
                mailbox_factory=ScopedMailbox,
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
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Apply category actions to selected messages in configured spam.folders.",
    ),
    reclassify: bool = typer.Option(
        False,
        "--reclassify",
        help="Ignore stored classification state and classify selected messages again.",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        min=1,
        help="Classify at most this many messages per source after sorting and applying --offset.",
    ),
    offset: int = typer.Option(
        0,
        "--offset",
        min=0,
        help="Skip this many messages independently in each source after sorting.",
    ),
    sort: MessageSort = typer.Option(  # noqa: B008
        MessageSort.NEWEST,
        "--sort",
        help="Order by mailbox-local UID arrival order, not the message Date header.",
    ),
    progress: bool = typer.Option(  # noqa: B008
        True,
        "--progress/--no-progress",
        help="Stream each classification and final configured action as it completes.",
    ),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print safe IMAP operation progress"),
    debug: bool = typer.Option(False, "--debug", help="Print a traceback without exception payloads"),
) -> None:
    """Classify only spam.folders and optionally apply global category actions."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc

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

    excluded_keywords = (
        all_state_keywords()
        if settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS and not reclassify
        else ()
    )
    selection = MessageSelection(limit=limit, offset=offset, sort=sort, excluded_keywords=excluded_keywords)
    actions = settings.spam.actions
    destinations = _move_destinations(actions, rules)
    allow_delete = any(
        action.action is ActionKind.DELETE for action in (actions.spam, actions.not_spam, actions.review)
    )
    requires_state_persistence = settings.spam.state.backend is ClassificationStateBackend.IMAP_KEYWORDS and any(
        action.action is ActionKind.KEEP for action in (actions.spam, actions.not_spam, actions.review)
    )

    if apply:
        preflight_failed = False
        for folder in settings.spam.folders:
            result = preflight_source(
                settings,
                folder,
                password=password,
                destinations=destinations,
                requires_delete=allow_delete,
                require_state_persistence=requires_state_persistence,
                deep_probe=False,
                mailbox_factory=ScopedMailbox,
                event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            )
            state = "OK" if result.ok else "FAILED"
            _print_state_preflight(result, clean_apply=True)
            console.print(f"preflight {folder}: {state}", markup=False)
            for capability in (b"MOVE", b"UIDPLUS"):
                if capability in result.missing_capabilities:
                    console.print(f"required capability {capability.decode()}: MISSING")
            for destination, exists in result.destinations:
                if exists is not None:
                    state = "OK" if exists else "MISSING"
                    console.print(f"destination {destination}: {state}", markup=False)
            for error in result.errors:
                _print_failure(error, debug=False, command="clean")
            preflight_failed = preflight_failed or not result.ok
        if preflight_failed:
            console.print("apply aborted before classification/mutation")
            raise typer.Exit(1)
    reports: list[CleanReport] = []
    failure: Exception | None = None
    try:
        with PyJevSpamClassifier(
            trusted_authserv_ids=settings.spam.trusted_authserv_ids,
            trusted_provider_headers=settings.spam.trusted_provider_headers,
        ) as classifier:
            for folder in settings.spam.folders:
                report: CleanReport | None = None
                try:
                    with ScopedMailbox(
                        host=settings.imap.host,
                        port=settings.imap.port,
                        username=settings.imap.username,
                        password=password,
                        folder=folder,
                        writable=apply,
                        allowed_destinations=destinations,
                        allow_delete=allow_delete,
                        max_message_bytes=settings.spam.max_message_bytes,
                        max_body_chars=settings.spam.max_body_chars,
                        event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                    ) as mailbox:
                        if apply and requires_state_persistence:
                            mailbox.require_persistent_classification_state()
                        if apply:
                            for destination in destinations:
                                if not mailbox.destination_exists(destination):
                                    raise MailboxError(f"configured move destination does not exist: {destination}")
                        console.print(
                            _selection_summary(
                                folder=mailbox.folder,
                                total_messages=len(mailbox.snapshot().uids),
                                selected_count=mailbox.selected_count(selection),
                                unclassified_count=(
                                    len(mailbox.candidate_uids(excluded_keywords=selection.excluded_keywords))
                                    if selection.excluded_keywords
                                    else None
                                ),
                                selection=selection,
                            ),
                            markup=False,
                        )
                        report = SpamCleaner(
                            mailbox,
                            classifier,
                            policy=settings.spam.policy,
                            actions=actions,
                            rules=rules,
                            **(
                                {"state_backend": settings.spam.state.backend}
                                if settings.spam.state.backend is not ClassificationStateBackend.NONE
                                else {}
                            ),
                        ).run(
                            apply=apply,
                            **({"reclassify": True} if reclassify else {}),
                            selection=selection,
                            on_result=(
                                lambda row, position, total, source_folder=mailbox.folder: _print_result(
                                    row,
                                    folder=source_folder,
                                    position=position,
                                    total=total,
                                    apply=apply,
                                    verbose=verbose,
                                )
                            )
                            if progress
                            else None,
                        )
                        reports.append(report)
                        if progress:
                            _print_summary(report)
                        else:
                            _print_report(report)
                except Exception as exc:
                    failure = exc
                    break
                if report is not None and report.mutation_error is not None:
                    failure = report.mutation_error
                    break
    except Exception as exc:
        failure = exc

    if reports:
        _print_aggregate_summary(reports)
    if failure is not None:
        _print_failure(failure, debug=debug, command="clean")
        raise typer.Exit(1) from failure


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
    try:
        for folder in settings.spam.folders:
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
                    snapshot = mailbox.snapshot()
                    keywords = all_state_keywords()
                    matches = {keyword: mailbox.search_keyword(keyword) for keyword in keywords}
                    unclassified = mailbox.candidate_uids(excluded_keywords=keywords)
                    marked_uids = set().union(*matches.values())
                    conflicts = sum(
                        sum(uid in matching_uids for matching_uids in matches.values()) > 1 for uid in marked_uids
                    )
                    console.print(
                        f"folder={folder} uidvalidity={snapshot.uidvalidity} "
                        f"backend={settings.spam.state.backend.value} "
                        f"keyword_persistence={_keyword_persistence_label(settings.spam.state.backend, snapshot)} "
                        f"total={len(snapshot.uids)} spam={len(matches[keywords[0]])} "
                        f"notspam={len(matches[keywords[1]])} review={len(matches[keywords[2]])} "
                        f"unclassified={len(unclassified)} conflicts={conflicts}",
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

    folders = settings.spam.folders if all_folders else (folder,)
    password = _resolve_password(settings.imap)
    failed = False
    try:
        for source_folder in folders:
            try:
                with ScopedMailbox(
                    host=settings.imap.host,
                    port=settings.imap.port,
                    username=settings.imap.username,
                    password=password,
                    folder=source_folder,
                    writable=apply,
                    max_message_bytes=settings.spam.max_message_bytes,
                    max_body_chars=settings.spam.max_body_chars,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                ) as mailbox:
                    uid_keywords: dict[int, list[str]] = {}
                    if uid is not None:
                        flags = mailbox.get_flags(uid)
                        uid_keywords[uid] = list(_present_state_keywords(flags))
                    else:
                        for keyword in all_state_keywords():
                            for matched_uid in mailbox.search_keyword(keyword):
                                uid_keywords.setdefault(matched_uid, []).append(keyword)
                    marker_count = sum(len(keywords) for keywords in uid_keywords.values())
                    operation = "remove" if apply else "would remove"
                    if uid is not None:
                        markers = ",".join(uid_keywords[uid]) or "none"
                        console.print(
                            f"folder={source_folder} uid={uid} markers={markers} action={operation}",
                            markup=False,
                        )
                    else:
                        console.print(
                            f"folder={source_folder} targeted_uids={len(uid_keywords)} "
                            f"markers={marker_count} action={operation}",
                            markup=False,
                        )
                    if apply:
                        for target_uid in sorted(uid_keywords):
                            for keyword in uid_keywords[target_uid]:
                                mailbox.remove_keyword(target_uid, keyword)
                            remaining = _present_state_keywords(mailbox.get_flags(target_uid))
                            if remaining:
                                raise ImapOperationError(
                                    operation="imap_verify_keyword",
                                    message="classification state remains after reset",
                                    folder=source_folder,
                                    selector=", ".join(remaining),
                                    uids=(target_uid,),
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
    folders = (folder,) if folder is not None else settings.spam.folders
    password = _resolve_password(settings.imap)
    table = Table(title="Review queue")
    for column in ("Folder", "UID", "From", "Subject", "Date", "Message-ID"):
        table.add_column(column)
    failed = False
    try:
        for source_folder in folders:
            try:
                with ScopedMailbox(
                    host=settings.imap.host,
                    port=settings.imap.port,
                    username=settings.imap.username,
                    password=password,
                    folder=source_folder,
                    writable=False,
                    max_message_bytes=settings.spam.max_message_bytes,
                    max_body_chars=settings.spam.max_body_chars,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                ) as mailbox:
                    uids = sorted(
                        mailbox.search_keyword("imapledger-v1-review"),
                        reverse=sort is MessageSort.NEWEST,
                    )
                    selected = uids[offset:]
                    if limit is not None:
                        selected = selected[:limit]
                    for review_uid in selected:
                        message = mailbox.fetch_headers(review_uid)
                        if message is None:
                            continue
                        table.add_row(
                            source_folder,
                            str(review_uid),
                            _safe_text(message.sender),
                            _safe_text(message.subject),
                            _safe_text(message.date),
                            _safe_text(message.message_id),
                        )
            except Exception as exc:
                failed = True
                _print_failure(exc, debug=False, command="review")
    finally:
        password = ""
    console.print(table, markup=False)
    if failed:
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
