from __future__ import annotations

import getpass
import traceback
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, MessageResult, SpamCleaner
from .config import (
    ActionKind,
    AuthSource,
    ConfigError,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    default_config_path,
    load_imap_settings,
    load_settings,
    render_settings,
    write_settings,
)
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
    MessageSelection,
    MessageSort,
    ScopedMailbox,
)
from .preflight import preflight_source
from .rule_learning import RuleProposal, build_rule_candidates, learn_rule_proposal
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

app = typer.Typer(no_args_is_help=True, help="Security-scoped IMAP automation.")
config_app = typer.Typer(help="Inspect imapledger configuration.")
app.add_typer(config_app, name="config")
auth_app = typer.Typer(help="Store and inspect IMAP credentials.")
app.add_typer(auth_app, name="auth")
rule_app = typer.Typer(help="Learn and manage deterministic message routing rules.")
app.add_typer(rule_app, name="rule")
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
            prompt = (
                "Choose master passphrase "
                f"(minimum {settings.imap.auth.vault_min_passphrase_length} characters): "
            )
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
                deep_probe=True,
                mailbox_factory=ScopedMailbox,
                event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            )
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
        help="Execute the configured actions. Without this flag, run read-only.",
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
    """Classify configured source folders and optionally apply their configured actions."""
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
    password = _resolve_password(settings.imap)

    selection = MessageSelection(limit=limit, offset=offset, sort=sort)
    actions = settings.spam.actions
    destinations = _move_destinations(actions, rules)
    allow_delete = any(
        action.action is ActionKind.DELETE for action in (actions.spam, actions.not_spam, actions.review)
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
                deep_probe=False,
                mailbox_factory=ScopedMailbox,
                event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
            )
            state = "OK" if result.ok else "FAILED"
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
                        if apply:
                            for destination in destinations:
                                if not mailbox.destination_exists(destination):
                                    raise MailboxError(f"configured move destination does not exist: {destination}")
                        console.print(
                            _selection_summary(
                                folder=mailbox.folder,
                                total_messages=len(mailbox.snapshot().uids),
                                selected_count=mailbox.selected_count(selection),
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
                        ).run(
                            apply=apply,
                            selection=selection,
                            on_result=(
                                lambda row, position, total, source_folder=mailbox.folder: _print_result(
                                    row,
                                    folder=source_folder,
                                    position=position,
                                    total=total,
                                    apply=apply,
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


def _selection_summary(
    *,
    folder: str,
    total_messages: int,
    selected_count: int,
    selection: MessageSelection,
) -> str:
    limit = "all" if selection.limit is None else str(selection.limit)
    return (
        f"folder={folder} messages={total_messages} selected={selected_count} "
        f"sort={selection.sort.value} offset={selection.offset} limit={limit}"
    )


def _move_destinations(actions: SpamActions, rules: RuleSet | None = None) -> tuple[str, ...]:
    destinations = [
        action.destination
        for action in (actions.spam, actions.not_spam, actions.review)
        if action.action is ActionKind.MOVE and action.destination is not None
    ]
    if rules is not None:
        destinations.extend(rules.move_destinations())
    return tuple(dict.fromkeys(destinations))


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


def _print_result(
    row: MessageResult,
    *,
    folder: str,
    position: int,
    total: int,
    apply: bool,
) -> None:
    action = _final_action_label(row, apply=apply)
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
    console.print(
        f"[{position}/{total}] Folder={folder} UID {row.uid}  {action}  Outcome={outcome}  Verdict={verdict}  "
        f"Signals={_signal_summary(row)}  Reasons={reasons}  "
        f"From={_safe_text(row.sender)}  Subject={_safe_text(row.subject)}",
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
        prefix = "MOVE-APPROVED" if apply else "WOULD MOVE"
        return f"{prefix} -> {row.action.destination}"
    return "DELETE-APPROVED" if apply else "WOULD DELETE"


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
    console.print(
        f"Scanned {report.scanned}; rules {report.rule_matches}; spam {report.spam}; "
        f"not-spam {report.not_spam}; review {report.review}; "
        f"skipped {report.skipped}; errors {report.errors}."
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
        f"kept {sum(report.kept_in_place for report in reports)}."
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
            row.matched_rule_id or "-",
            _safe_text(row.sender),
            _safe_text(row.subject),
            row.detail or "",
        )
    console.print(table, markup=False)
    _print_summary(report)
