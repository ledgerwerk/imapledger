from __future__ import annotations

import getpass
import traceback
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, MessageResult, SpamCleaner, SpamOutcome
from .config import (
    ActionKind,
    ConfigError,
    ImapSettings,
    MessageAction,
    Settings,
    SpamActions,
    SpamSettings,
    default_config_path,
    load_settings,
    render_settings,
    write_settings,
)
from .evidence import redact_urls
from .mailbox import ImapOperationError, MailboxError, MessageSelection, MessageSort, ScopedMailbox

app = typer.Typer(no_args_is_help=True, help="Security-scoped IMAP automation.")
config_app = typer.Typer(help="Inspect imapledger configuration.")
app.add_typer(config_app, name="config")
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

    password = getpass.getpass("IMAP password: ")
    if not password:
        err_console.print("[red]Empty password; aborting.[/red]")
        raise typer.Exit(2)

    actions = settings.spam.actions
    destinations = _move_destinations(actions)
    requires_delete = any(
        action.action is ActionKind.DELETE
        for action in (actions.spam, actions.not_spam, actions.review)
    )
    failed = False
    try:
        for folder in settings.spam.folders:
            console.print(f"folder: {folder} (read-only)", markup=False)
            try:
                with ScopedMailbox(
                    host=settings.imap.host,
                    port=settings.imap.port,
                    username=settings.imap.username,
                    password=password,
                    folder=folder,
                    writable=False,
                    allowed_destinations=destinations,
                    allow_delete=requires_delete,
                    max_message_bytes=settings.spam.max_message_bytes,
                    max_body_chars=settings.spam.max_body_chars,
                    event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
                ) as mailbox:
                    probe = mailbox.probe()
                    console.print("TLS connect: OK")
                    console.print("login: OK")
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
                            available = capability in mailbox.capabilities
                            state = "OK" if available else "MISSING"
                            console.print(f"required capability {capability.decode()}: {state}")
                            failed = failed or not available
                    for destination in destinations:
                        try:
                            exists = mailbox.destination_exists(destination)
                        except Exception as exc:
                            _print_failure(exc, debug=False)
                            failed = True
                            continue
                        state = "OK" if exists else "MISSING"
                        console.print(f"destination {destination}: {state}", markup=False)
                        failed = failed or not exists
            except Exception as exc:
                _print_failure(exc, debug=False)
                failed = True
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
        help="Stream each classification decision as it completes.",
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

    password = getpass.getpass("IMAP password: ")
    if not password:
        err_console.print("[red]Empty password; aborting.[/red]")
        raise typer.Exit(2)

    selection = MessageSelection(limit=limit, offset=offset, sort=sort)
    actions = settings.spam.actions
    destinations = _move_destinations(actions)
    allow_delete = any(
        action.action is ActionKind.DELETE
        for action in (actions.spam, actions.not_spam, actions.review)
    )
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
                        ).run(
                            apply=apply,
                            selection=selection,
                            on_result=(
                                lambda row, position, total: _print_result(
                                    row,
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
                            _print_action_results(report)
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
    finally:
        password = ""

    if reports:
        _print_aggregate_summary(reports)
    if failure is not None:
        _print_failure(failure, debug=debug)
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



def _move_destinations(actions: SpamActions) -> tuple[str, ...]:
    destinations = []
    for action in (actions.spam, actions.not_spam, actions.review):
        if action.action is ActionKind.MOVE and action.destination is not None:
            if action.destination not in destinations:
                destinations.append(action.destination)
    return tuple(destinations)


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
    position: int,
    total: int,
    apply: bool,
) -> None:
    action = _classification_action_label(row, apply=apply)
    reasons = ",".join(row.reasons) or (row.detail or "-")
    verdict = row.verdict.name if row.verdict else "-"
    outcome = row.outcome.value.upper() if row.outcome else "-"
    console.print(
        f"[{position}/{total}] UID {row.uid}  {action}  Outcome={outcome}  Verdict={verdict}  "
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
    for outcome in (SpamOutcome.SPAM, SpamOutcome.NOT_SPAM, SpamOutcome.REVIEW):
        for row in report.results:
            if row.outcome is not outcome or row.action.action is ActionKind.KEEP:
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
        f"Scanned {report.scanned}; spam {report.spam}; not-spam {report.not_spam}; review {report.review}; "
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


def _print_action_results(report: CleanReport) -> None:
    if not report.apply:
        return
    for row in report.results:
        if row.action.action is ActionKind.KEEP:
            continue
        console.print(
            f"folder={report.folder} UID {row.uid}  {_final_action_label(row, apply=True)}",
            markup=False,
        )


def _print_aggregate_summary(reports: list[CleanReport]) -> None:
    console.print(
        f"Aggregate across {len(reports)} folders (UIDs remain folder-scoped): "
        f"scanned {sum(report.scanned for report in reports)}; "
        f"spam {sum(report.spam for report in reports)}; "
        f"not-spam {sum(report.not_spam for report in reports)}; "
        f"review {sum(report.review for report in reports)}; "
        f"skipped {sum(report.skipped for report in reports)}; "
        f"errors {sum(report.errors for report in reports)}; "
        f"moved {sum(report.moved for report in reports)}; "
        f"deleted {sum(report.deleted for report in reports)}; "
        f"kept {sum(report.kept_in_place for report in reports)}."
    )

def _print_failure(exc: Exception, *, debug: bool) -> None:
    if isinstance(exc, ImapOperationError):
        err_console.print(str(exc), markup=False)
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
            _safe_text(row.sender),
            _safe_text(row.subject),
            row.detail or "",
        )
    console.print(table, markup=False)
    _print_summary(report)
