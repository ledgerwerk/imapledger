from __future__ import annotations

import getpass
import traceback
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, MessageResult, SpamCleaner
from .config import (
    ConfigError,
    ImapSettings,
    Settings,
    SpamSettings,
    default_config_path,
    load_settings,
    write_settings,
)
from .mailbox import ImapOperationError, MailboxError, MessageSelection, MessageSort, ScopedMailbox

app = typer.Typer(no_args_is_help=True, help="Security-scoped IMAP automation.")
console = Console()
err_console = Console(stderr=True)


@app.command("init")
def init_config(
    host: str = typer.Option(..., prompt=True, help="IMAP host"),
    username: str = typer.Option(..., prompt=True, help="IMAP username"),
    folder: str = typer.Option("Spam", prompt=True, help="The only folder this cleaner may access"),
    port: int = typer.Option(993, help="IMAPS port"),
    spam_threshold: float = typer.Option(0.95, min=0.0, max=1.0, help="Delete threshold"),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config"),
) -> None:
    """Write non-secret configuration. The IMAP password is never stored."""
    try:
        path = write_settings(
            Settings(
                imap=ImapSettings(host=host, port=port, username=username),
                spam=SpamSettings(folder=folder, threshold=spam_threshold),
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
    """Probe the configured IMAP read path without classification or writes."""
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

    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=settings.spam.folder,
            writable=False,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            probe = mailbox.probe()
    except Exception as exc:
        _print_failure(exc, debug=False)
        raise typer.Exit(1) from exc
    finally:
        password = ""

    console.print("TLS connect: OK")
    console.print("login: OK")
    console.print("capabilities: OK")
    console.print(f"folder: {settings.spam.folder} (read-only)", markup=False)
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
    console.print("result: IMAP read path is healthy")


@app.command()
def clean(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Permanently delete messages classified as spam. Without this flag, run read-only.",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        min=1,
        help="Classify at most this many messages after sorting and applying --offset.",
    ),
    offset: int = typer.Option(
        0,
        "--offset",
        min=0,
        help="Skip this many messages after sorting.",
    ),
    sort: MessageSort = typer.Option(  # noqa: B008
        MessageSort.NEWEST,
        "--sort",
        help="Order by IMAP UID arrival order, not the message Date header.",
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
    """Classify a selected window in the configured folder and optionally delete approved spam."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(2) from exc

    # Deliberately prompt on every invocation. Passwords are not accepted as CLI
    # arguments, environment variables, or config values in the MVP.
    password = getpass.getpass("IMAP password: ")
    if not password:
        err_console.print("[red]Empty password; aborting.[/red]")
        raise typer.Exit(2)

    selection = MessageSelection(limit=limit, offset=offset, sort=sort)
    try:
        with ScopedMailbox(
            host=settings.imap.host,
            port=settings.imap.port,
            username=settings.imap.username,
            password=password,
            folder=settings.spam.folder,
            writable=apply,
            max_message_bytes=settings.spam.max_message_bytes,
            max_body_chars=settings.spam.max_body_chars,
            event_callback=(lambda event: console.print(event, markup=False)) if verbose else None,
        ) as mailbox:
            total_messages = len(mailbox.snapshot().uids)
            selected_count = mailbox.selected_count(selection)
            console.print(
                _selection_summary(
                    folder=mailbox.folder,
                    total_messages=total_messages,
                    selected_count=selected_count,
                    selection=selection,
                ),
                markup=False,
            )
            with PyJevSpamClassifier() as classifier:
                report = SpamCleaner(mailbox, classifier, threshold=settings.spam.threshold).run(
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
    except Exception as exc:
        _print_failure(exc, debug=debug)
        raise typer.Exit(1) from exc
    finally:
        password = ""

    if progress:
        _print_summary(report)
        if report.partial_delete_error is not None:
            _print_partial_delete_details(report)
    else:
        _print_report(report)
    if report.partial_delete_error is not None:
        _print_failure(report.partial_delete_error, debug=debug)
        raise typer.Exit(1)


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


def _print_result(
    row: MessageResult,
    *,
    position: int,
    total: int,
    apply: bool,
) -> None:
    probability = "-" if row.probability is None else f"{row.probability:.3f}"
    if row.status == "error":
        action = "ERROR / KEEP"
    elif row.status == "skip":
        action = "SKIP / KEEP"
    elif row.status == "spam":
        action = "DELETE-APPROVED" if apply else "WOULD DELETE"
    else:
        action = "KEEP"
    detail = f"  Detail={row.detail}" if row.detail else ""
    console.print(
        f"[{position}/{total}] UID {row.uid}  {action}  P(spam)={probability}  "
        f"Inclination={row.inclination}  From={row.sender}  Subject={row.subject}{detail}",
        markup=False,
    )


def _print_summary(report: CleanReport) -> None:
    console.print(
        f"Scanned {report.scanned}; spam {report.spam}; kept {report.kept}; "
        f"skipped {report.skipped}; errors {report.errors}; deleted {report.deleted}."
    )
    if report.apply:
        console.print(f"Deletion: {report.spam} approved; {report.deleted} confirmed deleted.")
    elif report.spam:
        console.print("Dry-run only. Re-run with --apply to permanently delete approved spam UIDs.")
    if report.partial_delete_error is not None:
        console.print(
            f"Partial deletion: {len(report.partial_delete_error.deleted)} confirmed; "
            f"{len(report.partial_delete_error.pending)} pending."
        )


def _print_partial_delete_details(report: CleanReport) -> None:
    console.print("Deletion details:")
    for row in report.results:
        if row.status == "spam":
            action = "DELETED" if row.deleted else "NOT CONFIRMED"
            detail = f"  {row.detail}" if row.detail else ""
            console.print(f"UID {row.uid}  {action}{detail}", markup=False)


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
    table = Table(title=f"imapledger — {report.folder} ({'APPLY' if report.apply else 'DRY RUN'})")
    table.add_column("UID", justify="right")
    table.add_column("P(spam)", justify="right")
    table.add_column("Inclination")
    table.add_column("Action")
    table.add_column("From")
    table.add_column("Subject")
    table.add_column("Detail")
    for row in report.results:
        probability = "-" if row.probability is None else f"{row.probability:.3f}"
        if row.status == "error":
            action = "ERROR / KEEP"
        elif row.status == "skip":
            action = "SKIP / KEEP"
        elif row.deleted:
            action = "DELETED"
        elif row.status == "spam" and report.partial_delete_error is not None:
            action = "NOT CONFIRMED"
        elif row.status == "spam" and report.apply:
            action = "DELETE-APPROVED"
        elif row.status == "spam":
            action = "WOULD DELETE"
        else:
            action = "KEEP"
        table.add_row(
            str(row.uid),
            probability,
            row.inclination,
            action,
            row.sender,
            row.subject,
            row.detail or "",
        )
    console.print(table, markup=False)
    console.print(
        f"Scanned {report.scanned}; spam {report.spam}; kept {report.kept}; "
        f"skipped {report.skipped}; errors {report.errors}; deleted {report.deleted}."
    )
    if report.partial_delete_error is not None:
        console.print(
            f"Partial deletion: {len(report.partial_delete_error.deleted)} confirmed; "
            f"{len(report.partial_delete_error.pending)} pending."
        )
    if not report.apply and report.spam:
        console.print("Dry-run only. Re-run with --apply to permanently delete approved spam UIDs.")
