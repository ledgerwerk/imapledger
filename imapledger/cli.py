from __future__ import annotations

import getpass
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .classifier import PyJevSpamClassifier
from .cleaner import CleanReport, SpamCleaner
from .config import (
    ConfigError,
    ImapSettings,
    Settings,
    SpamSettings,
    default_config_path,
    load_settings,
    write_settings,
)
from .mailbox import ScopedMailbox

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
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),
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
def clean(
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Permanently delete messages classified as spam. Without this flag, run read-only.",
    ),
    config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),
) -> None:
    """Classify every message in the configured folder and optionally delete spam."""
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
        ) as mailbox:
            with PyJevSpamClassifier() as classifier:
                report = SpamCleaner(mailbox, classifier, threshold=settings.spam.threshold).run(apply=apply)
    except Exception as exc:
        err_console.print(f"[red]{type(exc).__name__}:[/red] {exc}")
        raise typer.Exit(1) from exc
    finally:
        password = ""

    _print_report(report)


def _print_report(report: CleanReport) -> None:
    table = Table(title=f"imapledger — {report.folder} ({'APPLY' if report.apply else 'DRY RUN'})")
    table.add_column("UID", justify="right")
    table.add_column("P(spam)", justify="right")
    table.add_column("Action")
    table.add_column("From")
    table.add_column("Subject")
    for row in report.results:
        probability = "-" if row.probability is None else f"{row.probability:.3f}"
        if row.status == "error":
            action = "ERROR / KEEP"
        elif row.status == "skip":
            action = "SKIP / KEEP"
        elif row.deleted:
            action = "DELETED"
        elif row.status == "spam":
            action = "WOULD DELETE"
        else:
            action = "KEEP"
        table.add_row(str(row.uid), probability, action, row.sender, row.subject)
    console.print(table)
    console.print(
        f"Scanned {report.scanned}; spam {report.spam}; kept {report.kept}; "
        f"skipped {report.skipped}; errors {report.errors}; deleted {report.deleted}."
    )
    if not report.apply and report.spam:
        console.print("Dry-run only. Re-run with --apply to permanently delete approved spam UIDs.")
