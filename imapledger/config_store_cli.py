from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import timezone
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from .config import (
    ConfigError,
    ConfigStoreContext,
    default_config_path,
    load_config_store_context,
    load_optional_config_store_settings,
)
from .config_diff import DiffDirection
from .config_errors import ConfigLedgerError
from .config_ledger import ConfigLedger, ConfigToolStatus
from .config_mailbox import ConfigStoreMailbox, ConfigStoreOperationError

PasswordResolver = Callable[[Any], str]


def register_config_store_commands(app: typer.Typer, *, resolve_password: PasswordResolver) -> None:
    def run(config: Path, *, writable: bool, operation: Callable[[ConfigLedger, ConfigStoreContext], Any]) -> Any:
        try:
            context = load_config_store_context(config)
        except ConfigError as exc:
            typer.echo(f"Configuration error: {exc}", err=True)
            raise typer.Exit(2) from exc
        password = resolve_password(context.imap)
        try:
            mailbox = ConfigStoreMailbox(
                host=context.imap.host,
                port=context.imap.port,
                username=context.imap.username,
                password=password,
                folder=context.store.folder,
                max_file_bytes=context.store.max_file_bytes,
                writable=writable,
            )
            password = ""
            with mailbox:
                return operation(ConfigLedger(mailbox, context.store), context)
        except ConfigStoreOperationError as exc:
            typer.echo(f"IMAP error: {exc}", err=True)
            raise typer.Exit(2) from exc
        except ConfigLedgerError as exc:
            typer.echo(f"Configuration ledger error: {exc}", err=True)
            raise typer.Exit(2) from exc
        finally:
            password = ""

    def config_list(
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
        verbose: bool = typer.Option(False, "-v", "--verbose", help="Show corruption details"),
    ) -> None:
        """List local snapshots, or report clearly when the optional store is disabled."""
        try:
            store_settings = load_optional_config_store_settings(config)
        except ConfigError as exc:
            typer.echo(f"Configuration error: {exc}", err=True)
            raise typer.Exit(2) from exc
        if store_settings is None:
            typer.echo("Config store: disabled. Add a [config_store] table to enable remote snapshots.")
            return

        def operation(ledger: ConfigLedger, _context: ConfigStoreContext) -> None:
            summaries = ledger.list_tools()
            if not summaries:
                typer.echo("No configuration snapshots stored.")
                return
            table = Table(title="Stored configurations")
            table.add_column("Tool")
            table.add_column("Versions", justify="right")
            table.add_column("Status")
            table.add_column("Current")
            table.add_column("Default path")
            for summary in summaries:
                current = summary.current or ""
                if summary.status is ConfigToolStatus.CONFLICT:
                    current = f"{summary.heads} heads"
                table.add_row(
                    summary.tool,
                    str(summary.versions),
                    summary.status.value,
                    current,
                    summary.default_path or "",
                )
            Console(file=sys.stdout).print(table, markup=False)
            if verbose:
                for summary in summaries:
                    for detail in summary.details:
                        typer.echo(f"{summary.tool}: {detail}", err=True)

        run(config, writable=False, operation=operation)

    def config_versions(
        tool: str,
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
        verbose: bool = typer.Option(False, "-v", "--verbose", help="Show transport metadata"),
    ) -> None:
        def operation(ledger: ConfigLedger, _context: ConfigStoreContext) -> None:
            versions = ledger.list_versions(tool)
            table = Table(title=f"Configuration versions: {tool.lower()}")
            table.add_column("Current")
            table.add_column("Version")
            table.add_column("Created")
            table.add_column("SHA256")
            table.add_column("Size", justify="right")
            table.add_column("Default path")
            for record in versions:
                meta = record.meta
                current = "*" if record.current else "HEAD" if record.head else ""
                table.add_row(
                    current,
                    meta.version_id,
                    meta.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
                    meta.content_sha256[:12],
                    _human_size(meta.size_bytes),
                    meta.default_path,
                )
            Console(file=sys.stdout).print(table, markup=False)
            if verbose:
                for record in versions:
                    meta = record.meta
                    typer.echo(
                        f"{meta.version_id}: UID={meta.uid} UIDVALIDITY={meta.uidvalidity} "
                        f"Message-ID={meta.message_id or ''} parents={','.join(meta.parent_version_ids)} "
                        f"sha256={meta.content_sha256}",
                        err=True,
                    )

        run(config, writable=False, operation=operation)

    def config_push(
        tool: str,
        path: Path,
        allow_sensitive_plaintext: bool = typer.Option(
            False,
            "--allow-sensitive-plaintext",
            help="Acknowledge storing detected sensitive values as readable email",
        ),
        resolve_conflict: bool = typer.Option(False, "--resolve-conflict", help="Parent all current history heads"),
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    ) -> None:
        def operation(ledger: ConfigLedger, context: ConfigStoreContext) -> None:
            result = ledger.push(
                tool,
                path,
                allow_sensitive_plaintext=allow_sensitive_plaintext,
                resolve_conflict=resolve_conflict,
            )
            if not result.created:
                typer.echo(
                    f"{tool.lower()} is already current.\nversion: {result.snapshot.version_id}\nno snapshot created"
                )
                return
            parents = result.snapshot.parent_version_ids
            current = parents[0] if len(parents) == 1 else f"{len(parents)} heads" if parents else "none"
            typer.echo(f"tool: {result.snapshot.tool}")
            typer.echo(f"local: {path.expanduser().resolve()}")
            typer.echo(f"imap folder: {context.store.folder}")
            typer.echo(f"current: {current}")
            typer.echo(f"pushed: {result.snapshot.version_id}")
            typer.echo(f"sha256: {result.snapshot.content_sha256}")

        run(config, writable=True, operation=operation)

    def config_pull(
        tool: str,
        version: str | None = typer.Option(None, "--version", help="Snapshot version ID or unambiguous prefix"),
        to: Path | None = typer.Option(None, "--to", help="Override the stored default path"),  # noqa: B008
        force: bool = typer.Option(False, "--force", help="Overwrite without prompting or showing a diff"),
        show_diff: bool = typer.Option(False, "--show-diff", help="Show a diff when used with --force"),
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    ) -> None:
        def operation(ledger: ConfigLedger, _context: ConfigStoreContext) -> None:
            def confirm(target: Path, diff: str) -> bool:
                if diff:
                    typer.echo(diff, nl=False)
                return typer.confirm(f"Overwrite {target}?", default=False)

            result = ledger.pull(
                tool,
                version=version,
                to=to,
                force=force,
                show_diff=show_diff,
                confirm_overwrite=confirm,
                show_diff_callback=(lambda _target, diff: typer.echo(diff, nl=False)) if force and show_diff else None,
            )
            if result.already_up_to_date:
                typer.echo(f"{result.target} is already up to date.")
            elif result.cancelled:
                typer.echo("No changes made.")
            else:
                typer.echo(f"Wrote {result.target}")

        run(config, writable=False, operation=operation)

    def config_diff(
        tool: str,
        version: str | None = typer.Option(None, "--version", help="Snapshot version ID or unambiguous prefix"),
        path: Path | None = typer.Option(None, "--path", help="Local file to compare"),  # noqa: B008
        direction: DiffDirection = typer.Option(..., "--direction", help="Diff direction"),  # noqa: B008
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    ) -> None:
        def operation(ledger: ConfigLedger, _context: ConfigStoreContext) -> None:
            diff = ledger.diff(tool, version=version, path=path, direction=direction)
            if diff:
                typer.echo(diff, nl=False)
                raise typer.Exit(1)

        run(config, writable=False, operation=operation)

    def config_cat(
        tool: str,
        version: str | None = typer.Option(None, "--version", help="Snapshot version ID or unambiguous prefix"),
        config: Path = typer.Option(default_config_path(), "--config", help="Configuration file"),  # noqa: B008
    ) -> None:
        def operation(ledger: ConfigLedger, _context: ConfigStoreContext) -> None:
            typer.echo(ledger.cat(tool, version=version), nl=False)

        run(config, writable=False, operation=operation)

    app.command("list")(config_list)
    app.command("versions")(config_versions)
    app.command("push")(config_push)
    app.command("pull")(config_pull)
    app.command("diff")(config_diff)
    app.command("cat")(config_cat)


def _human_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}K"
    return f"{size_bytes / (1024 * 1024):.1f}M"
