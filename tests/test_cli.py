from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from imapledger import cli


def test_folders_help_describes_read_only_command_and_options() -> None:
    result = CliRunner().invoke(cli.app, ["folders", "--help"])

    assert result.exit_code == 0
    assert "without reading message contents" in result.output
    assert "mutating" in result.output
    for option in ("--config", "--host", "--username", "--port", "--counts", "--no-counts", "--verbose"):
        assert option in result.output


def test_auth_status_reports_prompt_source_without_secret_or_connection(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[imap]\nhost = "imap.example.org"\nusername = "user@example.org"\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli.app, ["auth", "status", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "configured source: prompt" in result.output
    assert "stored credential: no" in result.output
    assert "password" not in result.output.lower()
