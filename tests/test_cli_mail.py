from __future__ import annotations

from typer.testing import CliRunner

from imapledger import cli


def test_removed_mail_classifier_points_to_unified_rules() -> None:
    result = CliRunner().invoke(cli.app, ["mail", "classify", "10", "--folder", "INBOX"])

    assert result.exit_code == 2
    assert "was removed" in result.output
    assert "rule evaluate" in result.output


def test_ui_remains_an_explicit_command() -> None:
    runner = CliRunner()
    no_args = runner.invoke(cli.app, [])
    ui_help = runner.invoke(cli.app, ["ui", "--help"])

    assert no_args.exit_code == 2
    assert "Usage:" in no_args.output
    assert ui_help.exit_code == 0
    assert "interactive terminal mail review console" in ui_help.output
