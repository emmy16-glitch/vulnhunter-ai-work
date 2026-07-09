"""CLI contract tests for explicit authorization enforcement."""

from typer.testing import CliRunner

from vulnhunter.cli import app

runner = CliRunner()


def test_root_help_lists_authorization_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "authorize" in result.stdout


def test_authorize_help_lists_lifecycle_commands() -> None:
    result = runner.invoke(app, ["authorize", "--help"])

    assert result.exit_code == 0
    for command in ("create", "list", "show", "check", "revoke", "events"):
        assert command in result.stdout


def test_scan_run_requires_authorization_option() -> None:
    result = runner.invoke(app, ["scan", "run", "http://127.0.0.1:8000/"])

    assert result.exit_code == 2
    assert "authorization" in result.output.lower()
