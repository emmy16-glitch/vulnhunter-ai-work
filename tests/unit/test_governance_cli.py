from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.governance.cli import app

runner = CliRunner()


def test_root_cli_wires_governance_command_group() -> None:
    source = Path("vulnhunter/cli.py").read_text(encoding="utf-8")

    assert "from vulnhunter.governance.cli import app as governance_app" in source
    assert 'app.add_typer(governance_app, name="governance")' in source


def test_governance_help_lists_identity_and_campaign_groups() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    assert "identity" in result.stdout
    assert "campaign" in result.stdout


def test_identity_help_lists_lifecycle_commands() -> None:
    result = runner.invoke(app, ["identity", "--help"])

    assert result.exit_code == 0, result.output
    for command in ("bootstrap", "create", "list", "status", "reactivate", "integrity"):
        assert command in result.stdout


def test_campaign_help_lists_governed_workflow_commands() -> None:
    result = runner.invoke(app, ["campaign", "--help"])

    assert result.exit_code == 0, result.output
    for command in (
        "create",
        "add-application",
        "approve",
        "activate",
        "link-scan",
        "assign",
        "review",
        "adjudicate",
        "status",
        "release-check",
        "complete",
        "release",
    ):
        assert command in result.stdout


def test_bootstrap_rejects_short_secret_without_creating_registry(tmp_path) -> None:
    database = tmp_path / "governance.db"
    result = runner.invoke(
        app,
        [
            "identity",
            "bootstrap",
            "--reviewer",
            "admin-a",
            "--display-name",
            "Administrator",
            "--secret",
            "short",
            "--governance-database",
            str(database),
        ],
    )

    assert result.exit_code == 2
    assert "12 characters" in result.output
