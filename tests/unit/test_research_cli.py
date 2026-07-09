"""CLI tests for the transactional research command group."""

from __future__ import annotations

from typer.testing import CliRunner

from vulnhunter.research.cli import app

runner = CliRunner()


def test_research_help_lists_transactional_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "prepare" in result.output
    assert "record-baseline" in result.output
    assert "evaluate" in result.output
    assert "decide" in result.output
    assert "promote" in result.output
    assert "meta-analyze" in result.output


def test_template_writes_strict_spec(tmp_path) -> None:
    destination = tmp_path / "experiment.json"

    result = runner.invoke(app, ["template", str(destination)])

    assert result.exit_code == 0
    assert destination.is_file()
    assert '"minimum_delta"' in destination.read_text()
