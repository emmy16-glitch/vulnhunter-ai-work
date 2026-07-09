"""CLI tests for controlled benchmark commands."""

from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.cli import app

runner = CliRunner()


def test_benchmark_help_lists_safe_workflow_commands() -> None:
    result = runner.invoke(app, ["benchmark", "--help"])

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "status" in result.stdout
    assert "review" in result.stdout
    assert "train" in result.stdout


def test_benchmark_run_and_status_cli(tmp_path: Path) -> None:
    database = tmp_path / "benchmark.db"
    manifest = tmp_path / "manifest.json"

    run_result = runner.invoke(
        app,
        [
            "benchmark",
            "run",
            "--database",
            str(database),
            "--manifest",
            str(manifest),
        ],
    )
    status_result = runner.invoke(
        app,
        [
            "benchmark",
            "status",
            "--database",
            str(database),
            "--manifest",
            str(manifest),
        ],
    )

    assert run_result.exit_code == 0, run_result.stdout
    assert "Controlled benchmark completed" in run_result.stdout
    assert "synthetic" in run_result.stdout
    assert status_result.exit_code == 0, status_result.stdout
    assert "Pending review:" in status_result.stdout
    assert "Review complete: no" in status_result.stdout
