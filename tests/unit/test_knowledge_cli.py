"""CLI tests for the controlled project-knowledge system."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.knowledge.cli import app

runner = CliRunner()


def test_cli_initialises_and_registers_source(tmp_path: Path) -> None:
    root = tmp_path / "knowledge"
    source = tmp_path / "source.txt"
    source.write_text("A local authorised source.", encoding="utf-8")

    initialised = runner.invoke(app, ["init", "--root", str(root)])
    assert initialised.exit_code == 0
    assert "Knowledge store initialised" in initialised.stdout

    registered = runner.invoke(
        app,
        [
            "register",
            str(source),
            "--title",
            "Local source",
            "--origin",
            "Test fixture",
            "--type",
            "report",
            "--sensitivity",
            "internal",
            "--trust",
            "medium",
            "--root",
            str(root),
        ],
    )

    assert registered.exit_code == 0
    assert "Source registered safely" in registered.stdout
    assert "Prompt-injection review: not_detected" in registered.stdout


def test_cli_duplicate_registration_fails_cleanly(tmp_path: Path) -> None:
    root = tmp_path / "knowledge"
    source = tmp_path / "source.txt"
    source.write_text("duplicate", encoding="utf-8")
    arguments = [
        "register",
        str(source),
        "--title",
        "Local source",
        "--origin",
        "Test fixture",
        "--type",
        "report",
        "--sensitivity",
        "internal",
        "--trust",
        "medium",
        "--root",
        str(root),
    ]

    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)

    assert first.exit_code == 0
    assert second.exit_code == 2
    assert "already registered" in second.stderr
