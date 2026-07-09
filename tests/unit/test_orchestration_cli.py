"""CLI surface tests for the orchestration harness."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vulnhunter.cli import app as main_app
from vulnhunter.orchestration.cli import app

runner = CliRunner()


def test_template_command_writes_complete_specification(tmp_path) -> None:
    destination = tmp_path / "loop-spec.json"

    result = runner.invoke(app, ["template", str(destination)])

    assert result.exit_code == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["objective"]
    assert len(payload["allowed_actions"]) == 4
    assert payload["verifiers"]
    assert payload["recovery_instructions"]


def test_template_refuses_to_overwrite_existing_file(tmp_path) -> None:
    destination = tmp_path / "loop-spec.json"
    destination.write_text("existing", encoding="utf-8")

    result = runner.invoke(app, ["template", str(destination)])

    assert result.exit_code == 2
    assert "already exists" in result.output
    assert destination.read_text(encoding="utf-8") == "existing"


def test_main_cli_exposes_loop_command_group() -> None:
    result = runner.invoke(main_app, ["loop", "--help"])

    assert result.exit_code == 0
    assert "bounded engineering loops" in result.output.lower()
    assert "security-check" in result.output
    assert "recovery-plan" in result.output
    assert "evidence" in result.output
    assert "escalate" in result.output
