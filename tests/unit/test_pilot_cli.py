"""CLI tests for controlled pilot-plan validation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.pilot.cli import app

runner = CliRunner()
EXAMPLE = Path("config/pilot/example-plan.json")
NOW = "2026-07-10T00:00:00Z"


def test_text_output_is_read_only() -> None:
    before = EXAMPLE.read_bytes()
    result = runner.invoke(
        app,
        [
            "validate",
            "--plan",
            str(EXAMPLE),
            "--format",
            "text",
            "--assessed-at",
            NOW,
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Valid: True" in result.output
    assert EXAMPLE.read_bytes() == before


def test_json_output_and_export(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "validate",
            "--plan",
            str(EXAMPLE),
            "--format",
            "json",
            "--assessed-at",
            NOW,
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    displayed = json.loads(result.output)
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert displayed == exported
    assert displayed["valid"] is True


def test_invalid_plan_returns_nonzero(tmp_path: Path) -> None:
    payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    payload["automatic_campaign_approval"] = True
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(
        app,
        ["validate", "--plan", str(path), "--assessed-at", NOW],
    )
    assert result.exit_code == 1
    assert "automatic campaign approval" in result.output


def test_malformed_plan_returns_schema_error(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"schema_version":"9"}', encoding="utf-8")
    result = runner.invoke(app, ["validate", "--plan", str(path)])
    assert result.exit_code == 2
    assert "schema validation" in result.output
