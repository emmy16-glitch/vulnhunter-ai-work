"""Read-only CLI tests for agent activity evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.agent_activity.cli import app
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore

runner = CliRunner()


def _write_event(root: Path) -> None:
    service = AgentActivityService(AppendOnlyActivityStore(root))
    service.record_transition(
        run_id="run-example",
        timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        event_type="run_created",
        summary="The bounded run was created.",
        run_state="created",
        source="runtime",
    )


def test_verify_cli_is_read_only(tmp_path: Path) -> None:
    _write_event(tmp_path)
    path = tmp_path / "run-example.jsonl"
    before = path.read_bytes()
    result = runner.invoke(
        app,
        ["verify", "--root", str(tmp_path), "--run-id", "run-example"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["valid"] is True
    assert path.read_bytes() == before


def test_inspect_cli_returns_ordered_json(tmp_path: Path) -> None:
    _write_event(tmp_path)
    result = runner.invoke(
        app,
        [
            "inspect",
            "--root",
            str(tmp_path),
            "--run-id",
            "run-example",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["last_sequence"] == 1
    assert payload["events"][0]["event_type"] == "run_created"
