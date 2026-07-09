"""CLI tests for the unattended-operations control plane."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.unattended.cli import app

runner = CliRunner()


def test_help_lists_control_plane_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "recommend" in result.output
    assert "approve" in result.output
    assert "run-command" in result.output
    assert "record-failure" in result.output
    assert "revoke" in result.output


def test_template_writes_conservative_manifest(tmp_path: Path) -> None:
    destination = tmp_path / "permissions.json"

    result = runner.invoke(
        app,
        ["template", str(destination), "--repository", str(tmp_path)],
    )

    assert result.exit_code == 0
    data = json.loads(destination.read_text())
    assert data["allow_git_push"] is False
    assert data["allow_delete"] is False
    assert data["allow_deploy"] is False
    assert data["network_access"] == "none"


def test_recommend_rejects_sensitive_remote_profile(tmp_path: Path) -> None:
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps(
            {
                "remote_execution_required": True,
                "contains_sensitive_security_data": True,
            }
        )
    )

    result = runner.invoke(app, ["recommend", str(profile)])

    assert result.exit_code == 1
    assert "Permitted: no" in result.output
