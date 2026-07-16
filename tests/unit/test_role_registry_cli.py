from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.roles.cli import main

REGISTRY_ROOT = Path("config/roles")


def test_validate_command_prints_registry_report(capsys) -> None:
    exit_code = main(["--root", str(REGISTRY_ROOT), "validate"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["role_count"] == 18
    assert output["skill_count"] == 21
    assert output["active_role_count"] == 0


def test_list_roles_command_lists_specialists(capsys) -> None:
    exit_code = main(["--root", str(REGISTRY_ROOT), "list-roles"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "orchestrator" in output
    assert "independent-security-verifier" in output
    assert "knowledge-curator" in output


def test_show_role_command_prints_json(capsys) -> None:
    exit_code = main(["--root", str(REGISTRY_ROOT), "show-role", "dataset-quality-auditor"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["role_id"] == "dataset-quality-auditor"
    assert output["trust_assumption"] == "untrusted"


def test_check_action_returns_denied_exit_code_for_planned_role(capsys) -> None:
    exit_code = main(
        ["--root", str(REGISTRY_ROOT), "check-action", "report-writer", "report.draft"]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert output["status"] == "denied"


def test_fingerprint_command_prints_sha256(capsys) -> None:
    exit_code = main(["--root", str(REGISTRY_ROOT), "fingerprint"])
    output = capsys.readouterr().out.strip()

    assert exit_code == 0
    assert len(output) == 64
    assert all(character in "0123456789abcdef" for character in output)
