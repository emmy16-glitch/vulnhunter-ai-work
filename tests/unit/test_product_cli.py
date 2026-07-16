from __future__ import annotations

import json
from pathlib import Path

from governance_test_support import make_governance_store
from test_governance_workflow import prepare_world

from vulnhunter.product.cli import main


def test_status_command_reports_missing_store_state(capsys, tmp_path: Path) -> None:
    assert (
        main(
            [
                "--authorization-database",
                str(tmp_path / "auth.db"),
                "--governance-database",
                str(tmp_path / "governance.db"),
                "--agent-database",
                str(tmp_path / "agent.db"),
                "status",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["authorization_store"]["state"] == "missing"
    assert payload["governance_store"]["state"] == "missing"


def test_campaign_command_uses_real_governed_state(capsys, tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)

    assert (
        main(
            [
                "--authorization-database",
                str(tmp_path / "auth.db"),
                "--governance-database",
                str(tmp_path / "governance.db"),
                "campaign",
                world["campaign"].campaign_id,
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["campaign_id"] == world["campaign"].campaign_id
    assert payload["scans"][0]["scan_id"] == world["scan_id"]
