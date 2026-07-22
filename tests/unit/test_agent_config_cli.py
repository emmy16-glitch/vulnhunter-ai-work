from __future__ import annotations

import json

from vulnhunter.agent.cli import main
from vulnhunter.agent.config import load_runtime_config, runtime_config_fingerprint


def test_repository_runtime_config_loads() -> None:
    config = load_runtime_config()
    assert config.connectors_enabled is False
    assert config.unrestricted_shell_enabled is False
    assert len(runtime_config_fingerprint(config)) == 64


def test_validate_config_cli(capsys) -> None:
    assert main(["validate-config"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["runtime"]["public_scanning_enabled"] is False


def test_demo_cli_runs_real_bounded_loop(tmp_path, capsys) -> None:
    database = tmp_path / "demo.db"
    assert (
        main(
            [
                "demo",
                "--database",
                str(database),
                "--task-id",
                "demo-task",
                "--value",
                "hello",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "completed"
    assert output["tool_call_count"] == 1


def test_verify_audit_cli(tmp_path, capsys) -> None:
    database = tmp_path / "demo.db"
    main(["demo", "--database", str(database), "--task-id", "demo-task"])
    capsys.readouterr()
    assert main(["verify-audit", "--database", str(database), "demo-task"]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_show_cli_returns_task_and_events(tmp_path, capsys) -> None:
    database = tmp_path / "demo.db"
    main(["demo", "--database", str(database), "--task-id", "demo-task"])
    capsys.readouterr()
    assert main(["show", "--database", str(database), "demo-task"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["task"]["task_id"] == "demo-task"
    assert output["events"]
