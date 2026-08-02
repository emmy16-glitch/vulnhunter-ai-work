from __future__ import annotations

import json
import sqlite3
import stat
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from vulnhunter.web.backup_recovery import BackupRecoveryError, create_backup_bundle
from vulnhunter.web.restore_execution import (
    backup_bundle_digest,
    execute_verified_sqlite_restore,
)


def _create_sqlite(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE recovery_sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO recovery_sample (value) VALUES (?)", (value,))


def _replace_value(path: Path, value: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE recovery_sample SET value = ?", (value,))


def _read_value(path: Path) -> str:
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT value FROM recovery_sample").fetchone()
    assert row is not None
    return str(row[0])


@pytest.fixture
def restore_environment(tmp_path: Path, settings):
    databases = {
        "web_database": tmp_path / "runtime" / "web.sqlite3",
        "authorization_database": tmp_path / "runtime" / "authorization.sqlite3",
        "governance_database": tmp_path / "runtime" / "governance.sqlite3",
        "agent_database": tmp_path / "runtime" / "agent.sqlite3",
        "approval_database": tmp_path / "runtime" / "approval.sqlite3",
        "adversary_lab_database": tmp_path / "runtime" / "lab.sqlite3",
    }
    for logical_name, path in databases.items():
        _create_sqlite(path, f"backup-{logical_name}")

    directories = {
        "agent_activity": tmp_path / "state" / "activity",
        "security_evidence": tmp_path / "state" / "evidence",
        "verification": tmp_path / "state" / "verification",
        "task_graphs": tmp_path / "state" / "task-graphs",
        "adversary_lab_workspaces": tmp_path / "state" / "lab-workspaces",
        "adversary_lab_evidence": tmp_path / "state" / "lab-evidence",
        "mobile_artifacts": tmp_path / "state" / "mobile",
        "nuclei_executions": tmp_path / "state" / "nuclei",
        "web_media": tmp_path / "state" / "media",
    }
    for path in directories.values():
        path.mkdir(parents=True)

    settings.DATABASE_ENGINE = "sqlite"
    settings.DATABASES["default"]["NAME"] = databases["web_database"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = databases["authorization_database"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = databases["governance_database"]
    settings.VULNHUNTER_AGENT_DATABASE = databases["agent_database"]
    settings.VULNHUNTER_APPROVAL_DATABASE = databases["approval_database"]
    settings.VULNHUNTER_ADVERSARY_LAB_DATABASE = databases["adversary_lab_database"]
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = directories["agent_activity"]
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = directories["security_evidence"]
    settings.VULNHUNTER_VERIFICATION_ROOT = directories["verification"]
    settings.VULNHUNTER_TASK_GRAPH_ROOT = directories["task_graphs"]
    settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT = directories[
        "adversary_lab_workspaces"
    ]
    settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT = directories[
        "adversary_lab_evidence"
    ]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = directories["mobile_artifacts"]
    settings.VULNHUNTER_NUCLEI_EXECUTION_ROOT = directories["nuclei_executions"]
    settings.MEDIA_ROOT = directories["web_media"]

    bundle = tmp_path / "backups" / "snapshot"
    create_backup_bundle(bundle)
    digest = backup_bundle_digest(bundle)
    marker = tmp_path / "maintenance.json"
    marker.write_text(
        json.dumps(
            {
                "application": "vulnhunter",
                "maintenance": True,
                "database_mode": "sqlite",
                "bundle_digest": digest,
            }
        ),
        encoding="utf-8",
    )
    marker.chmod(stat.S_IRUSR | stat.S_IWUSR)

    for logical_name, path in databases.items():
        _replace_value(path, f"live-{logical_name}")

    return {
        "root": tmp_path,
        "databases": databases,
        "bundle": bundle,
        "digest": digest,
        "marker": marker,
    }


def test_verified_restore_replaces_all_sqlite_databases(restore_environment) -> None:
    rollback = restore_environment["root"] / "rollback"
    result = execute_verified_sqlite_restore(
        restore_environment["bundle"],
        expected_bundle_digest=restore_environment["digest"],
        maintenance_marker=restore_environment["marker"],
        rollback_directory=rollback,
    )

    assert result.databases_restored == 6
    assert result.rollback_directory == rollback
    for logical_name, path in restore_environment["databases"].items():
        assert _read_value(path) == f"backup-{logical_name}"
        assert _read_value(rollback / f"{logical_name}.sqlite3") == f"live-{logical_name}"


def test_restore_rejects_digest_or_marker_mismatch(restore_environment) -> None:
    with pytest.raises(BackupRecoveryError, match="digest does not match"):
        execute_verified_sqlite_restore(
            restore_environment["bundle"],
            expected_bundle_digest="0" * 64,
            maintenance_marker=restore_environment["marker"],
            rollback_directory=restore_environment["root"] / "rollback-digest",
        )

    restore_environment["marker"].chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    with pytest.raises(BackupRecoveryError, match="permissions"):
        execute_verified_sqlite_restore(
            restore_environment["bundle"],
            expected_bundle_digest=restore_environment["digest"],
            maintenance_marker=restore_environment["marker"],
            rollback_directory=restore_environment["root"] / "rollback-marker",
        )


def test_restore_rolls_back_replaced_databases_on_failure(
    restore_environment, monkeypatch
) -> None:
    from vulnhunter.web import restore_execution

    original_atomic_replace = restore_execution._atomic_replace
    calls = 0

    def fail_second_restore(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BackupRecoveryError("simulated restore failure")
        original_atomic_replace(source, destination)

    monkeypatch.setattr(restore_execution, "_atomic_replace", fail_second_restore)

    with pytest.raises(BackupRecoveryError, match="rolled back"):
        execute_verified_sqlite_restore(
            restore_environment["bundle"],
            expected_bundle_digest=restore_environment["digest"],
            maintenance_marker=restore_environment["marker"],
            rollback_directory=restore_environment["root"] / "rollback-failure",
        )

    for logical_name, path in restore_environment["databases"].items():
        assert _read_value(path) == f"live-{logical_name}"


def test_restore_management_command_returns_redacted_status(restore_environment) -> None:
    output = StringIO()
    rollback = restore_environment["root"] / "rollback-command"
    call_command(
        "vh_backup_restore_execute",
        restore_environment["bundle"],
        bundle_digest=restore_environment["digest"],
        maintenance_marker=restore_environment["marker"],
        rollback_directory=rollback,
        stdout=output,
    )
    payload = json.loads(output.getvalue())

    assert payload == {
        "bundle_digest": restore_environment["digest"],
        "databases_restored": 6,
        "rollback_retained": True,
        "status": "restored",
    }
    assert str(rollback) not in output.getvalue()


def test_restore_command_fails_closed_without_exact_digest(restore_environment) -> None:
    with pytest.raises(CommandError, match="digest does not match"):
        call_command(
            "vh_backup_restore_execute",
            restore_environment["bundle"],
            bundle_digest="f" * 64,
            maintenance_marker=restore_environment["marker"],
            rollback_directory=restore_environment["root"] / "rollback-command-failure",
        )
