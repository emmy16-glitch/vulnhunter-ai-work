from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from vulnhunter.web.backup_recovery import (
    BackupRecoveryError,
    create_backup_bundle,
    plan_restore,
    verify_backup_bundle,
)


def _create_sqlite(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE recovery_sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO recovery_sample (value) VALUES (?)", (value,))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


@pytest.fixture
def backup_environment(tmp_path: Path, settings):
    database_paths = {
        "web_database": tmp_path / "runtime" / "web.sqlite3",
        "authorization_database": tmp_path / "runtime" / "authorization.sqlite3",
        "governance_database": tmp_path / "runtime" / "governance.sqlite3",
        "agent_database": tmp_path / "runtime" / "agent.sqlite3",
        "approval_database": tmp_path / "runtime" / "approval.sqlite3",
        "adversary_lab_database": tmp_path / "runtime" / "lab.sqlite3",
    }
    for logical_name, path in database_paths.items():
        _create_sqlite(path, logical_name)

    directory_paths = {
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
    for path in directory_paths.values():
        path.mkdir(parents=True, exist_ok=True)
    evidence = directory_paths["security_evidence"] / "campaign" / "finding.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"finding":"VH-001"}\n', encoding="utf-8")
    activity = directory_paths["agent_activity"] / "run.jsonl"
    activity.write_text('{"event":"started"}\n', encoding="utf-8")

    settings.DATABASE_ENGINE = "sqlite"
    settings.DATABASES["default"]["NAME"] = database_paths["web_database"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = database_paths["authorization_database"]
    settings.VULNHUNTER_GOVERNANCE_DATABASE = database_paths["governance_database"]
    settings.VULNHUNTER_AGENT_DATABASE = database_paths["agent_database"]
    settings.VULNHUNTER_APPROVAL_DATABASE = database_paths["approval_database"]
    settings.VULNHUNTER_ADVERSARY_LAB_DATABASE = database_paths["adversary_lab_database"]
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = directory_paths["agent_activity"]
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = directory_paths["security_evidence"]
    settings.VULNHUNTER_VERIFICATION_ROOT = directory_paths["verification"]
    settings.VULNHUNTER_TASK_GRAPH_ROOT = directory_paths["task_graphs"]
    settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT = directory_paths[
        "adversary_lab_workspaces"
    ]
    settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT = directory_paths[
        "adversary_lab_evidence"
    ]
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = directory_paths["mobile_artifacts"]
    settings.VULNHUNTER_NUCLEI_EXECUTION_ROOT = directory_paths["nuclei_executions"]
    settings.MEDIA_ROOT = directory_paths["web_media"]

    return {
        "root": tmp_path,
        "databases": database_paths,
        "directories": directory_paths,
        "evidence": evidence,
    }


def _create_verified_bundle(environment: dict[str, object]) -> Path:
    root = environment["root"]
    assert isinstance(root, Path)
    bundle = root / "backups" / "snapshot"
    result = create_backup_bundle(bundle)
    assert result["verification"] == "valid"
    return bundle


def _manifest(bundle: Path) -> dict[str, object]:
    return json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(bundle: Path, manifest: dict[str, object]) -> None:
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_sqlite_bundle_is_atomic_private_and_self_verified(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    report = verify_backup_bundle(bundle)
    manifest = _manifest(bundle)

    assert report.valid is True
    assert report.sqlite_databases == 6
    assert report.external_database_dump is False
    assert manifest["database_mode"] == "sqlite"
    assert (bundle / "data/files/security_evidence/campaign/finding.json").exists()
    with sqlite3.connect(bundle / "data/databases/web_database.sqlite3") as connection:
        assert connection.execute("SELECT value FROM recovery_sample").fetchone() == (
            "web_database",
        )

    manifest_copy = json.dumps(manifest)
    for source in backup_environment["databases"].values():
        assert str(source) not in manifest_copy
    for source in backup_environment["directories"].values():
        assert str(source) not in manifest_copy

    for candidate in (bundle, *bundle.rglob("*")):
        mode = stat.S_IMODE(candidate.stat(follow_symlinks=False).st_mode)
        assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


def test_tampered_file_fails_hash_verification(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    evidence = bundle / "data/files/security_evidence/campaign/finding.json"
    evidence.write_text("tampered\n", encoding="utf-8")

    report = verify_backup_bundle(bundle)

    assert report.valid is False
    assert report.as_payload()["checks"]["hashes_match"] == "failed"


def test_unlisted_extra_file_fails_inventory_verification(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    extra = bundle / "data" / "unexpected.txt"
    extra.write_text("unexpected\n", encoding="utf-8")
    extra.chmod(stat.S_IRUSR | stat.S_IWUSR)

    report = verify_backup_bundle(bundle)

    assert report.valid is False
    assert report.as_payload()["checks"]["files_complete"] == "failed"


def test_unsafe_manifest_path_is_rejected(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    manifest = _manifest(bundle)
    manifest["entries"][0]["relative_path"] = "../escape.sqlite3"
    _write_manifest(bundle, manifest)

    report = verify_backup_bundle(bundle)

    assert report.valid is False
    assert report.as_payload()["checks"]["paths_safe"] == "failed"


def test_corrupt_sqlite_fails_integrity_even_when_hash_is_updated(
    backup_environment,
) -> None:
    bundle = _create_verified_bundle(backup_environment)
    database = bundle / "data/databases/web_database.sqlite3"
    database.write_bytes(b"not-a-sqlite-database")
    database.chmod(stat.S_IRUSR | stat.S_IWUSR)
    manifest = _manifest(bundle)
    for entry in manifest["entries"]:
        if entry["logical_name"] == "web_database":
            entry["sha256"] = _sha256(database)
            entry["size"] = database.stat().st_size
            break
    _write_manifest(bundle, manifest)

    report = verify_backup_bundle(bundle)

    assert report.valid is False
    assert report.as_payload()["checks"]["hashes_match"] == "ok"
    assert report.as_payload()["checks"]["sqlite_integrity"] == "failed"


def test_manifest_database_mode_must_match_included_artifact(
    backup_environment,
) -> None:
    bundle = _create_verified_bundle(backup_environment)
    manifest = _manifest(bundle)
    manifest["database_mode"] = "postgresql"
    _write_manifest(bundle, manifest)

    report = verify_backup_bundle(bundle)

    assert report.valid is False
    assert report.as_payload()["checks"]["database_mode_consistent"] == "failed"


def test_source_symlink_blocks_backup_creation(backup_environment) -> None:
    evidence_root = backup_environment["directories"]["security_evidence"]
    assert isinstance(evidence_root, Path)
    target = evidence_root / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = evidence_root / "unsafe-link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are unavailable in this test environment.")
    root = backup_environment["root"]
    assert isinstance(root, Path)

    with pytest.raises(BackupRecoveryError, match="contains a symlink"):
        create_backup_bundle(root / "backups" / "blocked")


def test_destination_inside_source_tree_is_rejected(backup_environment) -> None:
    evidence_root = backup_environment["directories"]["security_evidence"]
    assert isinstance(evidence_root, Path)

    with pytest.raises(BackupRecoveryError, match="inside a source directory"):
        create_backup_bundle(evidence_root / "nested-backup")


def test_existing_destination_is_never_replaced(backup_environment) -> None:
    root = backup_environment["root"]
    assert isinstance(root, Path)
    destination = root / "backups" / "existing"
    destination.mkdir(parents=True)
    marker = destination / "marker.txt"
    marker.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(BackupRecoveryError, match="must not already exist"):
        create_backup_bundle(destination)

    assert marker.read_text(encoding="utf-8") == "preserve\n"


def test_postgresql_requires_external_dump_and_verifies_it(backup_environment, settings) -> None:
    settings.DATABASE_ENGINE = "postgresql"
    root = backup_environment["root"]
    assert isinstance(root, Path)

    with pytest.raises(BackupRecoveryError, match="require.*pg_dump"):
        create_backup_bundle(root / "backups" / "missing-postgres")

    dump = root / "external" / "database.pg_dump"
    dump.parent.mkdir(parents=True)
    dump.write_bytes(b"PGDMP\x01synthetic-safe-test")
    bundle = root / "backups" / "postgres"
    result = create_backup_bundle(bundle, postgresql_dump=dump)
    report = verify_backup_bundle(bundle)

    assert result["database_mode"] == "postgresql"
    assert result["sqlite_databases"] == 5
    assert result["external_database_dump"] is True
    assert report.valid is True
    assert report.external_database_dump is True


def test_restore_plan_is_verified_and_non_destructive(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    source_database = backup_environment["databases"]["web_database"]
    assert isinstance(source_database, Path)
    before = source_database.read_bytes()

    plan = plan_restore(bundle)

    assert plan.ready is True
    assert ("web_database", "replace_after_stop") in plan.actions
    assert ("security_evidence", "replace_after_stop") in plan.actions
    assert source_database.read_bytes() == before


def test_invalid_bundle_has_no_restore_actions(backup_environment) -> None:
    bundle = _create_verified_bundle(backup_environment)
    (bundle / "data/databases/web_database.sqlite3").write_bytes(b"tampered")

    plan = plan_restore(bundle)

    assert plan.ready is False
    assert plan.actions == ()


def test_backup_commands_create_verify_and_plan(backup_environment) -> None:
    root = backup_environment["root"]
    assert isinstance(root, Path)
    bundle = root / "backups" / "command-bundle"

    create_stdout = StringIO()
    call_command("vh_backup_create", str(bundle), stdout=create_stdout)
    assert json.loads(create_stdout.getvalue())["verification"] == "valid"

    verify_stdout = StringIO()
    call_command("vh_backup_verify", str(bundle), stdout=verify_stdout)
    assert json.loads(verify_stdout.getvalue())["status"] == "valid"

    plan_stdout = StringIO()
    call_command("vh_backup_restore_plan", str(bundle), stdout=plan_stdout)
    assert json.loads(plan_stdout.getvalue())["status"] == "ready"


def test_verify_and_plan_commands_exit_nonzero_for_tampered_bundle(
    backup_environment,
) -> None:
    bundle = _create_verified_bundle(backup_environment)
    (bundle / "data/databases/web_database.sqlite3").write_bytes(b"tampered")

    with pytest.raises(CommandError, match="backup verification failed"):
        call_command("vh_backup_verify", str(bundle), stdout=StringIO())
    with pytest.raises(CommandError, match="restore planning is blocked"):
        call_command("vh_backup_restore_plan", str(bundle), stdout=StringIO())
