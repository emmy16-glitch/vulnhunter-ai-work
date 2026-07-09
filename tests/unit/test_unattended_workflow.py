"""End-to-end control-plane workflow tests."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.exceptions import UnattendedIntegrityError, UnattendedStateError
from vulnhunter.unattended.models import (
    BlockerClass,
    CommandId,
    ExecutionMode,
    PermissionManifest,
    RunState,
    ToolCapability,
)
from vulnhunter.unattended.service import (
    approve_manifest,
    complete_run,
    create_manifest,
    record_failure,
    record_task_success,
    run_fixed_command,
    start_run,
)
from vulnhunter.unattended.store import UnattendedStore


def git_repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=path, check=True)
    (path / "README.md").write_text("test\n")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "Initial"], cwd=path, check=True)
    return path.resolve()


def manifest(repository: Path) -> PermissionManifest:
    now = datetime.now(UTC)
    return PermissionManifest(
        manifest_id="manifest-workflow",
        loop_id="loop-workflow",
        repository_root=repository,
        execution_mode=ExecutionMode.LOCAL_SCHEDULED,
        available_tools=(
            ToolCapability.REPOSITORY_READ,
            ToolCapability.COMMAND_RUNNER,
        ),
        approved_read_paths=("**",),
        approved_commands=(CommandId.GIT_STATUS,),
        required_completion_commands=(CommandId.GIT_STATUS,),
        independent_task_ids=("docs-task", "tests-task"),
        created_by="creator.one",
        created_at=now,
        expires_at=now + timedelta(hours=2),
    )


def approved_run(tmp_path: Path):
    repository = git_repository(tmp_path / "repo")
    store = UnattendedStore(tmp_path / "control")
    record = create_manifest(store, manifest(repository))
    approve_manifest(
        store,
        record.manifest_id,
        approver_id="approver.one",
        reason="Reviewed the exact local command and repository boundaries.",
    )
    run = start_run(store, record.manifest_id, actor_id="scheduler.one")
    return store, record, run


def test_fixed_command_and_completion_require_real_evidence(tmp_path: Path) -> None:
    store, _, run = approved_run(tmp_path)

    with pytest.raises(UnattendedStateError, match="have not passed"):
        complete_run(store, run.run_id, actor_id="human.owner")

    evidence, updated = run_fixed_command(
        store,
        run.run_id,
        command_id=CommandId.GIT_STATUS,
        actor_id="runner.one",
    )
    assert evidence.return_code == 0
    assert updated.iterations_used == 1

    completed = complete_run(store, run.run_id, actor_id="human.owner")
    assert completed.state == RunState.COMPLETED


def test_two_identical_noncritical_failures_isolate_only_that_item(tmp_path: Path) -> None:
    store, _, run = approved_run(tmp_path)
    first, current = record_failure(
        store,
        run.run_id,
        actor_id="runner.one",
        item_id="docs-task",
        operation="write-docs",
        error_code="missing-file",
        summary="The expected documentation file does not exist.",
        blocker_class=BlockerClass.LOCAL_RECOVERABLE,
    )
    second, current = record_failure(
        store,
        run.run_id,
        actor_id="runner.one",
        item_id="docs-task",
        operation="write-docs",
        error_code="missing-file",
        summary="The expected documentation file does not exist.",
        blocker_class=BlockerClass.LOCAL_RECOVERABLE,
    )

    assert first.isolated is False
    assert second.isolated is True
    assert current.state == RunState.RUNNING
    assert current.isolated_item_ids == ("docs-task",)

    current = record_task_success(store, run.run_id, actor_id="runner.one", task_id="tests-task")
    assert current.completed_task_ids == ("tests-task",)


def test_two_critical_failures_halt_the_entire_workflow(tmp_path: Path) -> None:
    store, _, run = approved_run(tmp_path)
    for _ in range(2):
        _, current = record_failure(
            store,
            run.run_id,
            actor_id="security.verifier",
            item_id="tests-task",
            operation="verify-scope",
            error_code="scope-regression",
            summary="Scope enforcement invariant failed.",
            blocker_class=BlockerClass.SCOPE,
        )

    assert current.state == RunState.HALTED

    with pytest.raises(UnattendedStateError, match="halted"):
        record_task_success(store, run.run_id, actor_id="runner.one", task_id="docs-task")


def test_revocation_blocks_future_runtime_actions(tmp_path: Path) -> None:
    store, record, run = approved_run(tmp_path)
    store.revoke_manifest(
        record.manifest_id,
        actor_id="approver.one",
        reason="Permission withdrawn before further execution.",
    )

    with pytest.raises(UnattendedStateError, match="revoked"):
        run_fixed_command(
            store,
            run.run_id,
            command_id=CommandId.GIT_STATUS,
            actor_id="runner.one",
        )


def test_command_evidence_tampering_is_detected(tmp_path: Path) -> None:
    store, _, run = approved_run(tmp_path)
    run_fixed_command(
        store,
        run.run_id,
        command_id=CommandId.GIT_STATUS,
        actor_id="runner.one",
    )
    path = next((store.run_directory(run.run_id) / "evidence").glob("command-*.json"))
    data = json.loads(path.read_text())
    data["return_code"] = 99
    path.write_text(json.dumps(data))

    with pytest.raises(UnattendedIntegrityError, match="evidence"):
        store.verify_run(run.run_id)
