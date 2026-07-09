"""Business rules for the unattended-operations control plane."""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import (
    UnattendedPolicyError,
    UnattendedStateError,
)
from vulnhunter.security import redact_text
from vulnhunter.unattended.models import (
    ActionKind,
    ApprovalRecord,
    BlockerClass,
    CommandId,
    ExecutionMode,
    FailureRecord,
    NetworkAccess,
    PermissionManifest,
    RunRecord,
    RunState,
    TaskProfile,
    ToolCapability,
    normalize_actor_id,
)
from vulnhunter.unattended.policy import PermissionEnforcer, recommend_execution_mode
from vulnhunter.unattended.runner import execute_command
from vulnhunter.unattended.store import UnattendedStore


def _git_commit(repository: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise UnattendedStateError("Repository must be a readable Git worktree.") from exc


def load_manifest_spec(path: Path) -> PermissionManifest:
    """Load a strict permission manifest JSON file."""
    try:
        return PermissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise UnattendedPolicyError(f"Permission manifest is invalid: {exc}") from exc


def write_manifest_template(destination: Path, *, repository: Path) -> Path:
    """Write a conservative local scheduled manifest template."""
    now = datetime.now(UTC)
    template = PermissionManifest(
        manifest_id="manifest-example",
        loop_id="loop-example",
        repository_root=repository.expanduser().resolve(),
        execution_mode=ExecutionMode.LOCAL_SCHEDULED,
        available_tools=(
            ToolCapability.REPOSITORY_READ,
            ToolCapability.COMMAND_RUNNER,
        ),
        approved_read_paths=("vulnhunter/**", "tests/**", "docs/**"),
        approved_commands=(
            CommandId.RUFF_CHECK,
            CommandId.COMPILE,
            CommandId.PYTEST,
            CommandId.RUFF_FORMAT_CHECK,
            CommandId.GIT_DIFF_CHECK,
        ),
        required_completion_commands=(
            CommandId.RUFF_CHECK,
            CommandId.COMPILE,
            CommandId.PYTEST,
            CommandId.RUFF_FORMAT_CHECK,
            CommandId.GIT_DIFF_CHECK,
        ),
        created_by="human.owner",
        created_at=now,
        expires_at=now + timedelta(days=365),
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(template.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return destination


def create_manifest(store: UnattendedStore, manifest: PermissionManifest) -> PermissionManifest:
    """Persist one immutable permission manifest."""
    if manifest.repository_root.expanduser().resolve() != manifest.repository_root:
        raise UnattendedPolicyError("Repository root must be an absolute resolved path.")
    if not manifest.repository_root.is_dir():
        raise UnattendedPolicyError("Repository root does not exist.")
    store.create_manifest(manifest)
    return manifest


def approve_manifest(
    store: UnattendedStore,
    manifest_id: str,
    *,
    approver_id: str,
    reason: str,
) -> ApprovalRecord:
    """Bind explicit human approval to the exact manifest bytes."""
    manifest = store.load_manifest(manifest_id)
    approver = normalize_actor_id(approver_id)
    if approver == manifest.created_by:
        raise UnattendedStateError("Manifest creator and approver must be distinct actors.")
    now = datetime.now(UTC)
    approval = ApprovalRecord(
        manifest_id=manifest_id,
        manifest_sha256=store.manifest_sha256(manifest_id),
        approved_by=approver,
        approved_at=now,
        expires_at=manifest.expires_at,
        reason=reason,
    )
    store.save_approval(approval)
    return approval


def start_run(
    store: UnattendedStore,
    manifest_id: str,
    *,
    actor_id: str,
) -> RunRecord:
    """Start a run only from an active, intact, approved manifest."""
    manifest = _require_active_manifest(store, manifest_id)
    now = datetime.now(UTC)
    run = RunRecord(
        run_id=f"run-{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}",
        manifest_id=manifest_id,
        manifest_sha256=store.manifest_sha256(manifest_id),
        repository_commit=_git_commit(manifest.repository_root),
        state=RunState.RUNNING,
        started_by=normalize_actor_id(actor_id),
        started_at=now,
        updated_at=now,
    )
    store.create_run(run)
    return run


def _require_active_manifest(store: UnattendedStore, manifest_id: str) -> PermissionManifest:
    manifest = store.verify_manifest(manifest_id)
    approval = store.load_approval(manifest_id)
    now = datetime.now(UTC)
    if store.is_revoked(manifest_id):
        raise UnattendedStateError("Permission manifest has been revoked.")
    if manifest.expires_at <= now or approval.expires_at <= now:
        raise UnattendedStateError("Permission manifest or approval has expired.")
    return manifest


def check_action(
    store: UnattendedStore,
    manifest_id: str,
    *,
    action: ActionKind,
    value: str,
):
    """Evaluate one runtime action against the approved manifest."""
    manifest = _require_active_manifest(store, manifest_id)
    enforcer = PermissionEnforcer(manifest)
    if action == ActionKind.TOOL:
        decision = enforcer.check_tool(ToolCapability(value))
    elif action == ActionKind.COMMAND:
        decision = enforcer.check_command(value)
    elif action == ActionKind.READ_PATH:
        decision = enforcer.check_path(Path(value))
    elif action == ActionKind.WRITE_PATH:
        decision = enforcer.check_path(Path(value), write=True)
    elif action == ActionKind.DELETE_PATH:
        decision = enforcer.check_path(Path(value), write=True, delete=True)
    elif action == ActionKind.NETWORK:
        kind, _, host = value.partition(":")
        decision = enforcer.check_network(NetworkAccess(kind), host)
    elif action == ActionKind.CONNECTOR:
        decision = enforcer.check_connector(value)
    elif action == ActionKind.SECRET:
        decision = enforcer.check_secret(value)
    elif action == ActionKind.GIT_PUSH:
        decision = enforcer.check_git_push()
    elif action == ActionKind.DEPLOY:
        decision = enforcer.check_deploy()
    else:  # pragma: no cover - enum exhaustiveness
        raise UnattendedPolicyError(f"Unsupported action: {action}")
    store.append_event(
        manifest_id,
        "permission_checked",
        "runtime.enforcer",
        decision.model_dump(mode="json"),
    )
    return decision


def run_fixed_command(
    store: UnattendedStore,
    run_id: str,
    *,
    command_id: CommandId,
    actor_id: str,
    timeout_seconds: int = 300,
):
    """Execute one fixed command after runtime permission and budget checks."""
    run = store.verify_run(run_id)
    manifest = _require_active_manifest(store, run.manifest_id)
    if run.state != RunState.RUNNING:
        raise UnattendedStateError(f"Run {run_id} is not running.")
    now = datetime.now(UTC)
    if now >= manifest.expires_at:
        raise UnattendedStateError("Permission manifest has expired.")
    if (now - run.started_at).total_seconds() >= manifest.maximum_runtime_seconds:
        raise UnattendedStateError("Run exceeded its maximum runtime.")
    if run.iterations_used >= manifest.maximum_iterations:
        raise UnattendedStateError("Run exceeded its maximum iteration count.")
    enforcer = PermissionEnforcer(manifest)
    enforcer.require(enforcer.check_tool(ToolCapability.COMMAND_RUNNER))
    enforcer.require(enforcer.check_command(command_id.value))
    actor = normalize_actor_id(actor_id)
    elapsed = (now - run.started_at).total_seconds()
    remaining = max(1, int(manifest.maximum_runtime_seconds - elapsed))
    evidence = execute_command(
        command_id,
        repository=manifest.repository_root,
        run_id=run_id,
        actor_id=actor,
        timeout_seconds=min(timeout_seconds, remaining),
    )
    path = store.save_command_evidence(evidence)
    updated = run.model_copy(
        update={
            "iterations_used": run.iterations_used + 1,
            "updated_at": datetime.now(UTC),
            "last_error": None
            if evidence.return_code == 0
            else f"{command_id.value}:{evidence.return_code}",
        }
    )
    store.save_run(updated)
    store.append_event(
        run_id,
        "command_executed",
        actor,
        {
            "command_id": command_id.value,
            "return_code": evidence.return_code,
            "timed_out": evidence.timed_out,
            "evidence_file": path.relative_to(store.run_directory(run_id)).as_posix(),
            "evidence_sha256": evidence.evidence_sha256,
        },
        run=True,
    )
    return evidence, updated


def record_failure(
    store: UnattendedStore,
    run_id: str,
    *,
    actor_id: str,
    item_id: str,
    operation: str,
    error_code: str,
    summary: str,
    blocker_class: BlockerClass,
) -> tuple[FailureRecord, RunRecord]:
    """Isolate an item after two materially identical failures."""
    run = store.verify_run(run_id)
    if run.state not in {RunState.RUNNING, RunState.BLOCKED}:
        raise UnattendedStateError("Failures can only be recorded for active runs.")
    manifest = _require_active_manifest(store, run.manifest_id)
    normalized = {
        "item_id": item_id.strip().lower(),
        "operation": operation.strip().lower(),
        "error_code": error_code.strip().lower(),
        "summary": " ".join(redact_text(summary).lower().split()),
        "blocker_class": blocker_class.value,
    }
    fingerprint = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    prior = [item for item in store.failures(run_id) if item.fingerprint == fingerprint]
    occurrence = len(prior) + 1
    isolated = occurrence >= manifest.maximum_repeated_failures
    halted = isolated and blocker_class.halts_workflow
    isolated_items = set(run.isolated_item_ids)
    if isolated:
        isolated_items.add(normalized["item_id"])
    independent_remaining = (
        set(manifest.independent_task_ids) - isolated_items - set(run.completed_task_ids)
    )
    state = run.state
    if halted:
        state = RunState.HALTED
    elif isolated and not independent_remaining:
        state = RunState.BLOCKED
    elif isolated:
        state = RunState.RUNNING
    record = FailureRecord(
        run_id=run_id,
        item_id=normalized["item_id"],
        operation=normalized["operation"],
        error_code=normalized["error_code"],
        summary=normalized["summary"],
        blocker_class=blocker_class,
        fingerprint=fingerprint,
        occurrence=occurrence,
        isolated=isolated,
        workflow_halted=halted,
        recorded_at=datetime.now(UTC),
    )
    store.append_failure(record)
    updated = run.model_copy(
        update={
            "state": state,
            "updated_at": datetime.now(UTC),
            "isolated_item_ids": tuple(sorted(isolated_items)),
            "last_error": f"{blocker_class.value}:{record.error_code}",
        }
    )
    store.save_run(updated)
    store.append_event(
        run_id,
        "failure_recorded",
        normalize_actor_id(actor_id),
        record.model_dump(mode="json"),
        run=True,
    )
    return record, updated


def record_task_success(
    store: UnattendedStore,
    run_id: str,
    *,
    actor_id: str,
    task_id: str,
) -> RunRecord:
    """Record progress for one declared independent task."""
    run = store.verify_run(run_id)
    manifest = _require_active_manifest(store, run.manifest_id)
    normalized = task_id.strip().lower()
    if normalized not in manifest.independent_task_ids:
        raise UnattendedPolicyError("Task is not declared independent in the manifest.")
    if normalized in run.isolated_item_ids:
        raise UnattendedStateError("An isolated blocked task cannot be marked successful.")
    if run.state == RunState.HALTED:
        raise UnattendedStateError("A halted workflow cannot continue with another task.")
    completed = set(run.completed_task_ids)
    completed.add(normalized)
    updated = run.model_copy(
        update={
            "completed_task_ids": tuple(sorted(completed)),
            "updated_at": datetime.now(UTC),
            "state": RunState.RUNNING,
            "last_error": None,
        }
    )
    store.save_run(updated)
    store.append_event(
        run_id,
        "task_completed",
        normalize_actor_id(actor_id),
        {"task_id": normalized},
        run=True,
    )
    return updated


def complete_run(store: UnattendedStore, run_id: str, *, actor_id: str) -> RunRecord:
    """Complete only after every required verifier has passed."""
    run = store.verify_run(run_id)
    if run.state in {RunState.HALTED, RunState.REVOKED, RunState.EXPIRED}:
        raise UnattendedStateError(f"Run in state {run.state.value} cannot complete.")
    manifest = _require_active_manifest(store, run.manifest_id)
    evidence = store.command_evidence(run_id)
    successful = {
        item.command_id for item in evidence if item.return_code == 0 and not item.timed_out
    }
    missing = set(manifest.required_completion_commands) - successful
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise UnattendedStateError(f"Required completion commands have not passed: {names}")
    updated = run.model_copy(update={"state": RunState.COMPLETED, "updated_at": datetime.now(UTC)})
    store.save_run(updated)
    store.append_event(
        run_id,
        "run_completed",
        normalize_actor_id(actor_id),
        {"required_commands": [item.value for item in manifest.required_completion_commands]},
        run=True,
    )
    return updated


def recommend_from_file(path: Path):
    """Load a task profile and apply the scheduling decision matrix."""
    try:
        profile = TaskProfile.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise UnattendedPolicyError(f"Task profile is invalid: {exc}") from exc
    return recommend_execution_mode(profile)
