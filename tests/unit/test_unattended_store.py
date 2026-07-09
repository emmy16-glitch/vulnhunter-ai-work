"""Integrity tests for unattended manifests, runs, and events."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunter.exceptions import UnattendedIntegrityError
from vulnhunter.unattended.models import (
    ApprovalRecord,
    ExecutionMode,
    PermissionManifest,
    ToolCapability,
)
from vulnhunter.unattended.store import UnattendedStore


def manifest(repository: Path) -> PermissionManifest:
    now = datetime.now(UTC)
    return PermissionManifest(
        manifest_id="manifest-store",
        loop_id="loop-store",
        repository_root=repository.resolve(),
        execution_mode=ExecutionMode.INTERACTIVE_GOAL,
        available_tools=(ToolCapability.REPOSITORY_READ,),
        approved_read_paths=("vulnhunter/**",),
        created_by="creator.one",
        created_at=now,
        expires_at=now + timedelta(hours=2),
    )


def approve(store: UnattendedStore, record: PermissionManifest) -> None:
    now = datetime.now(UTC)
    store.save_approval(
        ApprovalRecord(
            manifest_id=record.manifest_id,
            manifest_sha256=store.manifest_sha256(record.manifest_id),
            approved_by="approver.one",
            approved_at=now,
            expires_at=record.expires_at,
            reason="Reviewed exact permissions and approved this bounded local task.",
        )
    )


def test_manifest_integrity_is_bound_to_approval(tmp_path: Path) -> None:
    store = UnattendedStore(tmp_path / "control")
    record = manifest(tmp_path)
    store.create_manifest(record)
    approve(store, record)

    assert store.verify_manifest(record.manifest_id) == record

    path = store.manifest_directory(record.manifest_id) / "manifest.json"
    data = json.loads(path.read_text())
    data["maximum_iterations"] = 999
    path.write_text(json.dumps(data))

    with pytest.raises(UnattendedIntegrityError, match="changed after approval"):
        store.verify_manifest(record.manifest_id)


def test_event_chain_detects_tampering(tmp_path: Path) -> None:
    store = UnattendedStore(tmp_path / "control")
    record = manifest(tmp_path)
    store.create_manifest(record)
    approve(store, record)
    path = store.manifest_directory(record.manifest_id) / "events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines() if line]
    events[0]["event_type"] = "tampered"
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n")

    with pytest.raises(UnattendedIntegrityError, match="integrity|altered"):
        store.verify_events(record.manifest_id)


def test_approval_is_immutable(tmp_path: Path) -> None:
    store = UnattendedStore(tmp_path / "control")
    record = manifest(tmp_path)
    store.create_manifest(record)
    approve(store, record)

    with pytest.raises(UnattendedIntegrityError, match="immutable"):
        approve(store, record)
