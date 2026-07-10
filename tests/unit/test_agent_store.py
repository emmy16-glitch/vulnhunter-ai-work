from __future__ import annotations

import sqlite3

import pytest

from vulnhunter.agent.models import AgentTask, PermissionManifest
from vulnhunter.agent.store import (
    AgentAuditIntegrityError,
    AgentStore,
    AgentStoreConflict,
    AgentStoreError,
)


def task() -> AgentTask:
    return AgentTask(
        task_id="task-store",
        objective="Persist and verify bounded agent state.",
        permission_manifest=PermissionManifest(
            manifest_id="manifest-store",
            role_id="orchestrator",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
        ),
    )


def test_create_and_load_task(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    original = task()
    store.create_task(original)
    assert store.get_task("task-store") == original


def test_duplicate_task_is_rejected(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    store.create_task(task())
    with pytest.raises(AgentStoreConflict, match="already exists"):
        store.create_task(task())


def test_unknown_task_is_rejected(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    with pytest.raises(AgentStoreError, match="Unknown task"):
        store.get_task("missing-task")


def test_save_uses_optimistic_revision(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    original = task()
    store.create_task(original)
    updated = original.evolved(paused_reason="updated")
    store.save_task(updated, expected_revision=0)
    with pytest.raises(AgentStoreConflict, match="revision conflict"):
        store.save_task(updated.evolved(), expected_revision=0)


def test_append_and_verify_audit_chain(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    store.create_task(task())
    first = store.append_event("task-store", "task.created", {"value": 1})
    second = store.append_event("task-store", "tool.executed", {"value": 2})
    assert second.previous_sha256 == first.event_sha256
    assert store.verify_integrity("task-store") == second.event_sha256


def test_events_are_returned_in_sequence(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    store.create_task(task())
    store.append_event("task-store", "one", {})
    store.append_event("task-store", "two", {})
    assert [event.sequence for event in store.list_events("task-store")] == [1, 2]


def test_audit_tampering_is_detected(tmp_path) -> None:
    database = tmp_path / "agent.db"
    store = AgentStore(database)
    store.create_task(task())
    store.append_event("task-store", "task.created", {"value": 1})
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE agent_events SET payload_json = ? WHERE task_id = ? AND sequence = 1",
            ('{"value": 99}', "task-store"),
        )
    with pytest.raises(AgentAuditIntegrityError, match="hash does not match"):
        store.verify_integrity("task-store")
