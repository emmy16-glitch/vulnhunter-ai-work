from __future__ import annotations

import sqlite3
import stat

import pytest

from vulnhunter.agent.models import AgentTask, PermissionManifest, TaskStatus
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


def test_missing_store_is_not_created_by_read_path(tmp_path) -> None:
    database = tmp_path / "runtime" / "agent.db"
    with pytest.raises(AgentStoreError, match="missing or unsafe"):
        AgentStore.open_existing(database)
    assert not database.exists()


def test_explicit_initialization_creates_versioned_secure_store(tmp_path) -> None:
    database = tmp_path / "runtime" / "agent" / "agent.db"
    store, backup = AgentStore.initialize_database(database)
    assert backup is None
    assert store.schema_version() == 1
    assert AgentStore.open_existing(database).list_tasks() == ()
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_malformed_store_is_rejected_without_destructive_reset(tmp_path) -> None:
    database = tmp_path / "agent.db"
    original = b"not a sqlite database"
    database.write_bytes(original)
    with pytest.raises(AgentStoreError):
        AgentStore.initialize_database(database, migrate_legacy=True)
    assert database.read_bytes() == original


def test_unsupported_schema_version_is_rejected(tmp_path) -> None:
    database = tmp_path / "agent.db"
    AgentStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE agent_store_schema SET schema_version = 99")
    with pytest.raises(AgentStoreError, match="unsupported"):
        AgentStore.open_existing(database)


def test_legacy_store_requires_explicit_migration_and_backup(tmp_path) -> None:
    database = tmp_path / "agent.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE agent_tasks (
                task_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE agent_events (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL,
                PRIMARY KEY (task_id, sequence)
            );
            """
        )
    with pytest.raises(AgentStoreError):
        AgentStore.initialize_database(database)
    store, backup = AgentStore.initialize_database(database, migrate_legacy=True)
    assert backup is not None and backup.is_file()
    assert store.schema_version() == 1


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


def test_store_revalidates_transition_against_current_snapshot(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    original = task()
    store.create_task(original)
    forged = original.model_copy(
        update={"status": TaskStatus.COMPLETED, "revision": original.revision + 1}
    )
    with pytest.raises(AgentStoreError, match="created -> completed"):
        store.save_task(forged, expected_revision=original.revision)


def test_store_rejects_immutable_objective_mutation(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    original = task()
    store.create_task(original)
    forged = original.model_copy(
        update={
            "objective": "Replace the immutable objective after creation.",
            "revision": original.revision + 1,
        }
    )
    with pytest.raises(AgentStoreError, match="immutable task fields"):
        store.save_task(forged, expected_revision=original.revision)


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


def test_tasks_and_recent_events_can_be_listed_read_only(tmp_path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    store.create_task(task())
    store.append_event("task-store", "one", {})
    assert [item.task_id for item in store.list_tasks()] == ["task-store"]
    assert store.list_recent_events(limit=1)[0].event_type == "one"


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
