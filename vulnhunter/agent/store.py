"""SQLite persistence and immutable audit-chain storage for agent tasks."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnhunter.agent.models import AgentTask, AuditEvent, canonical_json, utc_now


class AgentStoreError(RuntimeError):
    """Base persistence error."""


class AgentStoreConflict(AgentStoreError):
    """Raised for duplicate or stale task writes."""


class AgentAuditIntegrityError(AgentStoreError):
    """Raised when an audit chain does not verify."""


_ZERO_HASH = "0" * 64


class AgentStore:
    """Connection-safe SQLite store with optimistic task revisions."""

    def __init__(self, database: Path | str) -> None:
        self.database = Path(database).expanduser().resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_tasks (
                    task_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_events (
                    task_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    PRIMARY KEY (task_id, sequence),
                    FOREIGN KEY (task_id) REFERENCES agent_tasks(task_id)
                );
                """
            )

    def create_task(self, task: AgentTask) -> None:
        payload = json.dumps(task.model_dump(mode="json"), sort_keys=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO agent_tasks(task_id, revision, payload_json) VALUES (?, ?, ?)",
                    (task.task_id, task.revision, payload),
                )
        except sqlite3.IntegrityError as exc:
            raise AgentStoreConflict(f"Task already exists: {task.task_id}") from exc

    def get_task(self, task_id: str) -> AgentTask:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM agent_tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise AgentStoreError(f"Unknown task: {task_id}")
        return AgentTask.model_validate_json(row["payload_json"])

    def save_task(self, task: AgentTask, *, expected_revision: int) -> None:
        payload = json.dumps(task.model_dump(mode="json"), sort_keys=True)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE agent_tasks
                   SET revision = ?, payload_json = ?
                 WHERE task_id = ? AND revision = ?
                """,
                (task.revision, payload, task.task_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise AgentStoreConflict(
                    f"Task revision conflict for {task.task_id}: expected {expected_revision}"
                )

    def append_event(
        self,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        created_at: datetime | None = None,
    ) -> AuditEvent:
        timestamp = created_at or utc_now()
        with self._connect() as connection:
            task_exists = connection.execute(
                "SELECT 1 FROM agent_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if task_exists is None:
                raise AgentStoreError(f"Unknown task: {task_id}")
            previous = connection.execute(
                """
                SELECT sequence, event_sha256
                  FROM agent_events
                 WHERE task_id = ?
                 ORDER BY sequence DESC
                 LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = _ZERO_HASH if previous is None else str(previous["event_sha256"])
            event_material = {
                "task_id": task_id,
                "sequence": sequence,
                "event_type": event_type,
                "payload": payload,
                "created_at": timestamp.isoformat(),
                "previous_sha256": previous_hash,
            }
            event_hash = hashlib.sha256(canonical_json(event_material)).hexdigest()
            connection.execute(
                """
                INSERT INTO agent_events(
                    task_id, sequence, event_type, payload_json, created_at,
                    previous_sha256, event_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    sequence,
                    event_type,
                    json.dumps(payload, sort_keys=True, default=str),
                    timestamp.isoformat(),
                    previous_hash,
                    event_hash,
                ),
            )
        return AuditEvent(
            task_id=task_id,
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            created_at=timestamp,
            previous_sha256=previous_hash,
            event_sha256=event_hash,
        )

    def list_events(self, task_id: str) -> tuple[AuditEvent, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT task_id, sequence, event_type, payload_json, created_at,
                       previous_sha256, event_sha256
                  FROM agent_events
                 WHERE task_id = ?
                 ORDER BY sequence
                """,
                (task_id,),
            ).fetchall()
        return tuple(
            AuditEvent(
                task_id=row["task_id"],
                sequence=row["sequence"],
                event_type=row["event_type"],
                payload=json.loads(row["payload_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                previous_sha256=row["previous_sha256"],
                event_sha256=row["event_sha256"],
            )
            for row in rows
        )

    def verify_integrity(self, task_id: str) -> str:
        previous_hash = _ZERO_HASH
        events = self.list_events(task_id)
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                raise AgentAuditIntegrityError("Audit event sequence is not contiguous")
            if event.previous_sha256 != previous_hash:
                raise AgentAuditIntegrityError("Audit previous hash does not match")
            material = {
                "task_id": event.task_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "payload": event.payload,
                "created_at": event.created_at.isoformat(),
                "previous_sha256": event.previous_sha256,
            }
            expected_hash = hashlib.sha256(canonical_json(material)).hexdigest()
            if expected_hash != event.event_sha256:
                raise AgentAuditIntegrityError("Audit event hash does not match")
            previous_hash = event.event_sha256
        return previous_hash
