"""SQLite persistence and immutable audit-chain storage for agent tasks."""

from __future__ import annotations

import hashlib
import json
import shutil
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
_SCHEMA_VERSION = 1
_REQUIRED_COLUMNS = {
    "agent_tasks": {"task_id", "revision", "payload_json"},
    "agent_events": {
        "task_id",
        "sequence",
        "event_type",
        "payload_json",
        "created_at",
        "previous_sha256",
        "event_sha256",
    },
}


class AgentStore:
    """Connection-safe SQLite store with optimistic task revisions."""

    def __init__(self, database: Path | str, *, initialize: bool = True) -> None:
        supplied = Path(database).expanduser()
        if supplied.is_symlink():
            raise AgentStoreError("Agent store database may not be a symbolic link")
        self.database = Path(database).expanduser().resolve()
        if initialize:
            self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._initialize()
        else:
            self._validate_schema()

    @classmethod
    def open_existing(cls, database: Path | str) -> AgentStore:
        path = Path(database).expanduser()
        if path.is_symlink() or not path.is_file():
            raise AgentStoreError("Agent store is missing or unsafe")
        return cls(path, initialize=False)

    @classmethod
    def initialize_database(
        cls,
        database: Path | str,
        *,
        migrate_legacy: bool = False,
        backup_root: Path | None = None,
    ) -> tuple[AgentStore, Path | None]:
        """Explicitly initialize or adopt the supported agent-store schema."""

        supplied = Path(database).expanduser()
        if supplied.is_symlink():
            raise AgentStoreError("Agent store database may not be a symbolic link")
        path = supplied.resolve()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            path.parent.chmod(0o700)
        except OSError as exc:
            raise AgentStoreError("Agent store parent permissions could not be secured") from exc
        if not path.exists():
            store = cls(path)
            path.chmod(0o600)
            return store, None
        if not path.is_file():
            raise AgentStoreError("Agent store path is not a regular file")
        try:
            return cls.open_existing(path), None
        except AgentStoreError as original:
            if not migrate_legacy or not cls._is_legacy_store(path):
                raise original

        backup_directory = (backup_root or path.parent / "backups").expanduser().resolve()
        backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        backup = backup_directory / f"{path.name}.{timestamp}.bak"
        shutil.copy2(path, backup)
        backup.chmod(0o600)
        try:
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "CREATE TABLE agent_store_schema (schema_version INTEGER NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO agent_store_schema(schema_version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
        except sqlite3.DatabaseError as exc:
            raise AgentStoreError(
                "Legacy agent store migration failed; the backup was preserved"
            ) from exc
        path.chmod(0o600)
        return cls.open_existing(path), backup

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
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                CREATE TABLE IF NOT EXISTS agent_store_schema (
                    schema_version INTEGER NOT NULL
                );
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
                row = connection.execute("SELECT schema_version FROM agent_store_schema").fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO agent_store_schema(schema_version) VALUES (?)",
                        (_SCHEMA_VERSION,),
                    )
                elif int(row["schema_version"]) != _SCHEMA_VERSION:
                    raise AgentStoreError("Agent store schema version is unsupported")
            self.database.chmod(0o600)
            self._validate_schema()
        except sqlite3.DatabaseError as exc:
            raise AgentStoreError("Agent store could not be initialized safely") from exc

    def _validate_schema(self) -> None:
        if not self.database.is_file() or self.database.is_symlink():
            raise AgentStoreError("Agent store is missing or unsafe")
        try:
            with self._connect() as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or str(integrity[0]).lower() != "ok":
                    raise AgentStoreError("Agent store integrity check failed")
                schema_row = connection.execute(
                    "SELECT schema_version FROM agent_store_schema"
                ).fetchone()
                if schema_row is None or int(schema_row["schema_version"]) != _SCHEMA_VERSION:
                    raise AgentStoreError("Agent store schema version is missing or unsupported")
                for table, required in _REQUIRED_COLUMNS.items():
                    columns = {
                        str(row["name"])
                        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
                    }
                    if not required.issubset(columns):
                        raise AgentStoreError(f"Agent store table is malformed: {table}")
        except sqlite3.DatabaseError as exc:
            raise AgentStoreError("Agent store schema could not be validated") from exc

    def schema_version(self) -> int:
        self._validate_schema()
        return _SCHEMA_VERSION

    @staticmethod
    def _is_legacy_store(path: Path) -> bool:
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
        except sqlite3.DatabaseError:
            return False
        return "agent_store_schema" not in tables and set(_REQUIRED_COLUMNS).issubset(tables)

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

    def list_tasks(self) -> tuple[AgentTask, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM agent_tasks ORDER BY task_id"
            ).fetchall()
        return tuple(AgentTask.model_validate_json(row["payload_json"]) for row in rows)

    def save_task(self, task: AgentTask, *, expected_revision: int) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM agent_tasks WHERE task_id = ? AND revision = ?",
                (task.task_id, expected_revision),
            ).fetchone()
            if row is None:
                raise AgentStoreConflict(
                    f"Task revision conflict for {task.task_id}: expected {expected_revision}"
                )
            previous = AgentTask.model_validate_json(row["payload_json"])
            try:
                task.validate_update_from(previous)
            except ValueError as exc:
                raise AgentStoreError(f"Invalid task state update: {exc}") from exc
            payload = json.dumps(task.model_dump(mode="json"), sort_keys=True)
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

    def list_recent_events(self, *, limit: int = 100) -> tuple[AuditEvent, ...]:
        if limit < 1 or limit > 10_000:
            raise ValueError("limit must be between 1 and 10000.")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT task_id, sequence, event_type, payload_json, created_at,
                       previous_sha256, event_sha256
                  FROM agent_events
                 ORDER BY created_at DESC, task_id DESC, sequence DESC
                 LIMIT ?
                """,
                (limit,),
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
