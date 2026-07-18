"""Transactional persistence for controlled adversary-emulation runs."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.adversary_lab.models import LabRecord, LabState


class AdversaryLabStoreError(RuntimeError):
    """Raised when a lab record cannot be persisted safely."""


class AdversaryLabStore:
    """SQLite-backed store with optimistic revisions and atomic worker claims."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS adversary_lab_runs (
                    lab_id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_adversary_lab_assessment
                ON adversary_lab_runs (assessment_id, updated_at DESC)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_adversary_lab_state
                ON adversary_lab_runs (state, updated_at ASC)
                """
            )

    @staticmethod
    def _decode(raw: str) -> LabRecord:
        try:
            return LabRecord.model_validate_json(raw)
        except ValidationError as exc:
            raise AdversaryLabStoreError("persisted adversary-lab record is invalid") from exc

    def create(self, record: LabRecord) -> LabRecord:
        self.initialize()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO adversary_lab_runs
                        (lab_id, assessment_id, state, revision, updated_at, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.plan.lab_id,
                        record.plan.assessment_id,
                        record.state.value,
                        record.revision,
                        record.updated_at.isoformat(),
                        record.model_dump_json(),
                    ),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            raise AdversaryLabStoreError(
                f"adversary-lab run already exists: {record.plan.lab_id}"
            ) from exc
        return record

    def get(self, lab_id: str) -> LabRecord:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM adversary_lab_runs WHERE lab_id = ?",
                (lab_id,),
            ).fetchone()
        if row is None:
            raise AdversaryLabStoreError(f"unknown adversary-lab run: {lab_id}")
        return self._decode(str(row["payload_json"]))

    def list_for_assessment(self, assessment_id: str) -> tuple[LabRecord, ...]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM adversary_lab_runs
                WHERE assessment_id = ?
                ORDER BY updated_at DESC
                """,
                (assessment_id,),
            ).fetchall()
        return tuple(self._decode(str(row["payload_json"])) for row in rows)

    def list_all(self, *, limit: int = 250) -> tuple[LabRecord, ...]:
        self.initialize()
        bounded_limit = min(max(limit, 1), 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM adversary_lab_runs
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
        return tuple(self._decode(str(row["payload_json"])) for row in rows)

    def save(self, record: LabRecord, *, expected_revision: int) -> LabRecord:
        if record.revision != expected_revision + 1:
            raise AdversaryLabStoreError("record revision must advance by exactly one")
        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE adversary_lab_runs
                SET state = ?, revision = ?, updated_at = ?, payload_json = ?
                WHERE lab_id = ? AND revision = ?
                """,
                (
                    record.state.value,
                    record.revision,
                    record.updated_at.isoformat(),
                    record.model_dump_json(),
                    record.plan.lab_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise AdversaryLabStoreError(
                    "adversary-lab record changed concurrently; reload before retrying"
                )
            connection.execute("COMMIT")
        return record

    def claim_next(self, *, now: datetime) -> LabRecord | None:
        """Atomically claim the oldest queued run for one worker."""

        current = now.astimezone(UTC)
        self.initialize()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT payload_json
                FROM adversary_lab_runs
                WHERE state = ?
                ORDER BY updated_at ASC
                LIMIT 1
                """,
                (LabState.QUEUED.value,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            record = self._decode(str(row["payload_json"]))
            claimed = record.model_copy(
                update={
                    "state": LabState.PROVISIONING,
                    "active_summary": "Provisioning the disposable synthetic lab.",
                    "started_at": record.started_at or current,
                    "updated_at": current,
                    "revision": record.revision + 1,
                }
            )
            cursor = connection.execute(
                """
                UPDATE adversary_lab_runs
                SET state = ?, revision = ?, updated_at = ?, payload_json = ?
                WHERE lab_id = ? AND revision = ? AND state = ?
                """,
                (
                    claimed.state.value,
                    claimed.revision,
                    claimed.updated_at.isoformat(),
                    claimed.model_dump_json(),
                    record.plan.lab_id,
                    record.revision,
                    LabState.QUEUED.value,
                ),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise AdversaryLabStoreError("queued lab run could not be claimed atomically")
            connection.execute("COMMIT")
            return claimed

    def request_cancellation(
        self,
        lab_id: str,
        *,
        reason: str,
        now: datetime,
    ) -> LabRecord:
        current = now.astimezone(UTC)
        record = self.get(lab_id)
        if record.terminal:
            return record
        safe_reason = " ".join(reason.split())[:500] or "Operator requested stop."
        terminal_now = record.state in {
            LabState.AWAITING_APPROVAL,
            LabState.APPROVED,
            LabState.QUEUED,
        }
        updated = record.model_copy(
            update={
                "state": LabState.CANCELLED if terminal_now else record.state,
                "cancellation_requested": True,
                "cancellation_reason": safe_reason,
                "active_summary": (
                    "The lab run was cancelled before execution."
                    if terminal_now
                    else "A stop request is waiting at the next safe checkpoint."
                ),
                "completed_at": current if terminal_now else record.completed_at,
                "updated_at": current,
                "revision": record.revision + 1,
            }
        )
        return self.save(updated, expected_revision=record.revision)
