"""Transactional persistence for Machine Oracle capsules and sessions."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.oracle.models import (
    OracleSession,
    OracleSessionEvent,
    OracleSessionStatus,
    ProofCapsule,
)


class OracleStoreError(RuntimeError):
    pass


_ZERO_HASH = "0" * 64
_TERMINAL_SESSION_STATES = {
    OracleSessionStatus.COMPLETED,
    OracleSessionStatus.CANCELLED,
    OracleSessionStatus.BLOCKED,
    OracleSessionStatus.FAILED,
}
_IMMUTABLE_SESSION_FIELDS = (
    "session_id",
    "capsule_sha256",
    "strategy",
    "verifier_identity",
    "provider_identity",
    "connector_identity",
    "authorization_reference",
    "scope_reference",
    "limits",
    "created_at",
)
_ALLOWED_TRANSITIONS = {
    OracleSessionStatus.QUEUED: {
        OracleSessionStatus.PREPARING,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
    },
    OracleSessionStatus.PREPARING: {
        OracleSessionStatus.VERIFYING,
        OracleSessionStatus.AWAITING_APPROVAL,
        OracleSessionStatus.AWAITING_EVIDENCE,
        OracleSessionStatus.PAUSED,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
    },
    OracleSessionStatus.VERIFYING: {
        OracleSessionStatus.AWAITING_APPROVAL,
        OracleSessionStatus.AWAITING_EVIDENCE,
        OracleSessionStatus.PAUSED,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
        OracleSessionStatus.COMPLETED,
    },
    OracleSessionStatus.AWAITING_APPROVAL: {
        OracleSessionStatus.PREPARING,
        OracleSessionStatus.VERIFYING,
        OracleSessionStatus.PAUSED,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
    },
    OracleSessionStatus.AWAITING_EVIDENCE: {
        OracleSessionStatus.PREPARING,
        OracleSessionStatus.VERIFYING,
        OracleSessionStatus.PAUSED,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
    },
    OracleSessionStatus.PAUSED: {
        OracleSessionStatus.PREPARING,
        OracleSessionStatus.VERIFYING,
        OracleSessionStatus.CANCELLATION_REQUESTED,
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.FAILED,
    },
    OracleSessionStatus.CANCELLATION_REQUESTED: {
        OracleSessionStatus.CANCELLED,
        OracleSessionStatus.FAILED,
        OracleSessionStatus.BLOCKED,
        OracleSessionStatus.COMPLETED,
    },
}


class OracleStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.capsules = self.root / "capsules"
        self.database_path = self.root / "oracle_sessions.sqlite3"
        self.capsules.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oracle_sessions (
                    session_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    snapshot_sha256 TEXT NOT NULL,
                    history_json TEXT NOT NULL,
                    history_sha256 TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    last_event_sha256 TEXT NOT NULL
                )
                """
            )

    def save_capsule(self, capsule: ProofCapsule) -> Path:
        path = self.capsules / f"{capsule.capsule_hash()}.json"
        self._atomic_write(path, capsule.model_dump_json(indent=2) + "\n")
        return path

    def load_capsule(self, capsule_sha256: str) -> ProofCapsule:
        path = self._safe_digest_path(self.capsules, capsule_sha256)
        if not path.is_file():
            raise OracleStoreError("proof capsule does not exist")
        try:
            capsule = ProofCapsule.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise OracleStoreError("proof capsule is invalid") from exc
        if capsule.capsule_hash() != capsule_sha256:
            raise OracleStoreError("proof capsule hash mismatch")
        return capsule

    def create_session(self, session: OracleSession) -> Path:
        session = OracleSession.model_validate(session.model_dump())
        self._validate_initial_session(session)
        event = self._event(
            sequence=1,
            previous_sha256=_ZERO_HASH,
            previous_status=None,
            session=session,
            occurred_at=max(datetime.now(UTC), session.created_at),
        )
        values = self._serialized_values(session, (event,))
        with self._connect(write=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO oracle_sessions(
                        session_id, status, snapshot_json, snapshot_sha256,
                        history_json, history_sha256, event_count, last_event_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session.session_id, session.status.value, *values),
                )
            except sqlite3.IntegrityError as exc:
                raise OracleStoreError("Oracle session already exists") from exc
        return self.database_path

    def update_session(
        self,
        session: OracleSession,
        *,
        expected_status: OracleSessionStatus,
        expected_snapshot_sha256: str,
    ) -> Path:
        session = OracleSession.model_validate(session.model_dump())
        with self._connect(write=True) as connection:
            row = self._row(connection, session.session_id)
            current, events = self._decode_and_validate(row, expected_session_id=session.session_id)
            current_hash = self.session_snapshot_hash(current)
            if current.status != expected_status:
                raise OracleStoreError("Oracle session update has stale expected status")
            if current_hash != expected_snapshot_sha256:
                raise OracleStoreError("Oracle session update has stale expected snapshot")
            self._validate_session_update(current, session)
            occurred_at = max(datetime.now(UTC), events[-1].occurred_at)
            event = self._event(
                sequence=len(events) + 1,
                previous_sha256=events[-1].event_sha256,
                previous_status=current.status,
                session=session,
                occurred_at=occurred_at,
            )
            values = self._serialized_values(session, events + (event,))
            cursor = connection.execute(
                """
                UPDATE oracle_sessions
                SET status=?, snapshot_json=?, snapshot_sha256=?, history_json=?,
                    history_sha256=?, event_count=?, last_event_sha256=?
                WHERE session_id=? AND status=? AND snapshot_sha256=?
                """,
                (
                    session.status.value,
                    *values,
                    session.session_id,
                    expected_status.value,
                    expected_snapshot_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise OracleStoreError("Oracle session compare-and-swap failed")
        return self.database_path

    def load_session(self, session_id: str) -> OracleSession:
        with self._connect() as connection:
            row = self._row(connection, session_id)
            session, _ = self._decode_and_validate(row, expected_session_id=session_id)
        return session

    def load_session_events(self, session_id: str) -> tuple[OracleSessionEvent, ...]:
        with self._connect() as connection:
            row = self._row(connection, session_id)
            _, events = self._decode_and_validate(row, expected_session_id=session_id)
        return events

    @staticmethod
    def session_snapshot_hash(session: OracleSession) -> str:
        return sha256_json(session.model_dump(mode="json"))

    def _row(self, connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        self._validate_session_id(session_id)
        row = connection.execute(
            "SELECT * FROM oracle_sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise OracleStoreError("Oracle session does not exist")
        return row

    def _decode_and_validate(
        self,
        row: sqlite3.Row,
        *,
        expected_session_id: str,
    ) -> tuple[OracleSession, tuple[OracleSessionEvent, ...]]:
        try:
            session = OracleSession.model_validate_json(row["snapshot_json"])
            raw_history = json.loads(row["history_json"])
            if not isinstance(raw_history, list):
                raise ValueError("history must be a list")
            events = tuple(OracleSessionEvent.model_validate(item) for item in raw_history)
        except (TypeError, ValueError, ValidationError) as exc:
            raise OracleStoreError("Oracle session state or history is malformed") from exc

        snapshot_sha256 = self.session_snapshot_hash(session)
        if snapshot_sha256 != row["snapshot_sha256"]:
            raise OracleStoreError("Oracle session snapshot hash mismatch")
        actual_history_sha256 = hashlib.sha256(row["history_json"].encode("utf-8")).hexdigest()
        if actual_history_sha256 != row["history_sha256"]:
            raise OracleStoreError("Oracle session history envelope hash mismatch")
        if len(events) != int(row["event_count"]):
            raise OracleStoreError("Oracle session history is missing or truncated")
        if not events:
            raise OracleStoreError("Oracle session history is missing")
        if events[-1].event_sha256 != row["last_event_sha256"]:
            raise OracleStoreError("Oracle session history tail mismatch")
        if row["status"] != session.status.value:
            raise OracleStoreError("Oracle session status columns disagree")
        if session.session_id != expected_session_id:
            raise OracleStoreError("Oracle session identifier changed")

        previous_event_hash = _ZERO_HASH
        previous_event: OracleSessionEvent | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                raise OracleStoreError("Oracle session history sequence is invalid")
            if (
                event.session_id != expected_session_id
                or event.snapshot.session_id != expected_session_id
            ):
                raise OracleStoreError("Oracle session identifier changed in history")
            if event.previous_sha256 != previous_event_hash:
                raise OracleStoreError("Oracle session previous event hash is invalid")
            if event.expected_hash() != event.event_sha256:
                raise OracleStoreError("Oracle session event hash mismatch")
            if event.snapshot_sha256 != self.session_snapshot_hash(event.snapshot):
                raise OracleStoreError("Oracle session event snapshot hash mismatch")
            if event.status != event.snapshot.status:
                raise OracleStoreError("Oracle session event status disagrees with snapshot")
            if previous_event is None:
                if event.previous_status is not None:
                    raise OracleStoreError("initial Oracle session event has a previous status")
                self._validate_initial_session(event.snapshot)
            else:
                if event.previous_status != previous_event.status:
                    raise OracleStoreError("Oracle session history status link is invalid")
                if event.occurred_at < previous_event.occurred_at:
                    raise OracleStoreError("Oracle session event timestamp moved backwards")
                self._validate_session_update(previous_event.snapshot, event.snapshot)
            previous_event_hash = event.event_sha256
            previous_event = event

        if events[-1].snapshot_sha256 != snapshot_sha256 or events[-1].snapshot != session:
            raise OracleStoreError("Oracle session snapshot and history disagree")
        return session, events

    @staticmethod
    def _validate_initial_session(session: OracleSession) -> None:
        canonical = (
            session.status == OracleSessionStatus.QUEUED
            and session.step == "queued"
            and session.attempt == 0
            and not session.produced_evidence_hashes
            and session.safe_error_category is None
            and session.final_verdict is None
        )
        if not canonical:
            raise OracleStoreError("Oracle session creation requires canonical queued state")

    @classmethod
    def _validate_session_update(cls, current: OracleSession, updated: OracleSession) -> None:
        if current.status in _TERMINAL_SESSION_STATES:
            raise OracleStoreError("terminal Oracle sessions are immutable")
        for field_name in _IMMUTABLE_SESSION_FIELDS:
            if getattr(current, field_name) != getattr(updated, field_name):
                raise OracleStoreError(f"immutable Oracle session field changed: {field_name}")
        if updated.attempt < current.attempt:
            raise OracleStoreError("Oracle session attempt cannot decrease")
        if updated.last_heartbeat_at < current.last_heartbeat_at:
            raise OracleStoreError("Oracle session heartbeat cannot move backwards")
        evidence_count = len(current.produced_evidence_hashes)
        if updated.produced_evidence_hashes[:evidence_count] != current.produced_evidence_hashes:
            raise OracleStoreError("Oracle session evidence is append-only")
        cls._validate_transition(current.status, updated.status)

    @staticmethod
    def _validate_transition(
        current: OracleSessionStatus,
        next_status: OracleSessionStatus,
    ) -> None:
        if current == next_status:
            return
        if next_status not in _ALLOWED_TRANSITIONS.get(current, set()):
            raise OracleStoreError(f"invalid Oracle session transition: {current}->{next_status}")

    def _event(
        self,
        *,
        sequence: int,
        previous_sha256: str,
        previous_status: OracleSessionStatus | None,
        session: OracleSession,
        occurred_at: datetime,
    ) -> OracleSessionEvent:
        draft = OracleSessionEvent(
            sequence=sequence,
            session_id=session.session_id,
            previous_status=previous_status,
            status=session.status,
            snapshot=session,
            snapshot_sha256=self.session_snapshot_hash(session),
            occurred_at=occurred_at,
            previous_sha256=previous_sha256,
            event_sha256=_ZERO_HASH,
        )
        return draft.model_copy(update={"event_sha256": draft.expected_hash()})

    def _serialized_values(
        self,
        session: OracleSession,
        events: tuple[OracleSessionEvent, ...],
    ) -> tuple[str, str, str, str, int, str]:
        snapshot_json = session.model_dump_json()
        snapshot_sha256 = self.session_snapshot_hash(session)
        history_json = json.dumps(
            [event.model_dump(mode="json") for event in events],
            sort_keys=True,
            separators=(",", ":"),
        )
        history_sha256 = hashlib.sha256(history_json.encode("utf-8")).hexdigest()
        return (
            snapshot_json,
            snapshot_sha256,
            history_json,
            history_sha256,
            len(events),
            events[-1].event_sha256,
        )

    @staticmethod
    def _safe_digest_path(root: Path, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise OracleStoreError("digest is malformed")
        path = (root / f"{digest}.json").resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise OracleStoreError("digest path escapes store") from exc
        return path

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        if "/" in session_id or ".." in session_id:
            raise OracleStoreError("Oracle session identifier is unsafe")

    @staticmethod
    def _atomic_write(path: Path, data: str) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
