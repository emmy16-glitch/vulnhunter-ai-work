"""Transactional SQLite approval store with a hash-chained event ledger."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.actions.models import ActionManifest, canonical_json
from vulnhunter.approvals.conditions import (
    ApprovalConditionError,
    ApprovalConditionEvaluator,
    CanonicalApprovalExecutionPlan,
    validate_authoritative_evaluation,
)
from vulnhunter.approvals.models import (
    ApprovalDecision,
    ApprovalEvent,
    ApprovalRequest,
    ApprovalStatus,
)

_ZERO_HASH = "0" * 64


class ApprovalStoreError(RuntimeError):
    pass


class ApprovalNotFoundError(ApprovalStoreError):
    pass


class ApprovalConflictError(ApprovalStoreError):
    pass


class ApprovalIntegrityError(ApprovalStoreError):
    pass


class ApprovalStore:
    def __init__(
        self,
        path: Path,
        *,
        condition_evaluator: ApprovalConditionEvaluator | None = None,
    ) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.condition_evaluator = condition_evaluator or ApprovalConditionEvaluator()

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
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

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    action_manifest_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    FOREIGN KEY (request_id)
                        REFERENCES approval_requests(request_id)
                        ON DELETE RESTRICT
                );

                CREATE INDEX IF NOT EXISTS idx_approval_status
                    ON approval_requests(status, request_id);
                CREATE INDEX IF NOT EXISTS idx_approval_event_request
                    ON approval_events(request_id, sequence);
                """
            )

    def create(self, request: ApprovalRequest) -> ApprovalRequest:
        self.initialize()
        record_json = request.model_dump_json()
        digest = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
        with self._connect(write=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO approval_requests(
                        request_id, campaign_id, run_id, action_manifest_sha256,
                        status, record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.request_id,
                        request.campaign_id,
                        request.run_id,
                        request.action_manifest_sha256,
                        request.status.value,
                        record_json,
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalConflictError(
                    f"Approval request already exists: {request.request_id}"
                ) from exc
            self._append_event(
                connection,
                request_id=request.request_id,
                event_type="approval_requested",
                actor_id=request.requested_by,
                detail={"action_manifest_sha256": request.action_manifest_sha256},
            )
        return request

    def get(self, request_id: str) -> ApprovalRequest:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM approval_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise ApprovalNotFoundError(f"Approval request does not exist: {request_id}")
        return self._decode_record(row["record_json"], row["record_sha256"])

    def list(self, *, status: ApprovalStatus | None = None) -> tuple[ApprovalRequest, ...]:
        self.initialize()
        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    "SELECT record_json, record_sha256 FROM approval_requests ORDER BY request_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT record_json, record_sha256 FROM approval_requests "
                    "WHERE status=? ORDER BY request_id",
                    (status.value,),
                ).fetchall()
        return tuple(self._decode_record(row["record_json"], row["record_sha256"]) for row in rows)

    def decide(
        self,
        *,
        request_id: str,
        actor_id: str,
        decision: ApprovalDecision,
        reason: str,
        conditions: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> ApprovalRequest:
        instant = now or datetime.now(UTC)
        safe_reason = reason.strip()
        if len(safe_reason) < 8:
            raise ApprovalConflictError(
                "Approval decisions require a reason of at least eight characters."
            )

        expired = False
        updated: ApprovalRequest | None = None
        with self._connect(write=True) as connection:
            current = self._load_locked(connection, request_id)
            if actor_id == current.requested_by:
                raise ApprovalConflictError("The requester cannot decide its own approval request.")
            if current.status not in {
                ApprovalStatus.PENDING,
                ApprovalStatus.INFORMATION_REQUIRED,
                ApprovalStatus.CONDITIONS_PROPOSED,
            }:
                raise ApprovalConflictError(
                    f"Approval request is not decidable from {current.status.value}."
                )
            if instant >= current.expires_at:
                updated = current.model_copy(update={"status": ApprovalStatus.EXPIRED})
                updated = ApprovalRequest.model_validate(updated.model_dump())
                self._save_locked(connection, updated)
                self._append_event(
                    connection,
                    request_id=request_id,
                    event_type="approval_expired",
                    actor_id=actor_id,
                    detail={},
                )
                expired = True
            else:
                if decision in {
                    ApprovalDecision.APPROVE_ONCE,
                    ApprovalDecision.APPROVE_WITH_CONDITIONS,
                }:
                    status = ApprovalStatus.APPROVED
                elif decision == ApprovalDecision.REQUEST_MORE_INFORMATION:
                    status = ApprovalStatus.INFORMATION_REQUIRED
                elif decision == ApprovalDecision.PROPOSE_SAFER_ALTERNATIVE:
                    status = ApprovalStatus.CONDITIONS_PROPOSED
                else:
                    status = ApprovalStatus.DENIED

                updated = current.model_copy(
                    update={
                        "status": status,
                        "decided_by": actor_id,
                        "decision": decision,
                        "decision_reason": safe_reason,
                        "conditions": conditions,
                        "decided_at": instant,
                    }
                )
                updated = ApprovalRequest.model_validate(updated.model_dump())
                self._save_locked(connection, updated)
                self._append_event(
                    connection,
                    request_id=request_id,
                    event_type=f"approval_{decision.value}",
                    actor_id=actor_id,
                    detail={"conditions": list(conditions)},
                )

        if expired:
            raise ApprovalConflictError("Approval request has expired.")
        if updated is None:  # pragma: no cover - defensive invariant
            raise ApprovalStoreError("Approval decision did not produce a final state.")
        return updated

    def consume(
        self,
        *,
        request_id: str,
        action_manifest_sha256: str,
        execution_id: str,
        actor_id: str,
        now: datetime | None = None,
        manifest: ActionManifest | None = None,
        execution_plan: CanonicalApprovalExecutionPlan | None = None,
    ) -> ApprovalRequest:
        instant = now or datetime.now(UTC)
        expired = False
        updated: ApprovalRequest | None = None
        with self._connect(write=True) as connection:
            current = self._load_locked(connection, request_id)
            if actor_id == current.requested_by:
                raise ApprovalConflictError(
                    "The requester cannot consume its own approval request."
                )
            if current.status != ApprovalStatus.APPROVED:
                raise ApprovalConflictError("Approval is not active.")
            if instant >= current.expires_at:
                updated = current.model_copy(update={"status": ApprovalStatus.EXPIRED})
                updated = ApprovalRequest.model_validate(updated.model_dump())
                self._save_locked(connection, updated)
                self._append_event(
                    connection,
                    request_id=request_id,
                    event_type="approval_expired",
                    actor_id=actor_id,
                    detail={},
                )
                expired = True
            else:
                if current.action_manifest_sha256 != action_manifest_sha256:
                    raise ApprovalConflictError("Approval is bound to a different action.")
                if current.decision == ApprovalDecision.APPROVE_WITH_CONDITIONS:
                    if manifest is None or execution_plan is None:
                        raise ApprovalConflictError(
                            "Conditional approval requires canonical execution inputs."
                        )
                    try:
                        evaluation = self.condition_evaluator.evaluate(
                            approval=current,
                            manifest=manifest,
                            execution_plan=execution_plan,
                            execution_id=execution_id,
                            now=instant,
                        )
                        validate_authoritative_evaluation(
                            approval=current,
                            manifest=manifest,
                            execution_plan=execution_plan,
                            execution_id=execution_id,
                            evaluation=evaluation,
                            evaluator=self.condition_evaluator,
                            now=instant,
                        )
                    except ApprovalConditionError as exc:
                        raise ApprovalConflictError(
                            "Conditional approval conditions are not satisfied."
                        ) from exc
                updated = current.model_copy(
                    update={
                        "status": ApprovalStatus.CONSUMED,
                        "consumed_at": instant,
                        "consumed_by_execution_id": execution_id,
                    }
                )
                updated = ApprovalRequest.model_validate(updated.model_dump())
                self._save_locked(connection, updated)
                self._append_event(
                    connection,
                    request_id=request_id,
                    event_type="approval_consumed",
                    actor_id=actor_id,
                    detail={
                        "execution_id": execution_id,
                        **(
                            {"condition_evaluation_sha256": evaluation.fingerprint()}
                            if current.decision == ApprovalDecision.APPROVE_WITH_CONDITIONS
                            else {}
                        ),
                    },
                )

        if expired:
            raise ApprovalConflictError("Approval has expired.")
        if updated is None:  # pragma: no cover - defensive invariant
            raise ApprovalStoreError("Approval consumption did not produce a final state.")
        return updated

    def events(self, request_id: str) -> tuple[ApprovalEvent, ...]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, request_id, event_type, actor_id, occurred_at,
                       detail_json, previous_sha256, event_sha256
                FROM approval_events
                WHERE request_id=?
                ORDER BY sequence
                """,
                (request_id,),
            ).fetchall()
        events = tuple(
            ApprovalEvent(
                sequence=int(row["sequence"]),
                request_id=row["request_id"],
                event_type=row["event_type"],
                actor_id=row["actor_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                detail=json.loads(row["detail_json"]),
                previous_sha256=row["previous_sha256"],
                event_sha256=row["event_sha256"],
            )
            for row in rows
        )
        previous = _ZERO_HASH
        for event in events:
            unsigned = {
                "sequence": event.sequence,
                "request_id": event.request_id,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "occurred_at": event.occurred_at.isoformat(),
                "detail": event.detail,
                "previous_sha256": event.previous_sha256,
            }
            if event.previous_sha256 != previous:
                raise ApprovalIntegrityError("Approval event chain has been altered.")
            expected = hashlib.sha256(canonical_json(unsigned)).hexdigest()
            if expected != event.event_sha256:
                raise ApprovalIntegrityError("Approval event digest does not match.")
            previous = event.event_sha256
        return events

    def _load_locked(
        self,
        connection: sqlite3.Connection,
        request_id: str,
    ) -> ApprovalRequest:
        row = connection.execute(
            "SELECT record_json, record_sha256 FROM approval_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise ApprovalNotFoundError(f"Approval request does not exist: {request_id}")
        return self._decode_record(row["record_json"], row["record_sha256"])

    @staticmethod
    def _decode_record(record_json: str, expected_sha256: str) -> ApprovalRequest:
        actual = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
        if actual != expected_sha256:
            raise ApprovalIntegrityError("Approval request failed integrity verification.")
        try:
            return ApprovalRequest.model_validate_json(record_json)
        except ValidationError as exc:
            raise ApprovalIntegrityError("Approval request is invalid.") from exc

    @staticmethod
    def _save_locked(connection: sqlite3.Connection, request: ApprovalRequest) -> None:
        record_json = request.model_dump_json()
        digest = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            UPDATE approval_requests
            SET status=?, record_json=?, record_sha256=?
            WHERE request_id=?
            """,
            (request.status.value, record_json, digest, request.request_id),
        )

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        request_id: str,
        event_type: str,
        actor_id: str,
        detail: dict[str, object],
    ) -> ApprovalEvent:
        sequence_row = connection.execute(
            "SELECT sequence FROM approval_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_row = connection.execute(
            "SELECT event_sha256 FROM approval_events "
            "WHERE request_id=? ORDER BY sequence DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        sequence = 1 if sequence_row is None else int(sequence_row["sequence"]) + 1
        previous_sha256 = _ZERO_HASH if previous_row is None else previous_row["event_sha256"]
        occurred_at = datetime.now(UTC)
        unsigned = {
            "sequence": sequence,
            "request_id": request_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "occurred_at": occurred_at.isoformat(),
            "detail": detail,
            "previous_sha256": previous_sha256,
        }
        event_sha256 = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        connection.execute(
            """
            INSERT INTO approval_events(
                sequence, request_id, event_type, actor_id, occurred_at,
                detail_json, previous_sha256, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                request_id,
                event_type,
                actor_id,
                occurred_at.isoformat(),
                json.dumps(detail, sort_keys=True, separators=(",", ":")),
                previous_sha256,
                event_sha256,
            ),
        )
        return ApprovalEvent(
            **unsigned,
            event_sha256=event_sha256,
        )
