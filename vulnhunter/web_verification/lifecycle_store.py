"""Transactional SQLite ledger for the governed web-verification lifecycle."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_verification.errors import WebVerificationContractError
from vulnhunter.web_verification.external_models import (
    SignedExternalEvidenceSubmission,
    VerifiedExternalEvidenceReceipt,
)
from vulnhunter.web_verification.lifecycle_models import (
    FinalVerificationDecision,
    HumanVerificationReview,
    PersistedEvidenceAdmission,
    StrategyAdjudication,
    VerificationCaseSnapshot,
    VerificationCaseState,
)

_SCHEMA_VERSION = "1"


def _json(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class VerificationLifecycleStore:
    """Authoritative verification ledger with global receipt replay protection."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            if immediate:
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
                CREATE TABLE IF NOT EXISTS verification_lifecycle_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verification_cases (
                    case_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    case_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verification_admissions (
                    admission_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS verification_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    submission_json TEXT NOT NULL,
                    verified_json TEXT NOT NULL,
                    persisted_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS verification_adjudications (
                    adjudication_sha256 TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS verification_reviews (
                    review_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT,
                    UNIQUE(case_id, reviewer_id)
                );
                CREATE TABLE IF NOT EXISTS verification_decisions (
                    decision_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS verification_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES verification_cases(case_id) ON DELETE RESTRICT
                );
                CREATE INDEX IF NOT EXISTS idx_verification_events_case
                    ON verification_events(case_id, event_id);
                CREATE INDEX IF NOT EXISTS idx_verification_receipts_case
                    ON verification_receipts(case_id, receipt_id);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO verification_lifecycle_meta(key, value) VALUES (?, ?)",
                ("schema_version", _SCHEMA_VERSION),
            )

    def persist_admission(
        self,
        *,
        snapshot: VerificationCaseSnapshot,
        persisted: PersistedEvidenceAdmission,
        submissions: tuple[SignedExternalEvidenceSubmission, ...],
    ) -> VerificationCaseSnapshot:
        """Atomically create a case and reserve every receipt ID globally."""
        if snapshot.case_id != persisted.case_id:
            raise WebVerificationContractError("verification case and admission IDs do not match")
        submission_by_id = {item.receipt.receipt_id: item for item in submissions}
        verified_by_id = {item.receipt.receipt_id: item for item in persisted.admission.receipts}
        if set(submission_by_id) != set(persisted.receipt_ids):
            raise WebVerificationContractError(
                "persisted evidence is missing its signed submissions"
            )
        try:
            with self._connect(immediate=True) as connection:
                connection.execute(
                    "INSERT INTO verification_cases("
                    "case_id,state,revision,snapshot_json,case_sha256"
                    ") VALUES (?,?,?,?,?)",
                    (
                        snapshot.case_id,
                        snapshot.state.value,
                        snapshot.revision,
                        _json(snapshot),
                        snapshot.case_sha256,
                    ),
                )
                connection.execute(
                    "INSERT INTO verification_admissions("
                    "admission_id,case_id,record_json,record_sha256"
                    ") VALUES (?,?,?,?)",
                    (
                        persisted.admission.admission_id,
                        snapshot.case_id,
                        _json(persisted),
                        persisted.ledger_sha256,
                    ),
                )
                for receipt_id in persisted.receipt_ids:
                    connection.execute(
                        "INSERT INTO verification_receipts(receipt_id,case_id,submission_json,"
                        "verified_json,persisted_at) VALUES (?,?,?,?,?)",
                        (
                            receipt_id,
                            snapshot.case_id,
                            _json(submission_by_id[receipt_id]),
                            _json(verified_by_id[receipt_id]),
                            persisted.persisted_at.isoformat(),
                        ),
                    )
                self._append_event(
                    connection,
                    snapshot.case_id,
                    "evidence_admitted",
                    {
                        "admission_sha256": persisted.ledger_sha256,
                        "receipt_ids": list(persisted.receipt_ids),
                    },
                    persisted.persisted_at,
                )
        except sqlite3.IntegrityError as exc:
            raise WebVerificationContractError(
                "verification evidence replay or duplicate case was rejected durably"
            ) from exc
        return snapshot

    def get_case(self, case_id: str) -> VerificationCaseSnapshot:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state, revision, snapshot_json, case_sha256 FROM verification_cases "
                "WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise WebVerificationContractError("verification case does not exist")
        try:
            snapshot = VerificationCaseSnapshot.model_validate(json.loads(row["snapshot_json"]))
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError(
                "verification case ledger entry is malformed"
            ) from exc
        if (
            snapshot.case_sha256 != row["case_sha256"]
            or snapshot.state.value != row["state"]
            or snapshot.revision != row["revision"]
        ):
            raise WebVerificationContractError("verification case ledger integrity check failed")
        return snapshot

    def get_admission(self, case_id: str) -> PersistedEvidenceAdmission:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM verification_admissions WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise WebVerificationContractError("verification evidence admission does not exist")
        try:
            record = PersistedEvidenceAdmission.model_validate(json.loads(row["record_json"]))
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError(
                "verification evidence ledger entry is malformed"
            ) from exc
        if record.ledger_sha256 != row["record_sha256"]:
            raise WebVerificationContractError(
                "verification evidence ledger integrity check failed"
            )
        return record

    def list_verified_receipts(self, case_id: str) -> tuple[VerifiedExternalEvidenceReceipt, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT verified_json FROM verification_receipts "
                "WHERE case_id = ? ORDER BY receipt_id",
                (case_id,),
            ).fetchall()
        try:
            return tuple(
                VerifiedExternalEvidenceReceipt.model_validate(json.loads(row["verified_json"]))
                for row in rows
            )
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError("verification receipt ledger is malformed") from exc

    def save_adjudication(
        self,
        adjudication: StrategyAdjudication,
        *,
        expected_revision: int,
        now: datetime,
    ) -> VerificationCaseSnapshot:
        with self._connect(immediate=True) as connection:
            current = self._get_case_in_transaction(connection, adjudication.case_id)
            if current.revision != expected_revision:
                raise WebVerificationContractError("verification case revision is stale")
            if current.state is not VerificationCaseState.EVIDENCE_ADMITTED:
                raise WebVerificationContractError(
                    "verification case cannot be adjudicated from its state"
                )
            try:
                connection.execute(
                    "INSERT INTO verification_adjudications("
                    "adjudication_sha256,case_id,record_json"
                    ") VALUES (?,?,?)",
                    (adjudication.adjudication_sha256, current.case_id, _json(adjudication)),
                )
            except sqlite3.IntegrityError as exc:
                raise WebVerificationContractError(
                    "verification case was already adjudicated"
                ) from exc
            replacement = self._replacement_snapshot(
                current,
                state=VerificationCaseState.ADJUDICATED,
                revision=current.revision + 1,
                adjudication_sha256=adjudication.adjudication_sha256,
                updated_at=now,
            )
            self._replace_case(connection, current, replacement)
            self._append_event(
                connection,
                current.case_id,
                "adjudicated",
                {
                    "adjudication_sha256": adjudication.adjudication_sha256,
                    "candidate_verdict": adjudication.candidate_verdict.value,
                },
                now,
            )
            return replacement

    def get_adjudication(self, case_id: str) -> StrategyAdjudication:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM verification_adjudications WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise WebVerificationContractError("verification adjudication does not exist")
        try:
            return StrategyAdjudication.model_validate(json.loads(row["record_json"]))
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError("verification adjudication is malformed") from exc

    def add_review(
        self,
        review: HumanVerificationReview,
        *,
        expected_revision: int,
    ) -> VerificationCaseSnapshot:
        with self._connect(immediate=True) as connection:
            current = self._get_case_in_transaction(connection, review.case_id)
            if current.revision != expected_revision:
                raise WebVerificationContractError("verification case revision is stale")
            if current.state not in {
                VerificationCaseState.ADJUDICATED,
                VerificationCaseState.AWAITING_HUMAN_REVIEW,
            }:
                raise WebVerificationContractError(
                    "verification case is not accepting human review"
                )
            try:
                connection.execute(
                    "INSERT INTO verification_reviews(review_id,case_id,reviewer_id,role,"
                    "record_json,record_sha256) VALUES (?,?,?,?,?,?)",
                    (
                        review.review_id,
                        review.case_id,
                        review.reviewer_id,
                        review.role.value,
                        _json(review),
                        review.review_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise WebVerificationContractError(
                    "a reviewer may submit only one decision for a verification case"
                ) from exc
            replacement = self._replacement_snapshot(
                current,
                state=VerificationCaseState.AWAITING_HUMAN_REVIEW,
                revision=current.revision + 1,
                updated_at=review.submitted_at,
            )
            self._replace_case(connection, current, replacement)
            self._append_event(
                connection,
                current.case_id,
                "human_review_recorded",
                {
                    "review_id": review.review_id,
                    "reviewer_id": review.reviewer_id,
                    "role": review.role.value,
                    "verdict": review.verdict.value,
                },
                review.submitted_at,
            )
            return replacement

    def list_reviews(self, case_id: str) -> tuple[HumanVerificationReview, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM verification_reviews WHERE case_id = ? "
                "ORDER BY role, reviewer_id",
                (case_id,),
            ).fetchall()
        results: list[HumanVerificationReview] = []
        for row in rows:
            try:
                review = HumanVerificationReview.model_validate(json.loads(row["record_json"]))
            except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise WebVerificationContractError(
                    "verification human review is malformed"
                ) from exc
            if review.review_sha256 != row["record_sha256"]:
                raise WebVerificationContractError(
                    "verification human review integrity check failed"
                )
            results.append(review)
        return tuple(results)

    def finalize(
        self,
        decision: FinalVerificationDecision,
        *,
        expected_revision: int,
    ) -> VerificationCaseSnapshot:
        with self._connect(immediate=True) as connection:
            current = self._get_case_in_transaction(connection, decision.case_id)
            if current.revision != expected_revision:
                raise WebVerificationContractError("verification case revision is stale")
            if current.state is VerificationCaseState.FINALIZED:
                row = connection.execute(
                    "SELECT record_sha256 FROM verification_decisions WHERE case_id = ?",
                    (current.case_id,),
                ).fetchone()
                if row and row["record_sha256"] == decision.decision_sha256:
                    return current
                raise WebVerificationContractError("final verification decision is immutable")
            if current.state is not VerificationCaseState.AWAITING_HUMAN_REVIEW:
                raise WebVerificationContractError(
                    "verification case is not ready for final decision"
                )
            try:
                connection.execute(
                    "INSERT INTO verification_decisions("
                    "decision_id,case_id,record_json,record_sha256"
                    ") VALUES (?,?,?,?)",
                    (
                        decision.decision_id,
                        current.case_id,
                        _json(decision),
                        decision.decision_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise WebVerificationContractError(
                    "final verification decision already exists"
                ) from exc
            replacement = self._replacement_snapshot(
                current,
                state=VerificationCaseState.FINALIZED,
                revision=current.revision + 1,
                final_decision_sha256=decision.decision_sha256,
                updated_at=decision.decided_at,
            )
            self._replace_case(connection, current, replacement)
            self._append_event(
                connection,
                current.case_id,
                "finalized",
                {
                    "decision_sha256": decision.decision_sha256,
                    "verdict": decision.verdict.value,
                },
                decision.decided_at,
            )
            return replacement

    def get_decision(self, case_id: str) -> FinalVerificationDecision | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM verification_decisions WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            decision = FinalVerificationDecision.model_validate(json.loads(row["record_json"]))
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError("final verification decision is malformed") from exc
        if decision.decision_sha256 != row["record_sha256"]:
            raise WebVerificationContractError("final verification decision integrity check failed")
        return decision

    def _get_case_in_transaction(
        self, connection: sqlite3.Connection, case_id: str
    ) -> VerificationCaseSnapshot:
        row = connection.execute(
            "SELECT state,revision,snapshot_json,case_sha256 "
            "FROM verification_cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if row is None:
            raise WebVerificationContractError("verification case does not exist")
        try:
            snapshot = VerificationCaseSnapshot.model_validate(json.loads(row["snapshot_json"]))
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise WebVerificationContractError(
                "verification case ledger entry is malformed"
            ) from exc
        if snapshot.case_sha256 != row["case_sha256"]:
            raise WebVerificationContractError("verification case ledger integrity check failed")
        return snapshot

    @staticmethod
    def _replacement_snapshot(
        current: VerificationCaseSnapshot,
        *,
        state: VerificationCaseState,
        revision: int,
        updated_at: datetime,
        adjudication_sha256: str | None = None,
        final_decision_sha256: str | None = None,
    ) -> VerificationCaseSnapshot:
        payload = current.model_dump()
        payload.update(
            {
                "state": state,
                "revision": revision,
                "updated_at": updated_at.astimezone(UTC),
                "case_sha256": "0" * 64,
            }
        )
        if adjudication_sha256 is not None:
            payload["adjudication_sha256"] = adjudication_sha256
        if final_decision_sha256 is not None:
            payload["final_decision_sha256"] = final_decision_sha256
        provisional = VerificationCaseSnapshot.model_construct(**payload)
        payload["case_sha256"] = sha256_json(
            provisional.model_dump(mode="json", exclude={"case_sha256"})
        )
        return VerificationCaseSnapshot.model_validate(payload)

    @staticmethod
    def _replace_case(
        connection: sqlite3.Connection,
        current: VerificationCaseSnapshot,
        replacement: VerificationCaseSnapshot,
    ) -> None:
        cursor = connection.execute(
            "UPDATE verification_cases SET state=?, revision=?, snapshot_json=?, case_sha256=? "
            "WHERE case_id=? AND revision=? AND case_sha256=?",
            (
                replacement.state.value,
                replacement.revision,
                _json(replacement),
                replacement.case_sha256,
                current.case_id,
                current.revision,
                current.case_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise WebVerificationContractError("verification case compare-and-swap failed")

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        case_id: str,
        event_type: str,
        detail: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        connection.execute(
            "INSERT INTO verification_events(case_id,event_type,occurred_at,detail_json) "
            "VALUES (?,?,?,?)",
            (case_id, event_type, occurred_at.astimezone(UTC).isoformat(), _json(detail)),
        )
