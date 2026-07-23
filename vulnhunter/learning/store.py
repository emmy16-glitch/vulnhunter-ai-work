"""Transactional storage for controlled learning and evaluation records."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.learning.models import (
    CandidateStatus,
    EvaluationResult,
    MemoryCandidate,
    MemoryKind,
    MemoryReview,
    PromotionRecord,
)


class ControlledMemoryStoreError(RuntimeError):
    pass


class ControlledMemoryStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "controlled-memory.sqlite3"
        self._initialize()

    @classmethod
    def from_environment(cls) -> ControlledMemoryStore | None:
        enabled = os.environ.get("VULNHUNTER_LEARNING_ENABLED", "false").strip().lower()
        if enabled not in {"1", "true", "yes", "on"}:
            return None
        return cls(os.environ.get("VULNHUNTER_LEARNING_ROOT", ".local/controlled-memory"))

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
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

    def _initialize(self) -> None:
        with self._connect(write=True) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS memory_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    candidate_sha256 TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_run_id TEXT NOT NULL,
                    candidate_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS memory_candidates_status_idx
                    ON memory_candidates(status, kind, created_at);
                CREATE TABLE IF NOT EXISTS memory_reviews (
                    review_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    review_json TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES memory_candidates(candidate_id)
                );
                CREATE TABLE IF NOT EXISTS memory_evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    passed INTEGER NOT NULL,
                    evaluation_json TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES memory_candidates(candidate_id)
                );
                CREATE TABLE IF NOT EXISTS memory_promotions (
                    promotion_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL UNIQUE,
                    promotion_json TEXT NOT NULL,
                    promoted_at TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES memory_candidates(candidate_id)
                );
                """
            )

    def add_candidate(self, candidate: MemoryCandidate) -> bool:
        with self._connect(write=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO memory_candidates(
                        candidate_id, candidate_sha256, kind, status, source_run_id,
                        candidate_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate.candidate_id,
                        candidate.candidate_sha256,
                        candidate.kind.value,
                        candidate.status.value,
                        candidate.source_run_id,
                        candidate.model_dump_json(),
                        candidate.created_at.isoformat(),
                        candidate.updated_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def get_candidate(self, candidate_id: str) -> MemoryCandidate:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT candidate_json FROM memory_candidates WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
        if row is None:
            raise ControlledMemoryStoreError("learning candidate does not exist")
        try:
            return MemoryCandidate.model_validate_json(row["candidate_json"])
        except ValidationError as exc:
            raise ControlledMemoryStoreError("stored learning candidate is invalid") from exc

    def list_candidates(
        self,
        *,
        status: CandidateStatus | None = None,
        limit: int = 100,
    ) -> tuple[MemoryCandidate, ...]:
        if not 1 <= limit <= 1_000:
            raise ControlledMemoryStoreError("candidate list limit must be between 1 and 1000")
        query = "SELECT candidate_json FROM memory_candidates"
        params: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status.value,)
        query += " ORDER BY created_at DESC, candidate_id LIMIT ?"
        params += (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        try:
            return tuple(MemoryCandidate.model_validate_json(row["candidate_json"]) for row in rows)
        except ValidationError as exc:
            raise ControlledMemoryStoreError("stored learning candidate is invalid") from exc

    def _replace_candidate(self, candidate: MemoryCandidate) -> None:
        with self._connect(write=True) as connection:
            cursor = connection.execute(
                """
                UPDATE memory_candidates
                SET status = ?, candidate_json = ?, updated_at = ?
                WHERE candidate_id = ?
                """,
                (
                    candidate.status.value,
                    candidate.model_dump_json(),
                    candidate.updated_at.isoformat(),
                    candidate.candidate_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlledMemoryStoreError("learning candidate update lost its target")

    def add_review(self, review: MemoryReview, candidate: MemoryCandidate) -> None:
        with self._connect(write=True) as connection:
            connection.execute(
                """
                INSERT INTO memory_reviews(
                    review_id, candidate_id, decision, review_json, reviewed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    review.review_id,
                    review.candidate_id,
                    review.decision.value,
                    review.model_dump_json(),
                    review.reviewed_at.isoformat(),
                ),
            )
        self._replace_candidate(candidate)

    def add_evaluation(self, evaluation: EvaluationResult) -> None:
        with self._connect(write=True) as connection:
            connection.execute(
                """
                INSERT INTO memory_evaluations(
                    evaluation_id, candidate_id, passed, evaluation_json, evaluated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    evaluation.evaluation_id,
                    evaluation.candidate_id,
                    int(evaluation.passed),
                    evaluation.model_dump_json(),
                    evaluation.evaluated_at.isoformat(),
                ),
            )

    def evaluations_for(self, candidate_id: str) -> tuple[EvaluationResult, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evaluation_json FROM memory_evaluations
                WHERE candidate_id = ? ORDER BY evaluated_at, evaluation_id
                """,
                (candidate_id,),
            ).fetchall()
        try:
            return tuple(
                EvaluationResult.model_validate_json(row["evaluation_json"]) for row in rows
            )
        except ValidationError as exc:
            raise ControlledMemoryStoreError("stored learning evaluation is invalid") from exc

    def promote(self, record: PromotionRecord, candidate: MemoryCandidate) -> None:
        with self._connect(write=True) as connection:
            connection.execute(
                """
                INSERT INTO memory_promotions(
                    promotion_id, candidate_id, promotion_json, promoted_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    record.promotion_id,
                    record.candidate_id,
                    record.model_dump_json(),
                    record.promoted_at.isoformat(),
                ),
            )
        self._replace_candidate(candidate)

    def retrieve_promoted(
        self,
        *,
        kind: MemoryKind | None = None,
        limit: int = 8,
    ) -> tuple[MemoryCandidate, ...]:
        if not 1 <= limit <= 32:
            raise ControlledMemoryStoreError("memory retrieval limit must be between 1 and 32")
        query = "SELECT candidate_json FROM memory_candidates WHERE status = ?"
        params: list[object] = [CandidateStatus.PROMOTED.value]
        if kind is not None:
            query += " AND kind = ?"
            params.append(kind.value)
        query += " ORDER BY updated_at DESC, candidate_id LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        try:
            return tuple(MemoryCandidate.model_validate_json(row["candidate_json"]) for row in rows)
        except ValidationError as exc:
            raise ControlledMemoryStoreError("stored promoted memory is invalid") from exc
