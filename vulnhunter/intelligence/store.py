"""Transactional queue and report store for advisory finding analysis."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.intelligence.models import (
    AnalysisStatus,
    FindingAnalysisRequest,
    FindingIntelligenceReport,
)
from vulnhunter.security import redact_text


class IntelligenceStoreError(RuntimeError):
    pass


class IntelligenceStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "intelligence.sqlite3"
        self._initialize()

    @classmethod
    def from_environment(cls) -> IntelligenceStore | None:
        enabled = os.environ.get("VULNHUNTER_INTELLIGENCE_ENABLED", "false").strip().lower()
        if enabled not in {"1", "true", "yes", "on"}:
            return None
        root = os.environ.get("VULNHUNTER_INTELLIGENCE_ROOT", ".local/intelligence")
        return cls(root)

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
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    report_json TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    safe_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS analyses_run_idx
                    ON analyses(run_id, status, created_at);
                """
            )

    def enqueue(self, request: FindingAnalysisRequest) -> bool:
        payload = request.model_dump_json()
        now = datetime.now(UTC).isoformat()
        with self._connect(write=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO analyses(
                        analysis_id, finding_id, run_id, status, request_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.analysis_id,
                        request.finding_id,
                        request.run_id,
                        AnalysisStatus.QUEUED.value,
                        payload,
                        request.created_at.isoformat(),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                row = connection.execute(
                    "SELECT request_json FROM analyses WHERE finding_id = ?",
                    (request.finding_id,),
                ).fetchone()
                if row is None:
                    raise IntelligenceStoreError("analysis queue integrity conflict") from exc
                try:
                    existing = FindingAnalysisRequest.model_validate_json(row["request_json"])
                except ValidationError as validation_exc:
                    raise IntelligenceStoreError(
                        "stored analysis request is invalid"
                    ) from validation_exc
                if existing.context_sha256 != request.context_sha256:
                    raise IntelligenceStoreError(
                        "finding analysis was already queued with different context"
                    ) from exc
                return False
        return True

    def claim_next(self, *, maximum_attempts: int = 2) -> FindingAnalysisRequest | None:
        if not 1 <= maximum_attempts <= 5:
            raise IntelligenceStoreError("maximum attempts must be between one and five")
        now = datetime.now(UTC).isoformat()
        with self._connect(write=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM analyses
                WHERE status = ? AND attempts < ?
                ORDER BY created_at, analysis_id
                LIMIT 1
                """,
                (AnalysisStatus.QUEUED.value, maximum_attempts),
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                """
                UPDATE analyses
                SET status = ?, attempts = attempts + 1, safe_error = NULL, updated_at = ?
                WHERE analysis_id = ? AND status = ?
                """,
                (
                    AnalysisStatus.RUNNING.value,
                    now,
                    row["analysis_id"],
                    AnalysisStatus.QUEUED.value,
                ),
            )
            if cursor.rowcount != 1:
                raise IntelligenceStoreError("analysis queue claim lost a concurrency race")
        try:
            return FindingAnalysisRequest.model_validate_json(row["request_json"])
        except ValidationError as exc:
            raise IntelligenceStoreError("stored analysis request is invalid") from exc

    def complete(self, report: FindingIntelligenceReport) -> None:
        if report.status not in {AnalysisStatus.COMPLETED, AnalysisStatus.ABSTAINED}:
            raise IntelligenceStoreError("only completed or abstained reports may be stored")
        with self._connect(write=True) as connection:
            cursor = connection.execute(
                """
                UPDATE analyses
                SET status = ?, report_json = ?, safe_error = ?, updated_at = ?
                WHERE analysis_id = ? AND status = ?
                """,
                (
                    report.status.value,
                    report.model_dump_json(),
                    report.safe_error,
                    report.completed_at.isoformat(),
                    report.analysis_id,
                    AnalysisStatus.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise IntelligenceStoreError("analysis completion did not match a running item")

    def fail(self, analysis_id: str, safe_error: str, *, maximum_attempts: int = 2) -> None:
        detail = redact_text(" ".join(safe_error.split()))[:1_000] or "advisory analysis failed"
        now = datetime.now(UTC).isoformat()
        with self._connect(write=True) as connection:
            row = connection.execute(
                "SELECT attempts, status FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                raise IntelligenceStoreError("analysis item does not exist")
            if row["status"] != AnalysisStatus.RUNNING.value:
                raise IntelligenceStoreError("only a running analysis may fail")
            status = (
                AnalysisStatus.QUEUED
                if int(row["attempts"]) < maximum_attempts
                else AnalysisStatus.FAILED
            )
            connection.execute(
                """
                UPDATE analyses
                SET status = ?, safe_error = ?, updated_at = ?
                WHERE analysis_id = ?
                """,
                (status.value, detail, now, analysis_id),
            )

    def get_report_for_finding(self, finding_id: str) -> FindingIntelligenceReport | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM analyses WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
        if row is None or row["report_json"] is None:
            return None
        try:
            return FindingIntelligenceReport.model_validate_json(row["report_json"])
        except ValidationError as exc:
            raise IntelligenceStoreError("stored intelligence report is invalid") from exc

    def status_for_finding(self, finding_id: str) -> AnalysisStatus | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM analyses WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
        return AnalysisStatus(row["status"]) if row is not None else None

    def list_reports_for_run(self, run_id: str) -> tuple[FindingIntelligenceReport, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT report_json FROM analyses
                WHERE run_id = ? AND report_json IS NOT NULL
                ORDER BY created_at, analysis_id
                """,
                (run_id,),
            ).fetchall()
        reports: list[FindingIntelligenceReport] = []
        for row in rows:
            try:
                reports.append(FindingIntelligenceReport.model_validate_json(row["report_json"]))
            except ValidationError as exc:
                raise IntelligenceStoreError("stored intelligence report is invalid") from exc
        return tuple(reports)
