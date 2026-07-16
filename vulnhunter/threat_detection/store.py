"""Hash-chained append-only storage for threat assessments."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from vulnhunter.actions.models import canonical_json
from vulnhunter.threat_detection.models import ThreatAssessment

_ZERO_HASH = "0" * 64


class ThreatAuditIntegrityError(RuntimeError):
    pass


class ThreatAssessmentStore:
    def __init__(self, database: Path | str) -> None:
        self.database = Path(database).expanduser().resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_assessments (
                    execution_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (execution_id, sequence)
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append(self, assessment: ThreatAssessment) -> str:
        payload = assessment.model_dump(mode="json")
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            previous = connection.execute(
                """
                SELECT sequence, record_sha256 FROM threat_assessments
                 WHERE execution_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (assessment.execution_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_sha256 = _ZERO_HASH if previous is None else str(previous["record_sha256"])
            material = {
                "execution_id": assessment.execution_id,
                "sequence": sequence,
                "payload": payload,
                "previous_sha256": previous_sha256,
            }
            record_sha256 = hashlib.sha256(canonical_json(material)).hexdigest()
            connection.execute(
                """
                INSERT INTO threat_assessments(
                    execution_id, sequence, payload_json, previous_sha256, record_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    assessment.execution_id,
                    sequence,
                    payload_json,
                    previous_sha256,
                    record_sha256,
                ),
            )
        return record_sha256

    def verify(self, execution_id: str) -> str:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, payload_json, previous_sha256, record_sha256
                  FROM threat_assessments WHERE execution_id = ? ORDER BY sequence
                """,
                (execution_id,),
            ).fetchall()
        previous_sha256 = _ZERO_HASH
        for expected_sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != expected_sequence:
                raise ThreatAuditIntegrityError("threat assessment sequence is not contiguous")
            if row["previous_sha256"] != previous_sha256:
                raise ThreatAuditIntegrityError("threat assessment previous hash does not match")
            payload = json.loads(row["payload_json"])
            material = {
                "execution_id": execution_id,
                "sequence": expected_sequence,
                "payload": payload,
                "previous_sha256": previous_sha256,
            }
            expected_hash = hashlib.sha256(canonical_json(material)).hexdigest()
            if expected_hash != row["record_sha256"]:
                raise ThreatAuditIntegrityError("threat assessment hash does not match")
            previous_sha256 = expected_hash
        return previous_sha256
