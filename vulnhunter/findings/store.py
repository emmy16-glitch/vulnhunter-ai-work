"""Transactional SQLite finding store with fingerprint deduplication and CAS."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from vulnhunter.findings.models import Finding


class FindingStoreError(RuntimeError):
    pass


class FindingConflict(FindingStoreError):
    pass


class FindingStore:
    def __init__(self, database: Path | str) -> None:
        self.database = Path(database).expanduser().resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(campaign_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS findings_campaign_idx ON findings(campaign_id);
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

    def create(self, finding: Finding) -> None:
        if finding.revision != 0:
            raise FindingStoreError("new findings must start at revision zero")
        payload = json.dumps(finding.model_dump(mode="json"), sort_keys=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO findings(
                        finding_id, campaign_id, fingerprint, revision, payload_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (finding.finding_id, finding.campaign_id, finding.fingerprint, 0, payload),
                )
        except sqlite3.IntegrityError as exc:
            raise FindingConflict("finding ID or campaign fingerprint already exists") from exc

    def get(self, finding_id: str) -> Finding:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            raise FindingStoreError(f"unknown finding: {finding_id}")
        return Finding.model_validate_json(row["payload_json"])

    def list_campaign(self, campaign_id: str) -> tuple[Finding, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM findings WHERE campaign_id = ? ORDER BY finding_id",
                (campaign_id,),
            ).fetchall()
        return tuple(Finding.model_validate_json(row["payload_json"]) for row in rows)

    def save(self, finding: Finding, *, expected_revision: int) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json, revision FROM findings WHERE finding_id = ?",
                (finding.finding_id,),
            ).fetchone()
            if row is None:
                raise FindingStoreError(f"unknown finding: {finding.finding_id}")
            if int(row["revision"]) != expected_revision:
                raise FindingConflict(
                    "finding revision conflict: "
                    f"expected {expected_revision}, found {row['revision']}"
                )
            previous = Finding.model_validate_json(row["payload_json"])
            try:
                finding.validate_update_from(previous)
            except ValueError as exc:
                raise FindingStoreError(f"invalid finding update: {exc}") from exc
            payload = json.dumps(finding.model_dump(mode="json"), sort_keys=True)
            cursor = connection.execute(
                """
                UPDATE findings SET revision = ?, payload_json = ?
                 WHERE finding_id = ? AND revision = ?
                """,
                (finding.revision, payload, finding.finding_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise FindingConflict("finding revision changed concurrently")
