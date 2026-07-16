"""SQLite-backed authorization registry with append-only audit events."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.authorization.models import (
    AuthorizationEvent,
    AuthorizationEventType,
    AuthorizationRecord,
    authorization_record_sha256,
)
from vulnhunter.exceptions import (
    AuthorizationIntegrityError,
    AuthorizationNotFoundError,
    AuthorizationPolicyError,
)
from vulnhunter.security import redact_mapping, redact_text

_SCHEMA_VERSION = "1"


_SHA256_AUTHORIZATION_EVENT_FIELDS = frozenset(
    {
        "record_sha256",
        "previous_record_sha256",
        "source_record_sha256",
    }
)
_SHA256_AUTHORIZATION_EVENT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_AUTHORIZATION_ID_PATTERN = re.compile(r"^auth-[0-9a-f]{20}$")


def _redact_authorization_event_detail(
    detail: dict[str, object],
) -> dict[str, object]:
    """Redact event data without corrupting valid integrity digests."""

    redacted = redact_mapping(detail)

    def restore(
        original: object,
        safe: object,
        *,
        field_name: str | None = None,
    ) -> object:
        if (
            field_name == "authorization_id"
            and isinstance(original, str)
            and _AUTHORIZATION_ID_PATTERN.fullmatch(original)
        ):
            return original

        if (
            field_name in _SHA256_AUTHORIZATION_EVENT_FIELDS
            and isinstance(original, str)
            and _SHA256_AUTHORIZATION_EVENT_PATTERN.fullmatch(original)
        ):
            return original

        if isinstance(original, dict) and isinstance(safe, dict):
            return {
                str(key): restore(
                    value,
                    safe.get(str(key)),
                    field_name=str(key),
                )
                for key, value in original.items()
            }

        if isinstance(original, (list, tuple)) and isinstance(safe, (list, tuple)):
            if len(original) != len(safe):
                return safe

            return [restore(original[index], safe[index]) for index in range(len(original))]

        return safe

    result = restore(detail, redacted)

    if not isinstance(result, dict):
        raise TypeError("Authorization event detail must remain a dictionary.")

    return result


class AuthorizationStore:
    """Transactional local registry for explicit target permission records."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_path(cls, path: Path) -> AuthorizationStore:
        """Create a registry handle for one local SQLite file."""
        return cls(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create missing registry tables without deleting existing records."""
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS authorization_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    path_boundary TEXT NOT NULL,
                    approved_addresses_json TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    evidence_reference TEXT,
                    issued_at TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    maximum_pages INTEGER NOT NULL,
                    maximum_depth INTEGER NOT NULL,
                    maximum_requests INTEGER NOT NULL,
                    minimum_request_delay_seconds REAL NOT NULL,
                    status TEXT NOT NULL,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    record_sha256 TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS authorization_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    authorization_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    FOREIGN KEY (authorization_id)
                        REFERENCES authorizations(authorization_id)
                        ON DELETE RESTRICT
                );

                CREATE INDEX IF NOT EXISTS idx_authorizations_status_expiry
                    ON authorizations(status, expires_at);

                CREATE INDEX IF NOT EXISTS idx_authorization_events_record
                    ON authorization_events(authorization_id, event_id);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO authorization_meta(key, value) VALUES (?, ?)",
                ("schema_version", _SCHEMA_VERSION),
            )

    def create(self, record: AuthorizationRecord) -> AuthorizationRecord:
        """Persist one new authorization and its creation event atomically."""
        self._verify_integrity(record)

        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO authorizations (
                        authorization_id, target_url, scheme, hostname, port,
                        path_boundary, approved_addresses_json, owner,
                        approved_by, purpose, evidence_reference, issued_at,
                        valid_from, expires_at, maximum_pages, maximum_depth,
                        maximum_requests, minimum_request_delay_seconds,
                        status, revoked_at, revocation_reason, record_sha256
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?
                    )
                    """,
                    self._record_values(record),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthorizationPolicyError(
                    f"Authorization {record.authorization_id} already exists."
                ) from exc

            self._append_event_in_transaction(
                connection,
                record.authorization_id,
                "created",
                {
                    "target_url": record.target_url,
                    "approved_by": record.approved_by,
                    "expires_at": record.expires_at.isoformat(),
                },
            )

        return record

    def get(self, authorization_id: str) -> AuthorizationRecord:
        """Load and integrity-check one authorization."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()

        if row is None:
            raise AuthorizationNotFoundError(f"Authorization {authorization_id} does not exist.")

        return self._row_to_record(row)

    def list(self, *, limit: int = 100) -> tuple[AuthorizationRecord, ...]:
        """Return newest authorizations first."""
        if limit < 1 or limit > 1_000:
            raise ValueError("limit must be between 1 and 1000.")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM authorizations
                ORDER BY issued_at DESC, authorization_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return tuple(self._row_to_record(row) for row in rows)

    def revoke(
        self,
        authorization_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> AuthorizationRecord:
        """Revoke one active record while preserving its audit history."""
        current = self.get(authorization_id)
        if current.status == "revoked":
            raise AuthorizationPolicyError(f"Authorization {authorization_id} is already revoked.")

        safe_reason = redact_text(reason).strip()[:2_000]
        if not safe_reason:
            raise AuthorizationPolicyError("A revocation reason is required.")

        timestamp = (revoked_at or datetime.now(UTC)).astimezone(UTC)
        replacement_data = current.model_dump()
        replacement_data.update(
            {
                "status": "revoked",
                "revoked_at": timestamp,
                "revocation_reason": safe_reason,
                "record_sha256": "0" * 64,
            }
        )
        replacement_data["record_sha256"] = authorization_record_sha256(replacement_data)
        replacement = AuthorizationRecord.model_validate(replacement_data)

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE authorizations
                SET status = ?, revoked_at = ?, revocation_reason = ?,
                    record_sha256 = ?
                WHERE authorization_id = ? AND status = 'active'
                """,
                (
                    replacement.status,
                    replacement.revoked_at.isoformat(),
                    replacement.revocation_reason,
                    replacement.record_sha256,
                    authorization_id,
                ),
            )
            if cursor.rowcount != 1:
                raise AuthorizationPolicyError(
                    f"Authorization {authorization_id} could not be revoked safely."
                )
            self._append_event_in_transaction(
                connection,
                authorization_id,
                "revoked",
                {"reason": safe_reason},
            )

        return replacement

    def append_event(
        self,
        authorization_id: str,
        event_type: AuthorizationEventType,
        detail: dict[str, object] | None = None,
    ) -> AuthorizationEvent:
        """Append a redacted audit event for an existing authorization."""
        self.get(authorization_id)
        with self._connect() as connection:
            event_id, occurred_at, safe_detail = self._append_event_in_transaction(
                connection,
                authorization_id,
                event_type,
                detail or {},
            )
        return AuthorizationEvent(
            event_id=event_id,
            authorization_id=authorization_id,
            event_type=event_type,
            occurred_at=occurred_at,
            detail=safe_detail,
        )

    def list_events(
        self,
        authorization_id: str,
        *,
        limit: int = 200,
    ) -> tuple[AuthorizationEvent, ...]:
        """Return the newest audit events for one authorization."""
        self.get(authorization_id)
        if limit < 1 or limit > 2_000:
            raise ValueError("limit must be between 1 and 2000.")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_id, authorization_id, event_type,
                       occurred_at, detail_json
                FROM authorization_events
                WHERE authorization_id = ?
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (authorization_id, limit),
            ).fetchall()

        return tuple(
            AuthorizationEvent(
                event_id=row["event_id"],
                authorization_id=row["authorization_id"],
                event_type=row["event_type"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                detail=json.loads(row["detail_json"]),
            )
            for row in rows
        )

    @staticmethod
    def _record_values(record: AuthorizationRecord) -> tuple[object, ...]:
        return (
            record.authorization_id,
            record.target_url,
            record.scheme,
            record.hostname,
            record.port,
            record.path_boundary,
            json.dumps(record.approved_addresses),
            record.owner,
            record.approved_by,
            record.purpose,
            record.evidence_reference,
            record.issued_at.isoformat(),
            record.valid_from.isoformat(),
            record.expires_at.isoformat(),
            record.limits.maximum_pages,
            record.limits.maximum_depth,
            record.limits.maximum_requests,
            record.limits.minimum_request_delay_seconds,
            record.status,
            record.revoked_at.isoformat() if record.revoked_at else None,
            record.revocation_reason,
            record.record_sha256,
        )

    @staticmethod
    def _append_event_in_transaction(
        connection: sqlite3.Connection,
        authorization_id: str,
        event_type: AuthorizationEventType,
        detail: dict[str, object],
    ) -> tuple[int, datetime, dict[str, object]]:
        occurred_at = datetime.now(UTC)
        safe_detail = _redact_authorization_event_detail(detail)
        cursor = connection.execute(
            """
            INSERT INTO authorization_events (
                authorization_id, event_type, occurred_at, detail_json
            ) VALUES (?, ?, ?, ?)
            """,
            (
                authorization_id,
                event_type,
                occurred_at.isoformat(),
                json.dumps(safe_detail, sort_keys=True, default=str),
            ),
        )
        return int(cursor.lastrowid), occurred_at, safe_detail

    @staticmethod
    def _verify_integrity(record: AuthorizationRecord) -> None:
        expected = authorization_record_sha256(record)
        if record.record_sha256 != expected:
            raise AuthorizationIntegrityError(
                f"Authorization {record.authorization_id} failed integrity verification."
            )

    def _row_to_record(self, row: sqlite3.Row) -> AuthorizationRecord:
        try:
            record = AuthorizationRecord(
                authorization_id=row["authorization_id"],
                target_url=row["target_url"],
                scheme=row["scheme"],
                hostname=row["hostname"],
                port=row["port"],
                path_boundary=row["path_boundary"],
                approved_addresses=tuple(json.loads(row["approved_addresses_json"])),
                owner=row["owner"],
                approved_by=row["approved_by"],
                purpose=row["purpose"],
                evidence_reference=row["evidence_reference"],
                issued_at=datetime.fromisoformat(row["issued_at"]),
                valid_from=datetime.fromisoformat(row["valid_from"]),
                expires_at=datetime.fromisoformat(row["expires_at"]),
                limits={
                    "maximum_pages": row["maximum_pages"],
                    "maximum_depth": row["maximum_depth"],
                    "maximum_requests": row["maximum_requests"],
                    "minimum_request_delay_seconds": row["minimum_request_delay_seconds"],
                },
                status=row["status"],
                revoked_at=(
                    datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
                ),
                revocation_reason=row["revocation_reason"],
                record_sha256=row["record_sha256"],
            )
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuthorizationIntegrityError(
                f"Authorization {row['authorization_id']} is malformed."
            ) from exc

        self._verify_integrity(record)
        return record
