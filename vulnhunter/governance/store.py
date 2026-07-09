"""Transactional SQLite store for campaign governance and authenticated review."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import (
    GovernanceIntegrityError,
    GovernanceNotFoundError,
    GovernancePolicyError,
)
from vulnhunter.governance.models import (
    CampaignApplication,
    CampaignRecord,
    CampaignScan,
    DatasetReleaseManifest,
    GovernanceEvent,
    ReviewAssignment,
    ReviewAttestation,
    ReviewerIdentity,
    application_record_sha256,
    assignment_record_sha256,
    attestation_record_sha256,
    campaign_record_sha256,
    campaign_scan_record_sha256,
    identity_record_sha256,
    release_manifest_sha256,
)
from vulnhunter.security import redact_mapping

_SCHEMA_VERSION = "1"
_ZERO_HASH = "0" * 64


class GovernanceStore:
    """Integrity-checked local governance registry."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_path(cls, path: Path) -> GovernanceStore:
        return cls(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open one transaction and always release its file descriptor."""
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
        """Create the append-preserving governance schema."""
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS governance_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS governance_identities (
                    reviewer_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS governance_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS governance_applications (
                    application_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    application_family TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY (campaign_id)
                        REFERENCES governance_campaigns(campaign_id)
                        ON DELETE RESTRICT,
                    UNIQUE(campaign_id, authorization_id)
                );

                CREATE TABLE IF NOT EXISTS governance_scans (
                    campaign_id TEXT NOT NULL,
                    application_id TEXT NOT NULL,
                    scan_database TEXT NOT NULL,
                    scan_id INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, scan_database, scan_id),
                    FOREIGN KEY (campaign_id)
                        REFERENCES governance_campaigns(campaign_id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (application_id)
                        REFERENCES governance_applications(application_id)
                        ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS governance_assignments (
                    campaign_id TEXT NOT NULL,
                    scan_database TEXT NOT NULL,
                    observation_id INTEGER NOT NULL,
                    application_id TEXT NOT NULL,
                    scan_id INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, scan_database, observation_id),
                    FOREIGN KEY (campaign_id)
                        REFERENCES governance_campaigns(campaign_id)
                        ON DELETE RESTRICT,
                    FOREIGN KEY (application_id)
                        REFERENCES governance_applications(application_id)
                        ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS governance_attestations (
                    attestation_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    scan_database TEXT NOT NULL,
                    observation_id INTEGER NOT NULL,
                    actor_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY (campaign_id)
                        REFERENCES governance_campaigns(campaign_id)
                        ON DELETE RESTRICT,
                    UNIQUE(campaign_id, scan_database, observation_id, actor_id, role)
                );

                CREATE TABLE IF NOT EXISTS governance_releases (
                    release_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    FOREIGN KEY (campaign_id)
                        REFERENCES governance_campaigns(campaign_id)
                        ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS governance_events (
                    event_id INTEGER PRIMARY KEY,
                    subject_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_governance_campaign_status
                    ON governance_campaigns(status, campaign_id);
                CREATE INDEX IF NOT EXISTS idx_governance_application_campaign
                    ON governance_applications(campaign_id, application_id);
                CREATE INDEX IF NOT EXISTS idx_governance_scan_campaign
                    ON governance_scans(campaign_id, application_id, scan_id);
                CREATE INDEX IF NOT EXISTS idx_governance_assignment_campaign
                    ON governance_assignments(campaign_id, observation_id);
                CREATE INDEX IF NOT EXISTS idx_governance_attestation_case
                    ON governance_attestations(campaign_id, observation_id);
                CREATE INDEX IF NOT EXISTS idx_governance_event_subject
                    ON governance_events(subject_type, subject_id, event_id);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO governance_meta(key, value) VALUES (?, ?)",
                ("schema_version", _SCHEMA_VERSION),
            )

    def identity_count(self) -> int:
        with self._connect() as connection:
            value = connection.execute("SELECT COUNT(*) FROM governance_identities").fetchone()[0]
        return int(value)

    def create_identity(self, identity: ReviewerIdentity) -> ReviewerIdentity:
        self._verify_identity(identity)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_identities(
                        reviewer_id, status, record_json, record_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        identity.reviewer_id,
                        identity.status,
                        identity.model_dump_json(),
                        identity.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    f"Identity {identity.reviewer_id} already exists."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="identity",
                subject_id=identity.reviewer_id,
                event_type="created",
                actor_id=identity.created_by,
                detail={"roles": list(identity.roles)},
            )
        return identity

    def get_identity(self, reviewer_id: str) -> ReviewerIdentity:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_identities "
                "WHERE reviewer_id = ?",
                (reviewer_id,),
            ).fetchone()
        if row is None:
            raise GovernanceNotFoundError(f"Identity {reviewer_id} does not exist.")
        return self._identity_from_row(row)

    def list_identities(self) -> tuple[ReviewerIdentity, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_identities ORDER BY reviewer_id"
            ).fetchall()
        return tuple(self._identity_from_row(row) for row in rows)

    def replace_identity(
        self,
        identity: ReviewerIdentity,
        *,
        actor_id: str,
        event_type: str,
        detail: dict[str, object],
    ) -> ReviewerIdentity:
        self._verify_identity(identity)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE governance_identities
                SET status = ?, record_json = ?, record_sha256 = ?
                WHERE reviewer_id = ?
                """,
                (
                    identity.status,
                    identity.model_dump_json(),
                    identity.record_sha256,
                    identity.reviewer_id,
                ),
            )
            if cursor.rowcount != 1:
                raise GovernanceNotFoundError(f"Identity {identity.reviewer_id} does not exist.")
            self._append_event_in_transaction(
                connection,
                subject_type="identity",
                subject_id=identity.reviewer_id,
                event_type=event_type,
                actor_id=actor_id,
                detail=detail,
            )
        return identity

    def create_campaign(self, campaign: CampaignRecord) -> CampaignRecord:
        self._verify_campaign(campaign)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_campaigns(
                        campaign_id, status, created_by, record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        campaign.campaign_id,
                        campaign.status,
                        campaign.created_by,
                        campaign.model_dump_json(),
                        campaign.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    f"Campaign {campaign.campaign_id} already exists."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=campaign.campaign_id,
                event_type="created",
                actor_id=campaign.created_by,
                detail={"owner_id": campaign.owner_id},
            )
        return campaign

    def get_campaign(self, campaign_id: str) -> CampaignRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_campaigns WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        if row is None:
            raise GovernanceNotFoundError(f"Campaign {campaign_id} does not exist.")
        return self._campaign_from_row(row)

    def list_campaigns(self) -> tuple[CampaignRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_campaigns ORDER BY campaign_id"
            ).fetchall()
        return tuple(self._campaign_from_row(row) for row in rows)

    def replace_campaign(
        self,
        campaign: CampaignRecord,
        *,
        actor_id: str,
        event_type: str,
        detail: dict[str, object],
    ) -> CampaignRecord:
        self._verify_campaign(campaign)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE governance_campaigns
                SET status = ?, record_json = ?, record_sha256 = ?
                WHERE campaign_id = ?
                """,
                (
                    campaign.status,
                    campaign.model_dump_json(),
                    campaign.record_sha256,
                    campaign.campaign_id,
                ),
            )
            if cursor.rowcount != 1:
                raise GovernanceNotFoundError(f"Campaign {campaign.campaign_id} does not exist.")
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=campaign.campaign_id,
                event_type=event_type,
                actor_id=actor_id,
                detail=detail,
            )
        return campaign

    def create_application(
        self,
        application: CampaignApplication,
    ) -> CampaignApplication:
        self._verify_application(application)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_applications(
                        application_id, campaign_id, authorization_id,
                        application_family, record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application.application_id,
                        application.campaign_id,
                        application.authorization_id,
                        application.application_family,
                        application.model_dump_json(),
                        application.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    "The campaign already contains this application or authorization."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=application.campaign_id,
                event_type="application_registered",
                actor_id=application.registered_by,
                detail={
                    "application_id": application.application_id,
                    "authorization_id": application.authorization_id,
                    "application_family": application.application_family,
                },
            )
        return application

    def get_application(self, application_id: str) -> CampaignApplication:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_applications "
                "WHERE application_id = ?",
                (application_id,),
            ).fetchone()
        if row is None:
            raise GovernanceNotFoundError(f"Application {application_id} does not exist.")
        return self._application_from_row(row)

    def list_applications(
        self,
        campaign_id: str,
    ) -> tuple[CampaignApplication, ...]:
        self.get_campaign(campaign_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_applications "
                "WHERE campaign_id = ? ORDER BY application_id",
                (campaign_id,),
            ).fetchall()
        return tuple(self._application_from_row(row) for row in rows)

    def create_scan(self, scan: CampaignScan) -> CampaignScan:
        self._verify_scan(scan)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_scans(
                        campaign_id, application_id, scan_database, scan_id,
                        record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan.campaign_id,
                        scan.application_id,
                        scan.scan_database,
                        scan.scan_id,
                        scan.model_dump_json(),
                        scan.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError("This scan is already linked to the campaign.") from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=scan.campaign_id,
                event_type="scan_linked",
                actor_id=scan.linked_by,
                detail={
                    "application_id": scan.application_id,
                    "scan_id": scan.scan_id,
                    "scan_database": scan.scan_database,
                },
            )
        return scan

    def list_scans(self, campaign_id: str) -> tuple[CampaignScan, ...]:
        self.get_campaign(campaign_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_scans "
                "WHERE campaign_id = ? ORDER BY application_id, scan_id",
                (campaign_id,),
            ).fetchall()
        return tuple(self._scan_from_row(row) for row in rows)

    def create_assignment(self, assignment: ReviewAssignment) -> ReviewAssignment:
        self._verify_assignment(assignment)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_assignments(
                        campaign_id, scan_database, observation_id, application_id, scan_id,
                        record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assignment.campaign_id,
                        assignment.scan_database,
                        assignment.observation_id,
                        assignment.application_id,
                        assignment.scan_id,
                        assignment.model_dump_json(),
                        assignment.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    "This observation already has a campaign assignment."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=assignment.campaign_id,
                event_type="review_assigned",
                actor_id=assignment.assigned_by,
                detail={
                    "observation_id": assignment.observation_id,
                    "primary_reviewers": list(assignment.primary_reviewers),
                    "adjudicator_id": assignment.adjudicator_id,
                },
            )
        return assignment

    def get_assignment(
        self,
        campaign_id: str,
        scan_database: str,
        observation_id: int,
    ) -> ReviewAssignment:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_assignments "
                "WHERE campaign_id = ? AND scan_database = ? AND observation_id = ?",
                (campaign_id, scan_database, observation_id),
            ).fetchone()
        if row is None:
            raise GovernanceNotFoundError(
                f"Observation {observation_id} has no assignment in {campaign_id}."
            )
        return self._assignment_from_row(row)

    def list_assignments(self, campaign_id: str) -> tuple[ReviewAssignment, ...]:
        self.get_campaign(campaign_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json, record_sha256 FROM governance_assignments "
                "WHERE campaign_id = ? ORDER BY observation_id",
                (campaign_id,),
            ).fetchall()
        return tuple(self._assignment_from_row(row) for row in rows)

    def create_attestation(
        self,
        attestation: ReviewAttestation,
    ) -> ReviewAttestation:
        self._verify_attestation(attestation)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_attestations(
                        attestation_id, campaign_id, scan_database, observation_id, actor_id,
                        role, record_json, record_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attestation.attestation_id,
                        attestation.campaign_id,
                        attestation.scan_database,
                        attestation.observation_id,
                        attestation.actor_id,
                        attestation.role,
                        attestation.model_dump_json(),
                        attestation.record_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    "This actor already attested this campaign review role."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=attestation.campaign_id,
                event_type="review_attested",
                actor_id=attestation.actor_id,
                detail={
                    "observation_id": attestation.observation_id,
                    "role": attestation.role,
                    "outcome": attestation.outcome,
                },
            )
        return attestation

    def list_attestations(
        self,
        campaign_id: str,
        *,
        scan_database: str | None = None,
        observation_id: int | None = None,
    ) -> tuple[ReviewAttestation, ...]:
        self.get_campaign(campaign_id)
        query = (
            "SELECT record_json, record_sha256 FROM governance_attestations WHERE campaign_id = ?"
        )
        values: list[object] = [campaign_id]
        if scan_database is not None:
            query += " AND scan_database = ?"
            values.append(scan_database)
        if observation_id is not None:
            query += " AND observation_id = ?"
            values.append(observation_id)
        query += " ORDER BY observation_id, attestation_id"
        with self._connect() as connection:
            rows = connection.execute(query, tuple(values)).fetchall()
        return tuple(self._attestation_from_row(row) for row in rows)

    def create_release(
        self,
        manifest: DatasetReleaseManifest,
    ) -> DatasetReleaseManifest:
        self._verify_release(manifest)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO governance_releases(
                        release_id, campaign_id, record_json, manifest_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        manifest.release_id,
                        manifest.campaign_id,
                        manifest.model_dump_json(),
                        manifest.manifest_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernancePolicyError(
                    "This campaign already has a dataset release manifest."
                ) from exc
            self._append_event_in_transaction(
                connection,
                subject_type="campaign",
                subject_id=manifest.campaign_id,
                event_type="dataset_released",
                actor_id=manifest.released_by,
                detail={
                    "release_id": manifest.release_id,
                    "manifest_sha256": manifest.manifest_sha256,
                },
            )
        return manifest

    def get_release(self, campaign_id: str) -> DatasetReleaseManifest:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json, manifest_sha256 FROM governance_releases "
                "WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        if row is None:
            raise GovernanceNotFoundError(
                f"Campaign {campaign_id} has no dataset release manifest."
            )
        return self._release_from_row(row)

    def list_events(
        self,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
        limit: int = 1_000,
    ) -> tuple[GovernanceEvent, ...]:
        if limit < 1 or limit > 10_000:
            raise ValueError("limit must be between 1 and 10000.")
        query = "SELECT * FROM governance_events"
        clauses: list[str] = []
        values: list[object] = []
        if subject_type is not None:
            clauses.append("subject_type = ?")
            values.append(subject_type)
        if subject_id is not None:
            clauses.append("subject_id = ?")
            values.append(subject_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY event_id DESC LIMIT ?"
        values.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(values)).fetchall()
        return tuple(self._event_from_row(row) for row in rows)

    def append_event(
        self,
        *,
        subject_type: str,
        subject_id: str,
        event_type: str,
        actor_id: str,
        detail: dict[str, object] | None = None,
    ) -> GovernanceEvent:
        with self._connect() as connection:
            return self._append_event_in_transaction(
                connection,
                subject_type=subject_type,
                subject_id=subject_id,
                event_type=event_type,
                actor_id=actor_id,
                detail=detail or {},
            )

    def verify_integrity(self) -> None:
        """Verify every stored record and the complete global event chain."""
        for identity in self.list_identities():
            self._verify_identity(identity)
        for campaign in self.list_campaigns():
            self._verify_campaign(campaign)
            for application in self.list_applications(campaign.campaign_id):
                self._verify_application(application)
            for scan in self.list_scans(campaign.campaign_id):
                self._verify_scan(scan)
            for assignment in self.list_assignments(campaign.campaign_id):
                self._verify_assignment(assignment)
            for attestation in self.list_attestations(campaign.campaign_id):
                self._verify_attestation(attestation)
            try:
                release = self.get_release(campaign.campaign_id)
            except GovernanceNotFoundError:
                pass
            else:
                self._verify_release(release)

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM governance_events ORDER BY event_id"
            ).fetchall()

        previous = _ZERO_HASH
        for row in rows:
            event = self._event_from_row(row)
            if event.previous_event_sha256 != previous:
                raise GovernanceIntegrityError(
                    f"Governance event {event.event_id} has an invalid previous hash."
                )
            expected = self._event_sha256(
                event_id=event.event_id,
                subject_type=event.subject_type,
                subject_id=event.subject_id,
                event_type=event.event_type,
                actor_id=event.actor_id,
                occurred_at=event.occurred_at,
                detail=event.detail,
                previous_event_sha256=event.previous_event_sha256,
            )
            if not hmac.compare_digest(expected, event.event_sha256):
                raise GovernanceIntegrityError(
                    f"Governance event {event.event_id} failed integrity verification."
                )
            previous = event.event_sha256

    def _append_event_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        subject_type: str,
        subject_id: str,
        event_type: str,
        actor_id: str,
        detail: dict[str, object],
    ) -> GovernanceEvent:
        latest = connection.execute(
            "SELECT event_id, event_sha256 FROM governance_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        event_id = int(latest["event_id"]) + 1 if latest is not None else 1
        previous = latest["event_sha256"] if latest is not None else _ZERO_HASH
        occurred_at = datetime.now(UTC)
        safe_detail = redact_mapping(detail)
        event_sha = self._event_sha256(
            event_id=event_id,
            subject_type=subject_type,
            subject_id=subject_id,
            event_type=event_type,
            actor_id=actor_id,
            occurred_at=occurred_at,
            detail=safe_detail,
            previous_event_sha256=previous,
        )
        connection.execute(
            """
            INSERT INTO governance_events(
                event_id, subject_type, subject_id, event_type, actor_id,
                occurred_at, detail_json, previous_event_sha256, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                subject_type,
                subject_id,
                event_type,
                actor_id,
                occurred_at.isoformat(),
                json.dumps(safe_detail, sort_keys=True, default=str),
                previous,
                event_sha,
            ),
        )
        return GovernanceEvent(
            event_id=event_id,
            subject_type=subject_type,
            subject_id=subject_id,
            event_type=event_type,
            actor_id=actor_id,
            occurred_at=occurred_at,
            detail=safe_detail,
            previous_event_sha256=previous,
            event_sha256=event_sha,
        )

    @staticmethod
    def _event_sha256(
        *,
        event_id: int,
        subject_type: str,
        subject_id: str,
        event_type: str,
        actor_id: str,
        occurred_at: datetime,
        detail: dict[str, object],
        previous_event_sha256: str,
    ) -> str:
        payload = {
            "event_id": event_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "occurred_at": occurred_at.astimezone(UTC).isoformat(),
            "detail": detail,
            "previous_event_sha256": previous_event_sha256,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _verify_identity(value: ReviewerIdentity) -> None:
        if identity_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Identity {value.reviewer_id} failed integrity verification."
            )

    @staticmethod
    def _verify_campaign(value: CampaignRecord) -> None:
        if campaign_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Campaign {value.campaign_id} failed integrity verification."
            )

    @staticmethod
    def _verify_application(value: CampaignApplication) -> None:
        if application_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Application {value.application_id} failed integrity verification."
            )

    @staticmethod
    def _verify_scan(value: CampaignScan) -> None:
        if campaign_scan_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Campaign scan {value.scan_id} failed integrity verification."
            )

    @staticmethod
    def _verify_assignment(value: ReviewAssignment) -> None:
        if assignment_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Assignment for observation {value.observation_id} failed integrity verification."
            )

    @staticmethod
    def _verify_attestation(value: ReviewAttestation) -> None:
        if attestation_record_sha256(value) != value.record_sha256:
            raise GovernanceIntegrityError(
                f"Attestation {value.attestation_id} failed integrity verification."
            )

    @staticmethod
    def _verify_release(value: DatasetReleaseManifest) -> None:
        if release_manifest_sha256(value) != value.manifest_sha256:
            raise GovernanceIntegrityError(
                f"Release {value.release_id} failed integrity verification."
            )

    @classmethod
    def _identity_from_row(cls, row: sqlite3.Row) -> ReviewerIdentity:
        try:
            value = ReviewerIdentity.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Identity record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Identity row hash does not match its record.")
        cls._verify_identity(value)
        return value

    @classmethod
    def _campaign_from_row(cls, row: sqlite3.Row) -> CampaignRecord:
        try:
            value = CampaignRecord.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Campaign record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Campaign row hash does not match its record.")
        cls._verify_campaign(value)
        return value

    @classmethod
    def _application_from_row(cls, row: sqlite3.Row) -> CampaignApplication:
        try:
            value = CampaignApplication.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Application record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Application row hash does not match its record.")
        cls._verify_application(value)
        return value

    @classmethod
    def _scan_from_row(cls, row: sqlite3.Row) -> CampaignScan:
        try:
            value = CampaignScan.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Campaign scan record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Campaign scan row hash does not match its record.")
        cls._verify_scan(value)
        return value

    @classmethod
    def _assignment_from_row(cls, row: sqlite3.Row) -> ReviewAssignment:
        try:
            value = ReviewAssignment.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Assignment record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Assignment row hash does not match its record.")
        cls._verify_assignment(value)
        return value

    @classmethod
    def _attestation_from_row(cls, row: sqlite3.Row) -> ReviewAttestation:
        try:
            value = ReviewAttestation.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Attestation record is invalid.") from exc
        if value.record_sha256 != row["record_sha256"]:
            raise GovernanceIntegrityError("Attestation row hash does not match its record.")
        cls._verify_attestation(value)
        return value

    @classmethod
    def _release_from_row(cls, row: sqlite3.Row) -> DatasetReleaseManifest:
        try:
            value = DatasetReleaseManifest.model_validate_json(row["record_json"])
        except ValidationError as exc:
            raise GovernanceIntegrityError("Release manifest is invalid.") from exc
        if value.manifest_sha256 != row["manifest_sha256"]:
            raise GovernanceIntegrityError("Release row hash does not match its manifest.")
        cls._verify_release(value)
        return value

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> GovernanceEvent:
        try:
            return GovernanceEvent(
                event_id=row["event_id"],
                subject_type=row["subject_type"],
                subject_id=row["subject_id"],
                event_type=row["event_type"],
                actor_id=row["actor_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                detail=json.loads(row["detail_json"]),
                previous_event_sha256=row["previous_event_sha256"],
                event_sha256=row["event_sha256"],
            )
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise GovernanceIntegrityError("Governance event is invalid.") from exc
