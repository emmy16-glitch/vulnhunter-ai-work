"""SQLite persistence for scans, page metadata, observations, and human labels."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    case,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from vulnhunter.mapping.models import MappingResult
from vulnhunter.observations.models import (
    ObservationSummary,
    ReviewLabel,
    ReviewOutcome,
    ScanSummary,
)
from vulnhunter.security import redact_mapping, redact_text, redact_url

_REVIEW_LABEL_ADAPTER = TypeAdapter(ReviewLabel)
_REVIEW_OUTCOME_ADAPTER = TypeAdapter(ReviewOutcome)


class Base(DeclarativeBase):
    """Base class for VulnHunter persistence models."""


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pages_visited: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observations_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)


class PageRow(Base):
    __tablename__ = "pages"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_page_scan_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    elapsed_ms: Mapped[float] = mapped_column(nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    links_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ObservationRow(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_observation_scan_fingerprint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    page_id: Mapped[int | None] = mapped_column(ForeignKey("pages.id", ondelete="SET NULL"))
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    review_label: Mapped[str] = mapped_column(String(30), nullable=False, default="unreviewed")
    review_note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanRepository:
    """Transactional repository for VulnHunter's local SQLite database."""

    def __init__(self, database_url: str) -> None:
        self._engine: Engine = create_engine(database_url, pool_pre_ping=True)

        if self._engine.dialect.name == "sqlite":
            event.listen(self._engine, "connect", self._enable_sqlite_foreign_keys)

        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    @staticmethod
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @classmethod
    def from_path(cls, database_path: Path) -> ScanRepository:
        """Create a repository from a local SQLite file path."""
        resolved_path = database_path.expanduser().resolve()
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        return cls(f"sqlite:///{resolved_path}")

    def initialize(self) -> None:
        """Create missing database tables without deleting existing data."""
        Base.metadata.create_all(self._engine)

    def create_scan(self, target_url: str) -> int:
        """Create and return a running scan record."""
        with self._session_factory.begin() as session:
            row = ScanRow(
                target_url=redact_url(target_url),
                status="running",
                started_at=datetime.now(UTC),
            )
            session.add(row)
            session.flush()
            return row.id

    def complete_scan(self, scan_id: int, result: MappingResult) -> None:
        """Persist one complete mapping result in a single transaction."""
        with self._session_factory.begin() as session:
            scan = session.get(ScanRow, scan_id)

            if scan is None:
                raise ValueError(f"Scan {scan_id} does not exist.")

            if scan.status != "running":
                raise ValueError(f"Scan {scan_id} is already {scan.status}.")

            page_ids_by_url: dict[str, int] = {}

            for page in result.pages:
                page_url = redact_url(page.url)
                row = PageRow(
                    scan_id=scan_id,
                    url=page_url,
                    depth=page.depth,
                    status_code=page.status_code,
                    content_type=redact_text(page.content_type),
                    response_bytes=page.response_bytes,
                    elapsed_ms=page.elapsed_ms,
                    title=redact_text(page.title) if page.title else None,
                    links_discovered=page.links_discovered,
                )
                session.add(row)
                session.flush()
                page_ids_by_url[page_url] = row.id

            unique_observations = {item.fingerprint: item for item in result.observations}

            for observation in unique_observations.values():
                safe_url = redact_url(observation.url)
                safe_evidence = redact_mapping(observation.evidence)
                session.add(
                    ObservationRow(
                        scan_id=scan_id,
                        page_id=page_ids_by_url.get(safe_url),
                        category=observation.category,
                        severity=observation.severity,
                        title=redact_text(observation.title),
                        description=redact_text(observation.description),
                        url=safe_url,
                        evidence_json=json.dumps(
                            safe_evidence,
                            sort_keys=True,
                            default=str,
                        ),
                        fingerprint=observation.fingerprint,
                    )
                )

            scan.status = "completed"
            scan.started_at = result.started_at
            scan.completed_at = result.completed_at
            scan.pages_visited = len(result.pages)
            scan.observations_count = len(unique_observations)
            scan.error_message = None

    def fail_scan(self, scan_id: int, message: str) -> None:
        """Mark a running scan as failed with a redacted message."""
        with self._session_factory.begin() as session:
            scan = session.get(ScanRow, scan_id)

            if scan is None:
                raise ValueError(f"Scan {scan_id} does not exist.")

            scan.status = "failed"
            scan.completed_at = datetime.now(UTC)
            scan.error_message = redact_text(message)[:2_000]

    def list_scans(self, *, limit: int = 50) -> tuple[ScanSummary, ...]:
        """Return newest scans first."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500.")

        with Session(self._engine) as session:
            rows = session.scalars(select(ScanRow).order_by(ScanRow.id.desc()).limit(limit))
            return tuple(
                ScanSummary(
                    id=row.id,
                    target_url=row.target_url,
                    status=row.status,
                    started_at=row.started_at,
                    completed_at=row.completed_at,
                    pages_visited=row.pages_visited,
                    observations_count=row.observations_count,
                    error_message=row.error_message,
                )
                for row in rows
            )

    def list_observations(
        self,
        *,
        scan_id: int | None = None,
        review_label: str | None = None,
        limit: int = 100,
    ) -> tuple[ObservationSummary, ...]:
        """Return newest observations with optional scan and label filters."""
        if limit < 1 or limit > 1_000:
            raise ValueError("limit must be between 1 and 1000.")

        validated_label = (
            _REVIEW_LABEL_ADAPTER.validate_python(review_label)
            if review_label is not None
            else None
        )

        statement = select(ObservationRow).order_by(ObservationRow.id.desc()).limit(limit)

        if scan_id is not None:
            statement = statement.where(ObservationRow.scan_id == scan_id)

        if validated_label is not None:
            statement = statement.where(ObservationRow.review_label == validated_label)

        with Session(self._engine) as session:
            rows = session.scalars(statement)
            return tuple(self._to_observation_summary(row) for row in rows)

    def list_review_queue(
        self,
        *,
        limit: int = 50,
    ) -> tuple[ObservationSummary, ...]:
        """Return high-priority unreviewed findings in deterministic order."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500.")

        severity_rank = case(
            (ObservationRow.severity == "high", 0),
            (ObservationRow.severity == "medium", 1),
            (ObservationRow.severity == "low", 2),
            else_=3,
        )
        review_rank = case(
            (ObservationRow.review_label == "needs_review", 0),
            else_=1,
        )
        statement = (
            select(ObservationRow)
            .where(ObservationRow.review_label.in_(("unreviewed", "needs_review")))
            .order_by(severity_rank, review_rank, ObservationRow.id.asc())
            .limit(limit)
        )

        with Session(self._engine) as session:
            rows = session.scalars(statement)
            return tuple(self._to_observation_summary(row) for row in rows)

    def fingerprint_occurrence_counts(
        self,
        fingerprints: tuple[str, ...],
    ) -> dict[str, int]:
        """Count repeated fingerprints across scans for review context."""
        unique_fingerprints = tuple(sorted(set(fingerprints)))
        if not unique_fingerprints:
            return {}
        if len(unique_fingerprints) > 1_000:
            raise ValueError("At most 1000 fingerprints may be counted at once.")

        statement = (
            select(ObservationRow.fingerprint, func.count(ObservationRow.id))
            .where(ObservationRow.fingerprint.in_(unique_fingerprints))
            .group_by(ObservationRow.fingerprint)
        )

        with Session(self._engine) as session:
            return {fingerprint: count for fingerprint, count in session.execute(statement)}

    def label_observation(
        self,
        observation_id: int,
        label: str,
        *,
        note: str | None = None,
    ) -> ObservationSummary:
        """Apply a validated human-review label to one observation."""
        validated_label = _REVIEW_OUTCOME_ADAPTER.validate_python(label)

        with self._session_factory.begin() as session:
            row = session.get(ObservationRow, observation_id)

            if row is None:
                raise ValueError(f"Observation {observation_id} does not exist.")

            row.review_label = validated_label
            row.review_note = redact_text(note.strip())[:2_000] if note and note.strip() else None
            row.reviewed_at = datetime.now(UTC)
            session.flush()
            return self._to_observation_summary(row)

    def label_observations(
        self,
        observation_ids: tuple[int, ...],
        label: str,
        *,
        note: str | None = None,
    ) -> tuple[ObservationSummary, ...]:
        """Apply one human decision to several observations transactionally."""
        validated_label = _REVIEW_OUTCOME_ADAPTER.validate_python(label)
        unique_ids = tuple(sorted(set(observation_ids)))

        if not unique_ids:
            raise ValueError("At least one observation ID is required.")
        if len(unique_ids) != len(observation_ids):
            raise ValueError("Observation IDs must not contain duplicates.")
        if len(unique_ids) > 1_000:
            raise ValueError("At most 1000 observations may be labelled at once.")
        if any(observation_id < 1 for observation_id in unique_ids):
            raise ValueError("Observation IDs must be positive integers.")

        safe_note = redact_text(note.strip())[:2_000] if note and note.strip() else None
        reviewed_at = datetime.now(UTC)

        with self._session_factory.begin() as session:
            rows = tuple(
                session.scalars(
                    select(ObservationRow)
                    .where(ObservationRow.id.in_(unique_ids))
                    .order_by(ObservationRow.id.asc())
                )
            )

            if len(rows) != len(unique_ids):
                found_ids = {row.id for row in rows}
                missing_ids = [
                    observation_id
                    for observation_id in unique_ids
                    if observation_id not in found_ids
                ]
                raise ValueError("Observations do not exist: " + ", ".join(map(str, missing_ids)))

            for row in rows:
                row.review_label = validated_label
                row.review_note = safe_note
                row.reviewed_at = reviewed_at

            session.flush()
            return tuple(self._to_observation_summary(row) for row in rows)

    def get_observation(self, observation_id: int) -> ObservationSummary:
        """Return one observation by ID or raise a clear error."""
        if observation_id < 1:
            raise ValueError("observation_id must be at least 1.")

        with Session(self._engine) as session:
            row = session.get(ObservationRow, observation_id)

            if row is None:
                raise ValueError(f"Observation {observation_id} does not exist.")

            return self._to_observation_summary(row)

    def list_training_observations(self) -> tuple[ObservationSummary, ...]:
        """Return all human-reviewed binary labels in stable ID order."""
        statement = (
            select(ObservationRow)
            .where(ObservationRow.review_label.in_(("confirmed", "false_positive")))
            .order_by(ObservationRow.id.asc())
        )

        with Session(self._engine) as session:
            rows = session.scalars(statement)
            return tuple(self._to_observation_summary(row) for row in rows)

    @staticmethod
    def _to_observation_summary(row: ObservationRow) -> ObservationSummary:
        return ObservationSummary(
            id=row.id,
            scan_id=row.scan_id,
            page_id=row.page_id,
            category=row.category,
            severity=row.severity,
            title=row.title,
            description=row.description,
            url=row.url,
            evidence=json.loads(row.evidence_json),
            fingerprint=row.fingerprint,
            review_label=row.review_label,
            review_note=row.review_note,
            reviewed_at=row.reviewed_at,
        )
