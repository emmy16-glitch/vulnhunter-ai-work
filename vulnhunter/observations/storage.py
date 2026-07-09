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
from vulnhunter.review import (
    IndependentReviewOutcome,
    ReviewAdjudicationSummary,
    ReviewCaseSummary,
    ReviewDecisionSummary,
    normalize_reviewer_id,
)
from vulnhunter.security import redact_mapping, redact_text, redact_url

_REVIEW_LABEL_ADAPTER = TypeAdapter(ReviewLabel)
_REVIEW_OUTCOME_ADAPTER = TypeAdapter(ReviewOutcome)
_INDEPENDENT_REVIEW_OUTCOME_ADAPTER = TypeAdapter(IndependentReviewOutcome)


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


class ReviewDecisionRow(Base):
    __tablename__ = "review_decisions"
    __table_args__ = (
        UniqueConstraint(
            "observation_id",
            "reviewer_id",
            name="uq_review_decision_observation_reviewer",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id", ondelete="CASCADE"),
        index=True,
    )
    reviewer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReviewAdjudicationRow(Base):
    __tablename__ = "review_adjudications"
    __table_args__ = (
        UniqueConstraint(
            "observation_id",
            name="uq_review_adjudication_observation",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id", ondelete="CASCADE"),
        index=True,
    )
    adjudicator_id: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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

            governed_decision = session.scalar(
                select(ReviewDecisionRow.id)
                .where(ReviewDecisionRow.observation_id == observation_id)
                .limit(1)
            )
            if governed_decision is not None:
                raise ValueError(
                    "This observation is governed by independent review and cannot "
                    "be overwritten by legacy single-review labelling."
                )

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

            governed_ids = set(
                session.scalars(
                    select(ReviewDecisionRow.observation_id).where(
                        ReviewDecisionRow.observation_id.in_(unique_ids)
                    )
                )
            )
            if governed_ids:
                raise ValueError(
                    "Independent-review cases cannot be overwritten by legacy "
                    "bulk labelling: " + ", ".join(map(str, sorted(governed_ids)))
                )

            for row in rows:
                row.review_label = validated_label
                row.review_note = safe_note
                row.reviewed_at = reviewed_at

            session.flush()
            return tuple(self._to_observation_summary(row) for row in rows)

    def submit_review_decision(
        self,
        observation_id: int,
        reviewer_id: str,
        outcome: str,
        *,
        note: str | None = None,
    ) -> ReviewCaseSummary:
        """Record one immutable primary decision and update effective state."""
        if observation_id < 1:
            raise ValueError("observation_id must be at least 1.")

        normalized_reviewer = normalize_reviewer_id(reviewer_id)
        validated_outcome = _INDEPENDENT_REVIEW_OUTCOME_ADAPTER.validate_python(outcome)
        safe_note = redact_text(note.strip())[:2_000] if note is not None and note.strip() else None
        now = datetime.now(UTC)

        with self._session_factory.begin() as session:
            observation = session.get(ObservationRow, observation_id)
            if observation is None:
                raise ValueError(f"Observation {observation_id} does not exist.")

            adjudication = session.scalar(
                select(ReviewAdjudicationRow).where(
                    ReviewAdjudicationRow.observation_id == observation_id
                )
            )
            if adjudication is not None:
                raise ValueError("This review case has already been adjudicated.")

            decisions = tuple(
                session.scalars(
                    select(ReviewDecisionRow)
                    .where(ReviewDecisionRow.observation_id == observation_id)
                    .order_by(ReviewDecisionRow.id.asc())
                )
            )

            if not decisions and observation.review_label in {
                "confirmed",
                "false_positive",
            }:
                raise ValueError(
                    "This observation already has a legacy final label and cannot "
                    "enter the independent-review workflow."
                )

            if any(item.reviewer_id == normalized_reviewer for item in decisions):
                raise ValueError(
                    "A reviewer may submit only one immutable primary decision per observation."
                )
            if len(decisions) >= 2:
                raise ValueError(
                    "Two primary decisions already exist; use adjudication when they disagree."
                )

            session.add(
                ReviewDecisionRow(
                    observation_id=observation_id,
                    reviewer_id=normalized_reviewer,
                    outcome=validated_outcome,
                    note=safe_note,
                    created_at=now,
                )
            )
            session.flush()

            decisions = tuple(
                session.scalars(
                    select(ReviewDecisionRow)
                    .where(ReviewDecisionRow.observation_id == observation_id)
                    .order_by(ReviewDecisionRow.id.asc())
                )
            )

            if len(decisions) == 1:
                observation.review_label = "needs_review"
                observation.review_note = (
                    "One independent decision recorded; a distinct second reviewer is required."
                )
            elif decisions[0].outcome == decisions[1].outcome:
                observation.review_label = decisions[0].outcome
                observation.review_note = "Final label established by two-reviewer consensus."
            else:
                observation.review_label = "needs_review"
                observation.review_note = (
                    "Primary reviewers disagreed; independent adjudication is required."
                )

            observation.reviewed_at = now
            session.flush()
            return self._review_case_from_session(session, observation)

    def adjudicate_review(
        self,
        observation_id: int,
        adjudicator_id: str,
        outcome: str,
        *,
        rationale: str,
    ) -> ReviewCaseSummary:
        """Resolve a two-reviewer disagreement with a distinct adjudicator."""
        if observation_id < 1:
            raise ValueError("observation_id must be at least 1.")

        normalized_adjudicator = normalize_reviewer_id(adjudicator_id)
        validated_outcome = _INDEPENDENT_REVIEW_OUTCOME_ADAPTER.validate_python(outcome)
        if not rationale.strip():
            raise ValueError("An adjudication rationale is required.")
        safe_rationale = redact_text(rationale.strip())[:2_000]
        now = datetime.now(UTC)

        with self._session_factory.begin() as session:
            observation = session.get(ObservationRow, observation_id)
            if observation is None:
                raise ValueError(f"Observation {observation_id} does not exist.")

            existing = session.scalar(
                select(ReviewAdjudicationRow).where(
                    ReviewAdjudicationRow.observation_id == observation_id
                )
            )
            if existing is not None:
                raise ValueError("This review case has already been adjudicated.")

            decisions = tuple(
                session.scalars(
                    select(ReviewDecisionRow)
                    .where(ReviewDecisionRow.observation_id == observation_id)
                    .order_by(ReviewDecisionRow.id.asc())
                )
            )
            if len(decisions) != 2:
                raise ValueError("Adjudication requires exactly two primary review decisions.")
            if decisions[0].outcome == decisions[1].outcome:
                raise ValueError(
                    "Matching primary decisions already establish consensus and "
                    "must not be adjudicated."
                )
            reviewer_ids = {item.reviewer_id for item in decisions}
            if normalized_adjudicator in reviewer_ids:
                raise ValueError("The adjudicator must be distinct from both primary reviewers.")

            session.add(
                ReviewAdjudicationRow(
                    observation_id=observation_id,
                    adjudicator_id=normalized_adjudicator,
                    outcome=validated_outcome,
                    rationale=safe_rationale,
                    created_at=now,
                )
            )
            observation.review_label = validated_outcome
            observation.review_note = "Final label established by independent adjudication."
            observation.reviewed_at = now
            session.flush()
            return self._review_case_from_session(session, observation)

    def get_review_case(self, observation_id: int) -> ReviewCaseSummary:
        """Return one observation's review decisions and final resolution."""
        if observation_id < 1:
            raise ValueError("observation_id must be at least 1.")

        with Session(self._engine) as session:
            observation = session.get(ObservationRow, observation_id)
            if observation is None:
                raise ValueError(f"Observation {observation_id} does not exist.")
            return self._review_case_from_session(session, observation)

    def list_second_review_queue(
        self,
        reviewer_id: str,
        *,
        limit: int = 50,
    ) -> tuple[ReviewCaseSummary, ...]:
        """Return cases awaiting a distinct second primary reviewer."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500.")
        normalized_reviewer = normalize_reviewer_id(reviewer_id)

        with Session(self._engine) as session:
            decision_rows = tuple(
                session.scalars(select(ReviewDecisionRow).order_by(ReviewDecisionRow.id.asc()))
            )
            by_observation: dict[int, list[ReviewDecisionRow]] = {}
            for decision in decision_rows:
                by_observation.setdefault(decision.observation_id, []).append(decision)

            candidate_ids = [
                observation_id
                for observation_id, decisions in by_observation.items()
                if len(decisions) == 1 and decisions[0].reviewer_id != normalized_reviewer
            ]
            if not candidate_ids:
                return ()

            severity_rank = case(
                (ObservationRow.severity == "high", 0),
                (ObservationRow.severity == "medium", 1),
                (ObservationRow.severity == "low", 2),
                else_=3,
            )
            observations = tuple(
                session.scalars(
                    select(ObservationRow)
                    .where(
                        ObservationRow.id.in_(candidate_ids),
                        ObservationRow.review_label == "needs_review",
                    )
                    .order_by(severity_rank, ObservationRow.id.asc())
                    .limit(limit)
                )
            )
            return tuple(
                self._review_case_from_session(session, observation) for observation in observations
            )

    def list_disputed_review_cases(
        self,
        *,
        limit: int = 50,
    ) -> tuple[ReviewCaseSummary, ...]:
        """Return unresolved two-reviewer disagreements."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500.")

        with Session(self._engine) as session:
            decision_rows = tuple(
                session.scalars(select(ReviewDecisionRow).order_by(ReviewDecisionRow.id.asc()))
            )
            by_observation: dict[int, list[ReviewDecisionRow]] = {}
            for decision in decision_rows:
                by_observation.setdefault(decision.observation_id, []).append(decision)

            adjudicated_ids = set(session.scalars(select(ReviewAdjudicationRow.observation_id)))
            candidate_ids = [
                observation_id
                for observation_id, decisions in by_observation.items()
                if len(decisions) == 2
                and decisions[0].outcome != decisions[1].outcome
                and observation_id not in adjudicated_ids
            ]
            if not candidate_ids:
                return ()

            observations = tuple(
                session.scalars(
                    select(ObservationRow)
                    .where(ObservationRow.id.in_(candidate_ids))
                    .order_by(ObservationRow.id.asc())
                    .limit(limit)
                )
            )
            return tuple(
                self._review_case_from_session(session, observation) for observation in observations
            )

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

    def _review_case_from_session(
        self,
        session: Session,
        observation: ObservationRow,
    ) -> ReviewCaseSummary:
        decisions = tuple(
            session.scalars(
                select(ReviewDecisionRow)
                .where(ReviewDecisionRow.observation_id == observation.id)
                .order_by(ReviewDecisionRow.id.asc())
            )
        )
        adjudication = session.scalar(
            select(ReviewAdjudicationRow).where(
                ReviewAdjudicationRow.observation_id == observation.id
            )
        )

        if adjudication is not None:
            state = "adjudicated"
        elif len(decisions) == 2 and decisions[0].outcome == decisions[1].outcome:
            state = "consensus"
        elif len(decisions) == 2:
            state = "disputed"
        elif len(decisions) == 1:
            state = "pending_second_review"
        elif observation.review_label in {"confirmed", "false_positive"}:
            state = "legacy_final"
        elif observation.review_label == "needs_review":
            state = "legacy_needs_review"
        else:
            state = "unreviewed"

        return ReviewCaseSummary(
            observation=self._to_observation_summary(observation),
            state=state,
            effective_label=observation.review_label,
            decisions=tuple(
                ReviewDecisionSummary(
                    id=decision.id,
                    observation_id=decision.observation_id,
                    reviewer_id=decision.reviewer_id,
                    outcome=decision.outcome,
                    note=decision.note,
                    created_at=decision.created_at,
                )
                for decision in decisions
            ),
            adjudication=(
                ReviewAdjudicationSummary(
                    id=adjudication.id,
                    observation_id=adjudication.observation_id,
                    adjudicator_id=adjudication.adjudicator_id,
                    outcome=adjudication.outcome,
                    rationale=adjudication.rationale,
                    created_at=adjudication.created_at,
                )
                if adjudication is not None
                else None
            ),
        )

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
