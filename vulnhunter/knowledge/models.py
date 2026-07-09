"""Validated records for the controlled project-knowledge ingestion system."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SourceType(StrEnum):
    """Supported provenance categories for registered sources."""

    PAPER = "paper"
    REPORT = "report"
    STANDARD = "standard"
    TRANSCRIPT = "transcript"
    DATASET_DOCUMENTATION = "dataset_documentation"
    SANITISED_TEST_RESULT = "sanitised_test_result"
    WEB_EXPORT = "web_export"
    CODE_DOCUMENTATION = "code_documentation"
    OTHER = "other"


class Sensitivity(StrEnum):
    """Information-sensitivity classification."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class TrustLevel(StrEnum):
    """Human-assigned source trust level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class InjectionReviewStatus(StrEnum):
    """Prompt-injection screening and human-review state."""

    NOT_SCREENED = "not_screened"
    NOT_DETECTED = "not_detected"
    MACHINE_FLAGGED = "machine_flagged"
    HUMAN_CLEARED = "human_cleared"
    HUMAN_REJECTED = "human_rejected"


class HumanReviewStatus(StrEnum):
    """Human review state for a source and its interpretation."""

    PENDING = "pending"
    APPROVED = "approved"
    NEEDS_CHANGES = "needs_changes"
    REJECTED = "rejected"


class InjectionFinding(BaseModel):
    """One non-executing prompt-injection screening indicator."""

    model_config = ConfigDict(frozen=True)

    pattern_id: str
    line_number: int = Field(ge=1)
    excerpt: str = Field(min_length=1, max_length=240)


class SourceManifest(BaseModel):
    """Canonical provenance record for one preserved source."""

    model_config = ConfigDict(frozen=True)

    source_id: str = Field(pattern=r"^SRC-\d{8}-[a-f0-9]{12}$")
    title: str = Field(min_length=1, max_length=300)
    origin: str = Field(min_length=1, max_length=1000)
    source_type: SourceType
    publication_date: date | None = None
    ingest_date: datetime
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    original_filename: str = Field(min_length=1, max_length=255)
    preserved_relative_path: str = Field(min_length=1, max_length=1000)
    size_bytes: int = Field(ge=0)
    sensitivity: Sensitivity
    trust_level: TrustLevel
    prompt_injection_review_status: InjectionReviewStatus
    injection_findings: tuple[InjectionFinding, ...] = ()
    related_notes: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    human_review_status: HumanReviewStatus = HumanReviewStatus.PENDING
    human_review_note: str | None = Field(default=None, max_length=4000)


class KnowledgeStatus(BaseModel):
    """Summary of the local project-knowledge store."""

    model_config = ConfigDict(frozen=True)

    total_sources: int = Field(ge=0)
    pending_review: int = Field(ge=0)
    approved: int = Field(ge=0)
    rejected: int = Field(ge=0)
    needs_changes: int = Field(ge=0)
    injection_flagged: int = Field(ge=0)
    wiki_notes: int = Field(ge=0)
