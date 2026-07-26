"""Typed contracts for bounded Groq-backed source-code hunts."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class RepositoryVisibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


class SourceHuntStage(StrEnum):
    SNAPSHOT = "snapshot"
    RECONNAISSANCE = "reconnaissance"
    PARALLEL_HUNT = "parallel_hunt"
    FALSIFICATION = "falsification"
    CAPABILITY_FILTER = "capability_filter"
    REMEDIATION = "remediation"
    COMPLETE = "complete"
    ABSTAINED = "abstained"


class CandidateDisposition(StrEnum):
    SURVIVED = "survived"
    REJECTED = "rejected"
    ABSTAINED = "abstained"


class FixVerificationVerdict(StrEnum):
    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    REGRESSION_DETECTED = "regression_detected"
    CANNOT_VERIFY = "cannot_verify"
    OUT_OF_SCOPE_CHANGE = "out_of_scope_change"


class SourceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, max_length=512)
    source_sha256: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    symbol: str | None = Field(default=None, max_length=256)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        normalized = PurePosixPath(value)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError("source reference must be repository-relative")
        return normalized.as_posix()

    @field_validator("source_sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("source_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_line_range(self):
        if self.line_end < self.line_start:
            raise ValueError("line_end cannot precede line_start")
        return self


class RepositoryFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    language: str
    line_count: int = Field(ge=0)


class RepositorySnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_id: str
    repository_root: str
    revision: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: tuple[RepositoryFile, ...]
    total_bytes: int = Field(ge=0)
    created_at: datetime

    @field_validator("repository_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("repository_id must be a stable lowercase identifier")
        return value


class RemoteSourceProcessingApproval(BaseModel):
    """Human approval binding exact repository material to Groq processing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str
    repository_id: str
    revision: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    visibility: RepositoryVisibility
    provider: str = "groq"
    permitted_paths: tuple[str, ...] = (".",)
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    approval_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        repository_id: str,
        revision: str,
        snapshot_sha256: str,
        visibility: RepositoryVisibility,
        permitted_paths: tuple[str, ...],
        approved_by: str,
        approved_at: datetime,
        expires_at: datetime,
    ) -> RemoteSourceProcessingApproval:
        canonical = {
            "repository_id": repository_id,
            "revision": revision,
            "snapshot_sha256": snapshot_sha256,
            "visibility": visibility.value,
            "provider": "groq",
            "permitted_paths": list(permitted_paths),
            "approved_by": approved_by,
            "approved_at": approved_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(
            approval_id=f"source-approval-{digest[:24]}",
            repository_id=repository_id,
            revision=revision,
            snapshot_sha256=snapshot_sha256,
            visibility=visibility,
            permitted_paths=permitted_paths,
            approved_by=approved_by,
            approved_at=approved_at,
            expires_at=expires_at,
            approval_sha256=digest,
        )

    def validate_for(self, snapshot: RepositorySnapshot, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        if current >= self.expires_at:
            raise ValueError("remote source-processing approval has expired")
        if self.provider != "groq":
            raise ValueError("source-processing approval is not bound to Groq")
        if (
            self.repository_id != snapshot.repository_id
            or self.revision != snapshot.revision
            or self.snapshot_sha256 != snapshot.snapshot_sha256
        ):
            raise ValueError("source-processing approval does not match the repository snapshot")


class AttackSurface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    surface_id: str
    entry_point: SourceReference
    entry_kind: str
    attacker_inputs: tuple[str, ...]
    reachable_sinks: tuple[SourceReference, ...]
    sink_kinds: tuple[str, ...]
    guards: tuple[SourceReference, ...] = ()
    call_path: tuple[SourceReference, ...]


class GroqHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str = Field(min_length=3, max_length=200)
    vulnerability_class: str = Field(min_length=2, max_length=80)
    summary: str = Field(min_length=3, max_length=2_000)
    entry_point: SourceReference
    sink: SourceReference
    path: tuple[SourceReference, ...]
    assumptions: tuple[str, ...] = ()
    evidence_refs: tuple[SourceReference, ...]
    confidence: int = Field(ge=0, le=100)


class FalsificationDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    disposition: CandidateDisposition
    reason: str = Field(min_length=3, max_length=2_000)
    blocking_controls: tuple[SourceReference, ...] = ()
    unsupported_assumptions: tuple[str, ...] = ()
    contradicting_evidence: tuple[SourceReference, ...] = ()


class CapabilityAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    meaningful: bool
    required_attacker_capability: str = Field(min_length=2, max_length=500)
    resulting_capability: str = Field(min_length=2, max_length=500)
    impact_boundary: str = Field(min_length=2, max_length=500)
    reason: str = Field(min_length=3, max_length=2_000)


class RemediationProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(min_length=3, max_length=2_000)
    target_files: tuple[str, ...]
    regression_test: str = Field(min_length=3, max_length=4_000)
    compatibility_risks: tuple[str, ...] = ()
    verification_recipe: str = Field(min_length=3, max_length=4_000)


class SourceCandidate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    hypothesis: GroqHypothesis
    falsification: FalsificationDecision
    capability: CapabilityAssessment | None = None
    remediation: RemediationProposal | None = None


class SourceHuntReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str
    stage: SourceHuntStage
    snapshot: RepositorySnapshot
    approval_id: str
    model: str
    surfaces_examined: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    candidates: tuple[SourceCandidate, ...]
    rejected_count: int = Field(ge=0)
    abstained_count: int = Field(ge=0)
    safe_error: str | None = None
    created_at: datetime


class FixVerificationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    original_revision: str
    fixed_revision: str
    verdict: FixVerificationVerdict
    summary: str
    evidence_refs: tuple[SourceReference, ...] = ()
    regressions: tuple[str, ...] = ()
    created_at: datetime
