"""Immutable contracts for bounded, evidence-led vulnerability hunt loops."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class HuntAltitude(StrEnum):
    ARTIFACT = "artifact"
    ATTACK_SURFACE = "attack_surface"
    COMPONENT = "component"
    CODE = "code"
    NATIVE = "native"
    RUNTIME = "runtime"
    VERIFICATION = "verification"
    VARIANT_SWEEP = "variant_sweep"


class CoverageStatus(StrEnum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COVERED = "covered"
    BLOCKED = "blocked"


class CandidateState(StrEnum):
    GENERATED = "generated"
    JUDGING = "judging"
    EVIDENCE_REQUIRED = "evidence_required"
    VERIFIED = "verified"
    CONFIRMED = "confirmed"
    DOWNGRADED = "downgraded"
    REJECTED = "rejected"
    SWEPT = "swept"


class HuntRound(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    round_id: str
    altitude: HuntAltitude
    label: str
    purpose: str
    tool_ids: tuple[str, ...] = ()
    status: CoverageStatus = CoverageStatus.PLANNED
    blocked_reason: str | None = None


class CoverageCell(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cell_id: str
    altitude: HuntAltitude
    object_reference: str
    weakness_class: str
    scrutiny_level: int = Field(default=0, ge=0, le=10)
    attempts: int = Field(default=0, ge=0)
    evidence_receipts: tuple[str, ...] = ()
    status: CoverageStatus = CoverageStatus.PLANNED


class CandidateRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    weakness_id: str
    title: str
    component: str | None = None
    state: CandidateState = CandidateState.GENERATED
    severity: str = "unknown"
    evidence_receipts: tuple[str, ...] = ()
    judge_receipts: tuple[str, ...] = ()
    disposition_reason: str | None = None


class HuntPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hunt_id: str
    run_id: str
    subject_reference: str
    subject_sha256: str
    profile: str
    maximum_rounds: int = Field(default=8, ge=1, le=32)
    maximum_candidates: int = Field(default=100, ge=1, le=1_000)
    rounds: tuple[HuntRound, ...] = Field(min_length=1)
    coverage: tuple[CoverageCell, ...] = Field(min_length=1)
    plan_sha256: str
