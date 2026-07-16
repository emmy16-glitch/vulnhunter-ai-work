"""Typed contracts for Android APK ingestion and governed analysis."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class MobileAnalysisProfile(StrEnum):
    STATIC = "static"
    STATIC_AND_NATIVE = "static_and_native"
    DYNAMIC = "dynamic"
    FULL = "full"
    RETEST = "retest"


class MobileArtifactRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    original_filename: str
    stored_path: Path
    sha256: str
    size_bytes: int = Field(ge=1)
    archive_entry_count: int = Field(ge=1)
    total_uncompressed_bytes: int = Field(ge=1)
    manifest_entry: str
    dex_entries: tuple[str, ...]
    native_libraries: tuple[str, ...] = ()
    native_abis: tuple[str, ...] = ()
    ingested_at: datetime = Field(default_factory=utc_now)

    @field_validator("artifact_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("artifact_id must be a stable lowercase identifier")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a SHA-256 digest")
        return value


class MobileAnalysisRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    analysis_id: str
    campaign_id: str
    run_id: str
    requested_by: str
    artifact_id: str
    artifact_sha256: str
    artifact_path: Path
    profile: MobileAnalysisProfile
    authorization_references: tuple[str, ...] = Field(min_length=1)
    timeout_seconds: int = Field(default=1800, ge=1, le=86_400)
    maximum_output_bytes: int = Field(default=20_000_000, ge=1_024, le=500_000_000)
    isolated_runtime_reference: str | None = None
    android_device_reference: str | None = None

    @field_validator(
        "analysis_id",
        "campaign_id",
        "run_id",
        "requested_by",
        "artifact_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("artifact_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_dynamic_contract(self):
        dynamic = self.profile in {MobileAnalysisProfile.DYNAMIC, MobileAnalysisProfile.FULL}
        if dynamic and not self.isolated_runtime_reference:
            raise ValueError("dynamic analysis requires an isolated runtime reference")
        if dynamic and not self.android_device_reference:
            raise ValueError("dynamic analysis requires an Android device reference")
        return self


class MobileFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    weakness_id: str
    title: str
    severity: str
    confidence: str = "candidate"
    component: str | None = None
    tool_ids: tuple[str, ...] = Field(min_length=1)
    evidence: dict[str, object] = Field(default_factory=dict)
    artifact_sha256: str

    @field_validator("finding_id", "weakness_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("finding identifiers must be stable lowercase values")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("artifact_sha256 must be a SHA-256 digest")
        return value
