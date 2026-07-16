"""Report artifact metadata."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ReportKind(StrEnum):
    CAMPAIGN = "campaign"
    AUTHORIZATION = "authorization"
    TOOL_READINESS = "tool_readiness"
    APPROVALS = "approvals"
    FINDINGS = "findings"
    EVIDENCE = "evidence"
    ORACLE_CAPSULES = "oracle_capsules"
    ORACLE_VERDICTS = "oracle_verdicts"
    ATTACK_PATHS = "attack_paths"
    REPOSITORY_COVERAGE = "repository_coverage"
    AI_ROUTING = "ai_routing"


class ReportArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str
    kind: ReportKind
    payload_sha256: str
    provenance: tuple[str, ...]
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("report_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("payload_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("payload_sha256 must be a SHA-256 digest")
        return value


class DownloadFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    EVIDENCE_ZIP = "evidence_zip"
    ATTACK_PATH_SVG = "attack_path_svg"


class DownloadArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    format: DownloadFormat
    filename: str
    content_type: str
    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    provenance: tuple[str, ...]
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("artifact_id must be a stable lowercase value")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_artifact_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a SHA-256 digest")
        return value
