"""Immutable bindings between chat workspaces and assessment task graphs."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import ActionManifest, sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AssessmentKind(StrEnum):
    WEBSITE = "website"
    APK = "apk"
    SOURCE = "source"
    ACTIVE_VALIDATION = "active_validation"
    REMEDIATION = "remediation"
    RETEST = "retest"
    REPORT = "report"


class AssessmentStage(StrEnum):
    AUTHORIZATION = "authorization"
    PLAN = "plan"
    APPROVAL = "approval"
    EXECUTION = "execution"
    EVIDENCE = "evidence"
    VERIFICATION = "verification"
    REVIEW = "review"
    REPORT = "report"


class AssessmentGraphBundle(BaseModel):
    """Immutable manifest registry and chat-workspace binding for one graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    graph_id: str
    run_id: str
    assessment_kind: AssessmentKind
    workspace_id: UUID | None = None
    owner_id: str
    authorization_id: str
    target_reference: str
    node_stages: dict[str, AssessmentStage] = Field(min_length=1)
    manifests: tuple[ActionManifest, ...] = Field(min_length=1)
    created_at: datetime

    @field_validator("graph_id", "run_id", "owner_id", "authorization_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
  raise ValueError("assessment graph identifiers must be stable lowercase values")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
  raise ValueError("assessment graph timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        if not self.target_reference.strip():
  raise ValueError("target_reference must not be blank")
        if len(set(self.node_stages)) != len(self.node_stages):
  raise ValueError("task graph node identifiers must be unique")
        fingerprints = [manifest.fingerprint() for manifest in self.manifests]
        if len(set(fingerprints)) != len(fingerprints):
  raise ValueError("assessment action manifests must be unique")
        if len(self.node_stages) != len(self.manifests):
  raise ValueError("every assessment graph node requires one action manifest")
        return self

    def manifest_by_sha256(self) -> dict[str, ActionManifest]:
        return {manifest.fingerprint(): manifest for manifest in self.manifests}

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))
