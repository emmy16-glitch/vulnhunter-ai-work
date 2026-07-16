"""Profiles and requests for deep, multi-stage authorised assessments."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class AssessmentProfile(StrEnum):
    DEEP_DISCOVERY = "deep_discovery"
    ACTIVE_ASSESSMENT = "active_assessment"
    EXPLOITABILITY_VALIDATION = "exploitability_validation"
    PRIVILEGED_ENVIRONMENT = "privileged_environment"
    ATTACK_PATH_SIMULATION = "attack_path_simulation"
    REMEDIATION_RETEST = "remediation_retest"


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment_id: str
    campaign_id: str
    run_id: str
    requested_by: str
    profile: AssessmentProfile
    target_references: tuple[str, ...] = Field(min_length=1)
    authorization_references: tuple[str, ...] = Field(min_length=1)
    maximum_requests: int = Field(default=500, ge=1, le=1_000_000)
    timeout_seconds: int = Field(default=1800, ge=1, le=86_400)
    permit_privileged_broker: bool = False

    @field_validator("assessment_id", "campaign_id", "run_id", "requested_by")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value
