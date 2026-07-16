"""AI routing records that keep model output untrusted."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PrivacyClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CUSTOMER_PRIVATE = "customer_private"
    SECRET = "secret"
    UNKNOWN = "unknown"


class AiRoute(StrEnum):
    DETERMINISTIC = "deterministic"
    LOCAL_QWEN_SMALL = "local_qwen_small"
    LOCAL_QWEN_STRONG = "local_qwen_strong"
    GROQ_QWEN = "groq_qwen"
    GROQ_COMPOUND_MINI = "groq_compound_mini"
    HUMAN_ESCALATION = "human_escalation"
    DENIED = "denied"


class RoutingRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    task_type: str
    input_sha256: str
    privacy_class: PrivacyClass
    deterministic_sufficient: bool
    public_freshness_required: bool = False
    non_sensitive_reasoning_approved: bool = False
    escalation_reason: str | None = None
    attempt: int = Field(default=1, ge=1, le=5)
    route_history: tuple[AiRoute, ...] = ()

    @field_validator("task_id", "task_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("input_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("input_sha256 must be a SHA-256 digest")
        return value


class AiRouteDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    route: AiRoute
    provider: str
    model_role: str
    reason: str
    input_sha256: str
    privacy_class: PrivacyClass
    deterministic_alternatives: tuple[str, ...]
    output_trusted: bool = False
    stop_condition: str
