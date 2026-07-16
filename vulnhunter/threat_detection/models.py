"""Typed contracts for agentic-threat detection and containment."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ThreatSignalKind(StrEnum):
    REPEATED_SECRET_ACCESS = "repeated_secret_access"
    UNEXPECTED_OUTBOUND_CONNECTION = "unexpected_outbound_connection"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"
    SCOPE_EXPANSION_ATTEMPT = "scope_expansion_attempt"
    PERSISTENCE_ATTEMPT = "persistence_attempt"
    LOGGING_DISABLE_ATTEMPT = "logging_disable_attempt"
    UNAPPROVED_TOOL_DOWNLOAD = "unapproved_tool_download"
    EXCESSIVE_ACTION_CHAIN = "excessive_action_chain"
    REPEATED_AFTER_DENIAL = "repeated_after_denial"
    UNTRUSTED_INSTRUCTION_FOLLOWING = "untrusted_instruction_following"


class ThreatRisk(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContainmentDecision(StrEnum):
    CONTINUE = "continue"
    RESTRICT = "restrict"
    PAUSE = "pause"
    KILL = "kill"


class AgentActionEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    execution_id: str
    actor_id: str
    action: str
    target: str | None = None
    outcome: str = "proposed"
    source_trust: str = "trusted"
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("event_id", "execution_id", "actor_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value


class ThreatSignal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ThreatSignalKind
    risk: ThreatRisk
    reason: str = Field(min_length=8, max_length=500)
    event_ids: tuple[str, ...] = Field(min_length=1)


class ThreatPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    outbound_allowlist: tuple[str, ...] = ()
    maximum_action_chain: int = Field(default=20, ge=1, le=10_000)
    secret_access_threshold: int = Field(default=2, ge=1, le=100)
    denial_retry_threshold: int = Field(default=2, ge=1, le=100)
    kill_on_critical: bool = True
    pause_on_high: bool = True


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    signals: tuple[ThreatSignal, ...]
    highest_risk: ThreatRisk
    decision: ContainmentDecision
    notify_human: bool
    assessed_at: datetime = Field(default_factory=utc_now)

    @field_validator("execution_id")
    @classmethod
    def validate_execution(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("execution_id must be a stable lowercase value")
        return value
