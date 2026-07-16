"""Typed contracts for governed security-tool operations."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import ActionClass, sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ToolProfile(StrEnum):
    DISCOVERY = "discovery"
    SAFE_ASSESSMENT = "safe_assessment"
    ACTIVE_ASSESSMENT = "active_assessment"
    VALIDATION = "validation"
    PRIVILEGED_INSPECTION = "privileged_inspection"
    RETEST = "retest"
    MOBILE_STATIC = "mobile_static"
    MOBILE_NATIVE = "mobile_native"
    MOBILE_DYNAMIC = "mobile_dynamic"
    MOBILE_RETEST = "mobile_retest"


class ToolTargetKind(StrEnum):
    NETWORK = "network"
    LOCAL_PATH = "local_path"
    BINARY_FILE = "binary_file"
    APK_FILE = "apk_file"
    ANDROID_DEVICE = "android_device"
    CONTAINER_IMAGE = "container_image"
    FINDING_REFERENCE = "finding_reference"


class SecurityToolDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str
    display_name: str
    executable_candidates: tuple[str, ...] = Field(min_length=1)
    profiles: tuple[ToolProfile, ...] = Field(min_length=1)
    target_kinds: tuple[ToolTargetKind, ...] = Field(min_length=1)
    action_class: ActionClass
    acceptable_return_codes: tuple[int, ...] = (0,)
    approval_required: bool
    privileged: bool = False
    connector_only: bool = False
    requires_isolation: bool = False
    output_formats: tuple[str, ...] = ()
    description: str = Field(min_length=8)
    homepage: str | None = None

    @field_validator("tool_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("tool_id must be a stable lowercase identifier")
        return value


class ToolAvailabilityStatus(StrEnum):
    NOT_DETECTED = "not_detected"
    READY = "ready"
    DETECTED_UNVERIFIED = "detected_unverified"
    UNUSABLE = "unusable"
    TIMED_OUT = "timed_out"


class ToolAvailability(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str
    available: bool
    usable: bool = False
    status: ToolAvailabilityStatus = ToolAvailabilityStatus.NOT_DETECTED
    executable_path: str | None = None
    version_summary: str | None = None
    return_code: int | None = None
    error_summary: str | None = None
    checked_at: datetime = Field(default_factory=utc_now)


class SecurityToolRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    action_manifest_sha256: str
    tool_id: str
    profile: ToolProfile
    operation: str
    target: str
    target_kind: ToolTargetKind = ToolTargetKind.NETWORK
    timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    maximum_output_bytes: int = Field(default=2_000_000, ge=1_024, le=100_000_000)
    output_directory: Path
    parameters: dict[str, object] = Field(default_factory=dict)

    @field_validator("request_id", "tool_id", "operation")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("action_manifest_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("action_manifest_sha256 must be a SHA-256 digest")
        return value


class CommandPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    tool_id: str
    executable: str
    argv: tuple[str, ...] = Field(min_length=1)
    output_files: tuple[Path, ...] = ()
    stdout_file: Path | None = None
    stderr_file: Path | None = None
    timeout_seconds: int
    maximum_output_bytes: int
    working_directory: Path
    action_manifest_sha256: str
    requires_approval: bool
    requires_isolation: bool = False
    action_class: ActionClass
    acceptable_return_codes: tuple[int, ...] = (0,)

    @model_validator(mode="after")
    def validate_command(self):
        if self.argv[0] != self.executable:
            raise ValueError("argv must begin with the selected executable")
        if any("\x00" in part for part in self.argv):
            raise ValueError("command arguments must not contain NUL bytes")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ToolExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    request_id: str
    tool_id: str
    command_plan_sha256: str
    started_at: datetime
    finished_at: datetime
    return_code: int
    timed_out: bool
    stdout_preview: str
    stderr_preview: str
    output_files: tuple[str, ...]
    evidence_sha256: str
    success: bool
