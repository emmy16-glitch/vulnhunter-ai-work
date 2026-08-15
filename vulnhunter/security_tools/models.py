"""Typed contracts for governed security-tool operations."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import ActionClass, sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_GITHUB_WORKFLOW_SIGNER = re.compile(
    r"^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml$"
)


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


class NetworkTargetBinding(BaseModel):
    """One immutable network destination selected before execution authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scheme: Literal["http", "https"]
    hostname: str = Field(min_length=1, max_length=253)
    ip_address: str
    port: int = Field(ge=1, le=65_535)
    connect_url: str = Field(min_length=1, max_length=2048)
    host_header: str = Field(min_length=1, max_length=512)
    tls_server_name: str | None = Field(default=None, max_length=253)

    @model_validator(mode="after")
    def validate_binding(self):
        try:
            address = ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError("network binding IP address is invalid") from exc
        if address.version != 4:
            raise ValueError("first-stage OpenSandbox network binding supports IPv4 only")
        parsed = urlsplit(self.connect_url)
        if parsed.scheme != self.scheme or parsed.hostname != self.ip_address:
            raise ValueError("network binding connect URL must use the pinned IP and scheme")
        if (parsed.port or (443 if self.scheme == "https" else 80)) != self.port:
            raise ValueError("network binding connect URL port does not match the pinned port")
        if self.scheme == "http" and self.tls_server_name is not None:
            raise ValueError("HTTP network bindings must not carry a TLS server name")
        return self


class CommandPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    tool_id: str
    executable: str
    argv: tuple[str, ...] = Field(min_length=1)
    target: str | None = None
    target_kind: ToolTargetKind = ToolTargetKind.NETWORK
    runtime_image: str | None = None
    runtime_release_id: str | None = None
    runtime_sbom_sha256: str | None = None
    runtime_provenance_sha256: str | None = None
    runtime_source_commit: str | None = None
    runtime_release_registry_sha256: str | None = None
    runtime_release_key_id: str | None = None
    runtime_github_provenance_attestation_sha256: str | None = None
    runtime_github_sbom_attestation_sha256: str | None = None
    runtime_github_attestation_signer: str | None = None
    template_manifest_sha256: str | None = None
    network_binding: NetworkTargetBinding | None = None
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
        if self.target is not None and "\x00" in self.target:
            raise ValueError("command target must not contain NUL bytes")
        if self.runtime_image is not None and _IMAGE_DIGEST.fullmatch(self.runtime_image) is None:
            raise ValueError("runtime_image must be pinned by sha256 digest")
        self._validate_runtime_release_identity()
        if (
            self.template_manifest_sha256 is not None
            and _SHA256.fullmatch(self.template_manifest_sha256) is None
        ):
            raise ValueError("template_manifest_sha256 must be a SHA-256 digest")
        if self.network_binding is not None and self.target_kind != ToolTargetKind.NETWORK:
            raise ValueError("network binding is valid only for network targets")
        return self

    def _validate_runtime_release_identity(self) -> None:
        release_values = (
            self.runtime_release_id,
            self.runtime_sbom_sha256,
            self.runtime_provenance_sha256,
            self.runtime_source_commit,
            self.runtime_release_registry_sha256,
            self.runtime_release_key_id,
        )
        if any(value is not None for value in release_values):
            if self.runtime_image is None or any(value is None for value in release_values):
                raise ValueError(
                    "runtime release identity must be complete and include runtime_image"
                )
            if _IDENTIFIER.fullmatch(self.runtime_release_id or "") is None:
                raise ValueError("runtime_release_id must be a stable lowercase identifier")
            for value, label in (
                (self.runtime_sbom_sha256, "runtime_sbom_sha256"),
                (self.runtime_provenance_sha256, "runtime_provenance_sha256"),
                (self.runtime_release_registry_sha256, "runtime_release_registry_sha256"),
            ):
                if _SHA256.fullmatch(value or "") is None:
                    raise ValueError(f"{label} must be a SHA-256 digest")
            if _SOURCE_COMMIT.fullmatch(self.runtime_source_commit or "") is None:
                raise ValueError("runtime_source_commit must be a Git commit digest")
            if _KEY_ID.fullmatch(self.runtime_release_key_id or "") is None:
                raise ValueError("runtime_release_key_id must be a SHA-256 key identifier")

        attestation_values = (
            self.runtime_github_provenance_attestation_sha256,
            self.runtime_github_sbom_attestation_sha256,
            self.runtime_github_attestation_signer,
        )
        if not any(value is not None for value in attestation_values):
            return
        if not all(value is not None for value in release_values):
            raise ValueError("runtime GitHub attestations require a complete release identity")
        if any(value is None for value in attestation_values):
            raise ValueError("runtime GitHub attestation identity must be complete")
        for value, label in (
            (
                self.runtime_github_provenance_attestation_sha256,
                "runtime_github_provenance_attestation_sha256",
            ),
            (
                self.runtime_github_sbom_attestation_sha256,
                "runtime_github_sbom_attestation_sha256",
            ),
        ):
            if _SHA256.fullmatch(value or "") is None:
                raise ValueError(f"{label} must be a SHA-256 digest")
        if _GITHUB_WORKFLOW_SIGNER.fullmatch(self.runtime_github_attestation_signer or "") is None:
            raise ValueError("runtime_github_attestation_signer must identify a GitHub workflow")

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
