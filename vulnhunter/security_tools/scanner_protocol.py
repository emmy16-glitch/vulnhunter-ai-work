"""Versioned contracts for scanner-manager and isolated-worker boundaries.

The models in this module contain no shell command, arbitrary argv, process
environment, or secret value.  They are safe control-plane contracts shared by
Nuclei, future OpenVAS integration, and future mobile-analysis workers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

SCANNER_PROTOCOL_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


def _identifier(value: str) -> str:
    normalized = value.strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError("identifier must be a stable lowercase value")
    return normalized


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _sha256(value: str, *, field: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a SHA-256 digest")
    return value


class ScannerKind(StrEnum):
    NUCLEI = "nuclei"
    OPENVAS = "openvas"
    MOBILE_ANALYSIS = "mobile_analysis"


class ScannerAdapterStatus(StrEnum):
    HARNESS_ONLY = "harness_only"
    PLANNED = "planned"
    UNAVAILABLE = "unavailable"


class ScannerDeploymentMode(StrEnum):
    DISABLED = "disabled"
    ISOLATED_CONTAINER = "isolated_container"
    DISPOSABLE_MACHINE = "disposable_machine"


class ScannerJobState(StrEnum):
    PREPARED = "prepared"
    VALIDATED = "validated"
    BLOCKED_EXECUTION_DISABLED = "blocked_execution_disabled"
    STARTING = "starting"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    COMPLETED = "completed"


TERMINAL_SCANNER_STATES = frozenset(
    {
        ScannerJobState.BLOCKED_EXECUTION_DISABLED,
        ScannerJobState.CANCELLED,
        ScannerJobState.TIMED_OUT,
        ScannerJobState.FAILED,
        ScannerJobState.COMPLETED,
    }
)


class ScannerFeedPin(BaseModel):
    """Reviewed feed or template-set identity used by a scanner adapter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    feed_id: str
    release: str | None = None
    manifest_path: str | None = None
    manifest_sha256: str | None = None

    @field_validator("feed_id")
    @classmethod
    def validate_feed_id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("release")
    @classmethod
    def validate_release(cls, value: str | None) -> str | None:
        if value is not None and _VERSION.fullmatch(value) is None:
            raise ValueError("feed release is malformed")
        return value

    @field_validator("manifest_path")
    @classmethod
    def validate_manifest_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
            raise ValueError("feed manifest path must be a safe repository-relative path")
        return candidate.as_posix()

    @field_validator("manifest_sha256")
    @classmethod
    def validate_manifest_sha256(cls, value: str | None) -> str | None:
        return None if value is None else _sha256(value, field="manifest_sha256")

    @model_validator(mode="after")
    def validate_manifest_pair(self):
        if (self.manifest_path is None) != (self.manifest_sha256 is None):
            raise ValueError("manifest_path and manifest_sha256 must be supplied together")
        return self


class ScannerVersionPin(BaseModel):
    """Central scanner, adapter, protocol, and feed compatibility record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scanner_id: str
    adapter_id: str
    adapter_version: str
    engine_version: str | None = None
    protocol_version: Literal[SCANNER_PROTOCOL_VERSION] = SCANNER_PROTOCOL_VERSION
    feed: ScannerFeedPin | None = None

    @field_validator("scanner_id", "adapter_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("adapter_version", "engine_version")
    @classmethod
    def validate_versions(cls, value: str | None) -> str | None:
        if value is not None and _VERSION.fullmatch(value) is None:
            raise ValueError("version value is malformed")
        return value


class ScannerAdapterDescriptor(BaseModel):
    """Capabilities exposed to the manager without exposing implementation details."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter_id: str
    scanner_kind: ScannerKind
    status: ScannerAdapterStatus
    deployment_mode: ScannerDeploymentMode
    supported_profiles: tuple[str, ...] = ()
    protocol_version: Literal[SCANNER_PROTOCOL_VERSION] = SCANNER_PROTOCOL_VERSION
    execution_enabled: Literal[False] = False

    @field_validator("adapter_id")
    @classmethod
    def validate_adapter_id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("supported_profiles")
    @classmethod
    def validate_profiles(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_identifier(value) for value in values}))


class ScannerCompatibilityRecord(BaseModel):
    """One adapter's compatibility and deployment policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    descriptor: ScannerAdapterDescriptor
    version_pin: ScannerVersionPin
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_binding(self):
        if self.descriptor.adapter_id != self.version_pin.adapter_id:
            raise ValueError("adapter descriptor and version pin do not match")
        if self.descriptor.scanner_kind.value != self.version_pin.scanner_id:
            raise ValueError("scanner kind and version pin do not match")
        return self


class ScannerCompatibilityManifest(BaseModel):
    """Versioned central registry for scanner adapters, feeds, and deployment modes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[SCANNER_PROTOCOL_VERSION] = SCANNER_PROTOCOL_VERSION
    records: tuple[ScannerCompatibilityRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_records(self):
        adapter_ids = [record.descriptor.adapter_id for record in self.records]
        scanner_ids = [record.version_pin.scanner_id for record in self.records]
        if len(adapter_ids) != len(set(adapter_ids)):
            raise ValueError("scanner adapter IDs must be unique")
        if len(scanner_ids) != len(set(scanner_ids)):
            raise ValueError("scanner IDs must be unique")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    def get(self, scanner_id: str) -> ScannerCompatibilityRecord:
        normalized = _identifier(scanner_id)
        for record in self.records:
            if record.version_pin.scanner_id == normalized:
                return record
        raise KeyError(f"unknown scanner compatibility record: {normalized}")

    def verify_repository_manifests(self, repository_root: Path) -> None:
        root = repository_root.expanduser().resolve(strict=True)
        for record in self.records:
            feed = record.version_pin.feed
            if feed is None or feed.manifest_path is None or feed.manifest_sha256 is None:
                continue
            candidate = root / feed.manifest_path
            if candidate.is_symlink():
                raise ValueError("scanner feed manifest must not be a symbolic link")
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError("scanner feed manifest escapes the repository") from exc
            if not resolved.is_file():
                raise ValueError("scanner feed manifest is not a regular file")
            actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if actual != feed.manifest_sha256:
                raise ValueError(
                    f"scanner feed manifest digest mismatch for {record.version_pin.scanner_id}"
                )

    @classmethod
    def load(cls, path: Path) -> ScannerCompatibilityManifest:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class ScannerExecutionLimits(BaseModel):
    """Shared bounded limits accepted by all scanner adapters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_seconds: int = Field(ge=1, le=3_600)
    maximum_stdout_bytes: int = Field(ge=1_024, le=2_000_000)
    maximum_stderr_bytes: int = Field(ge=1_024, le=2_000_000)
    concurrency: int = Field(ge=1, le=2)
    rate_limit: int = Field(ge=1, le=10)
    termination_grace_seconds: float = Field(default=2.0, ge=0, le=10)


class ScannerCandidateObservation(BaseModel):
    """Unverified scanner output; its trust state is permanently candidate here."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str
    scanner_id: str
    target_reference: str
    title: str = Field(min_length=3, max_length=500)
    severity: str = Field(min_length=2, max_length=32)
    confidence: str = Field(min_length=2, max_length=32)
    finding_status: Literal["candidate"] = "candidate"
    metadata: Mapping[str, object] = Field(default_factory=dict)

    @field_validator("observation_id", "scanner_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _identifier(value)


class ScannerEvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0, le=4_000_000)
    media_type: str = Field(min_length=3, max_length=100)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("evidence reference must be a safe relative path")
        return path.as_posix()

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _sha256(value, field="sha256")


class ScannerAdapterResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    state: ScannerJobState
    observations: tuple[ScannerCandidateObservation, ...] = ()
    evidence: tuple[ScannerEvidenceReference, ...] = ()
    reason: str

    @field_validator("execution_id")
    @classmethod
    def validate_execution_id(cls, value: str) -> str:
        return _identifier(value)

    @model_validator(mode="after")
    def validate_terminal_result(self):
        if self.state not in TERMINAL_SCANNER_STATES:
            raise ValueError("scanner adapter results must use a terminal state")
        return self


@runtime_checkable
class ScannerAdapter(Protocol):
    """Formal scanner-control interface implemented outside the web process."""

    @property
    def descriptor(self) -> ScannerAdapterDescriptor: ...

    def submit(self, request: object) -> ScannerAdapterResult: ...


class ScannerAdapterRegistry:
    """Manager-side registry for independent adapters sharing one protocol."""

    def __init__(self, adapters: Iterable[ScannerAdapter] = ()) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ScannerAdapter) -> None:
        adapter_id = adapter.descriptor.adapter_id
        if adapter_id in self._adapters:
            raise ValueError(f"duplicate scanner adapter: {adapter_id}")
        if adapter.descriptor.protocol_version != SCANNER_PROTOCOL_VERSION:
            raise ValueError("scanner adapter protocol version is incompatible")
        self._adapters[adapter_id] = adapter

    def get(self, adapter_id: str) -> ScannerAdapter:
        normalized = _identifier(adapter_id)
        try:
            return self._adapters[normalized]
        except KeyError as exc:
            raise KeyError(f"unknown scanner adapter: {normalized}") from exc

    def descriptors(self) -> tuple[ScannerAdapterDescriptor, ...]:
        return tuple(
            sorted(
                (adapter.descriptor for adapter in self._adapters.values()),
                key=lambda descriptor: descriptor.adapter_id,
            )
        )


class PlannedScannerAdapter:
    """Typed placeholder for adapters that have not passed activation review."""

    def __init__(self, descriptor: ScannerAdapterDescriptor) -> None:
        if descriptor.status not in {
            ScannerAdapterStatus.PLANNED,
            ScannerAdapterStatus.UNAVAILABLE,
        }:
            raise ValueError("planned adapter requires a planned or unavailable descriptor")
        self._descriptor = descriptor

    @property
    def descriptor(self) -> ScannerAdapterDescriptor:
        return self._descriptor

    def submit(self, request: object) -> ScannerAdapterResult:
        execution_id = getattr(request, "execution_id", "blocked-request")
        return ScannerAdapterResult(
            execution_id=execution_id,
            state=ScannerJobState.BLOCKED_EXECUTION_DISABLED,
            reason=f"{self.descriptor.scanner_kind.value} adapter is not activated",
        )


def render_compatibility_matrix(manifest: ScannerCompatibilityManifest) -> str:
    """Render a small Markdown compatibility table for release documentation."""
    rows = [
        "| Scanner | Adapter | Adapter version | Engine | Feed | Status | Deployment |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for record in sorted(manifest.records, key=lambda item: item.version_pin.scanner_id):
        pin = record.version_pin
        feed = pin.feed
        rows.append(
            "| "
            + " | ".join(
                (
                    pin.scanner_id,
                    pin.adapter_id,
                    pin.adapter_version,
                    pin.engine_version or "not selected",
                    (feed.release if feed and feed.release else "not selected"),
                    record.descriptor.status.value,
                    record.descriptor.deployment_mode.value,
                )
            )
            + " |"
        )
    return "\n".join(rows) + "\n"


def dump_compatibility_json(manifest: ScannerCompatibilityManifest) -> str:
    """Deterministic JSON representation used by release tooling and tests."""
    return json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
