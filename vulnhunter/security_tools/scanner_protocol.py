"""Versioned contracts for scanner-manager and isolated-worker boundaries.

The models in this module contain no shell command, arbitrary argv, process
environment, or secret value. They are safe control-plane contracts shared by
Nuclei and mobile-analysis workers.
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
    MOBILE_ANALYSIS = "mobile_analysis"


class ScannerAdapterStatus(StrEnum):
    HARNESS_ONLY = "harness_only"
    PILOT_READY = "pilot_ready"
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
    execution_enabled: bool = False

    @field_validator("adapter_id")
    @classmethod
    def validate_adapter_id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("supported_profiles")
    @classmethod
    def validate_profiles(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_identifier(value) for value in values}))


class ScannerCandidateObservation(BaseModel):
    """Scanner output that can never claim verification or publication."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str
    title: str = Field(min_length=3, max_length=500)
    severity: str = Field(min_length=2, max_length=32)
    confidence: str = Field(min_length=2, max_length=32)
    target_reference: str = Field(min_length=1, max_length=2_000)
    template_id: str | None = None
    metadata: Mapping[str, object] = Field(default_factory=dict)
    finding_status: Literal["candidate"] = "candidate"

    @field_validator("observation_id", "template_id")
    @classmethod
    def validate_ids(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value)


class ScannerEvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=3, max_length=100)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("evidence path must be safe and relative")
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
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("execution_id")
    @classmethod
    def validate_execution_id(cls, value: str) -> str:
        return _identifier(value)


@runtime_checkable
class ScannerAdapter(Protocol):
    @property
    def descriptor(self) -> ScannerAdapterDescriptor: ...

    def submit(self, request: object) -> ScannerAdapterResult: ...


class ScannerCompatibilityRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    descriptor: ScannerAdapterDescriptor
    version_pin: ScannerVersionPin
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_identity(self):
        if self.descriptor.adapter_id != self.version_pin.adapter_id:
            raise ValueError("adapter descriptor and version pin differ")
        if self.descriptor.scanner_kind.value != self.version_pin.scanner_id:
            raise ValueError("scanner descriptor and version pin differ")
        return self


class ScannerCompatibilityManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[SCANNER_PROTOCOL_VERSION] = SCANNER_PROTOCOL_VERSION
    records: tuple[ScannerCompatibilityRecord, ...]

    @model_validator(mode="after")
    def validate_unique_records(self):
        scanner_ids = [item.version_pin.scanner_id for item in self.records]
        adapter_ids = [item.version_pin.adapter_id for item in self.records]
        if len(scanner_ids) != len(set(scanner_ids)) or len(adapter_ids) != len(set(adapter_ids)):
            raise ValueError("scanner compatibility identities must be unique")
        return self

    def get(self, scanner_id: str) -> ScannerCompatibilityRecord:
        normalized = _identifier(scanner_id)
        for record in self.records:
            if record.version_pin.scanner_id == normalized:
                return record
        raise KeyError(scanner_id)

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def from_path(cls, path: Path) -> ScannerCompatibilityManifest:
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = cls.model_validate(payload)
        manifest.validate_repository_manifests(path.parent.parent.parent)
        return manifest

    def validate_repository_manifests(self, repository_root: Path) -> None:
        for record in self.records:
            feed = record.version_pin.feed
            if feed is None or feed.manifest_path is None:
                continue
            path = repository_root / feed.manifest_path
            if not path.is_file() or path.is_symlink():
                raise ValueError("scanner feed manifest is missing or unsafe")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != feed.manifest_sha256:
                raise ValueError("scanner feed manifest digest does not match compatibility pin")


def redact_mapping(value: Mapping[str, object]) -> dict[str, object]:
    """Return bounded primitive metadata without secret-shaped values."""

    safe: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)[:100]
        if isinstance(raw_value, (str, int, float, bool)) or raw_value is None:
            safe[key] = raw_value
        elif isinstance(raw_value, Iterable) and not isinstance(raw_value, (str, bytes, Mapping)):
            safe[key] = [str(item)[:500] for item in list(raw_value)[:50]]
        else:
            safe[key] = str(raw_value)[:500]
    return safe
