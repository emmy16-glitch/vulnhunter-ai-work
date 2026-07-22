"""Typed contracts for the restricted remote Nuclei worker boundary."""

from __future__ import annotations

import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.nuclei_execution import NucleiExecutionError

REMOTE_NUCLEI_PROTOCOL_VERSION = "1.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,254}$")
_SAFE_USER = re.compile(r"^[a-z_][a-z0-9._-]{0,31}$")


class RemoteNucleiWorkerError(NucleiExecutionError):
    """Raised when the remote worker boundary cannot be verified."""


def _digest(value: str, *, field: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a SHA-256 digest")
    return value


def _absolute(value: Path) -> Path:
    expanded = value.expanduser()
    if not expanded.is_absolute():
        raise ValueError("remote worker paths must be absolute")
    return expanded


def _fixed_http_url(value: str, *, field: str, loopback: bool) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"{field} must be an origin URL without a path, query, or fragment")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(f"{field} contains unsupported URL components")
    host = parsed.hostname
    if loopback and host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("transport_target must remain loopback-only on the remote host")
    if not loopback and host in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("logical_target must identify the approved private laboratory target")
    return value.rstrip("/")


class RemoteNucleiWorkerPolicy(BaseModel):
    """Guest-side SSH policy loaded only from an owner-controlled local file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[REMOTE_NUCLEI_PROTOCOL_VERSION] = REMOTE_NUCLEI_PROTOCOL_VERSION
    enabled: bool = False
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    ssh_executable: Path = Path("/usr/bin/ssh")
    remote_user: str = ""
    remote_host: str = ""
    remote_port: int = Field(default=22, ge=1, le=65_535)
    identity_file: Path
    known_hosts_file: Path
    logical_target: str = ""
    transport_target: str = ""
    engine_version: str = ""
    template_manifest_hash: str = "0" * 64
    template_sha256: str = "0" * 64
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    maximum_response_bytes: int = Field(default=131_072, ge=4_096, le=1_000_000)
    maximum_candidates: int = Field(default=250, ge=1, le=1_000)
    poll_interval_seconds: float = Field(default=0.1, ge=0.02, le=1.0)

    @field_validator("ssh_executable", "identity_file", "known_hosts_file")
    @classmethod
    def validate_paths(cls, value: Path) -> Path:
        return _absolute(value)

    @field_validator("template_manifest_hash", "template_sha256")
    @classmethod
    def validate_digests(cls, value: str, info) -> str:
        if value == "0" * 64:
            return value
        return _digest(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_enabled_policy(self) -> Self:
        if not self.enabled:
            return self
        if _SAFE_USER.fullmatch(self.remote_user) is None:
            raise ValueError("remote_user is malformed")
        if _SAFE_HOST.fullmatch(self.remote_host) is None:
            raise ValueError("remote_host is malformed")
        if not self.engine_version.strip():
            raise ValueError("engine_version is required when the remote worker is enabled")
        _fixed_http_url(self.logical_target, field="logical_target", loopback=False)
        _fixed_http_url(self.transport_target, field="transport_target", loopback=True)
        _digest(self.template_manifest_hash, field="template_manifest_hash")
        _digest(self.template_sha256, field="template_sha256")
        return self

    @classmethod
    def from_path(cls, path: Path) -> Self:
        expanded = _absolute(path)
        if expanded.is_symlink():
            raise RemoteNucleiWorkerError("remote worker policy must not be a symbolic link")
        try:
            metadata = expanded.stat()
            raw = expanded.read_text(encoding="utf-8")
        except OSError as exc:
            raise RemoteNucleiWorkerError("remote worker policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise RemoteNucleiWorkerError("remote worker policy must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RemoteNucleiWorkerError(
                "remote worker policy must not be group or world writable"
            )
        try:
            policy = cls.model_validate_json(raw)
        except ValueError as exc:
            raise RemoteNucleiWorkerError("remote worker policy is invalid") from exc
        if policy.enabled:
            policy.validate_runtime_files()
        return policy

    def validate_runtime_files(self) -> None:
        if not self.enabled:
            raise RemoteNucleiWorkerError("remote Nuclei worker is disabled")
        for path, label, executable in (
            (self.ssh_executable, "SSH executable", True),
            (self.identity_file, "SSH identity", False),
            (self.known_hosts_file, "known-hosts file", False),
        ):
            if path.is_symlink():
                raise RemoteNucleiWorkerError(f"{label} must not be a symbolic link")
            try:
                metadata = path.stat()
            except OSError as exc:
                raise RemoteNucleiWorkerError(f"{label} is unavailable") from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise RemoteNucleiWorkerError(f"{label} must be a regular file")
            if executable and not os.access(path, os.X_OK):
                raise RemoteNucleiWorkerError(f"{label} is not executable")
        if stat.S_IMODE(self.identity_file.stat().st_mode) & 0o077:
            raise RemoteNucleiWorkerError("SSH identity must not be accessible by group or others")
        if self.known_hosts_file.stat().st_size < 1:
            raise RemoteNucleiWorkerError("known-hosts file is empty")


class RemoteNucleiRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[REMOTE_NUCLEI_PROTOCOL_VERSION] = REMOTE_NUCLEI_PROTOCOL_VERSION
    operation: Literal["readiness", "scan"]
    request_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    logical_target: str
    transport_target: str
    engine_version: str
    template_sha256: str
    timeout_seconds: int = Field(ge=1, le=300)
    maximum_candidates: int = Field(ge=0, le=1_000)
    issued_at: datetime
    request_digest: str

    @field_validator("template_sha256", "request_digest")
    @classmethod
    def validate_digest(cls, value: str, info) -> str:
        return _digest(value, field=info.field_name)

    @field_validator("issued_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_request_digest(self) -> Self:
        if self.request_digest != self.expected_digest():
            raise ValueError("remote request digest mismatch")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"request_digest"})

    def expected_digest(self) -> str:
        return sha256_json(self.unsigned_payload())

    @classmethod
    def create(cls, **values: object) -> Self:
        temporary = cls.model_construct(**values, request_digest="0" * 64)
        return cls(**values, request_digest=sha256_json(temporary.unsigned_payload()))


class RemoteNucleiCandidate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str = Field(
        min_length=2,
        max_length=127,
        pattern=r"^[a-z0-9][a-z0-9._-]+$",
    )
    title: str = Field(min_length=3, max_length=500)
    severity: str = Field(min_length=2, max_length=32)
    matcher_name: str = Field(default="", max_length=200)
    protocol: str = Field(default="http", min_length=2, max_length=50)


class RemoteNucleiResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[REMOTE_NUCLEI_PROTOCOL_VERSION] = REMOTE_NUCLEI_PROTOCOL_VERSION
    operation: Literal["readiness", "scan"]
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    request_digest: str
    execution_state: Literal["ready", "completed", "failed", "timed_out", "cancelled"]
    reason: str = Field(min_length=3, max_length=500)
    engine_version: str
    template_sha256: str
    candidate_count: int = Field(ge=0, le=1_000)
    candidates: tuple[RemoteNucleiCandidate, ...] = ()
    http_status: int | None = Field(default=None, ge=100, le=599)
    completed_at: datetime
    result_digest: str

    @field_validator("request_digest", "template_sha256", "result_digest")
    @classmethod
    def validate_digests(cls, value: str, info) -> str:
        return _digest(value, field=info.field_name)

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("completed_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.candidate_count != len(self.candidates):
            raise ValueError("candidate_count does not match candidates")
        if self.operation == "readiness" and self.execution_state != "ready":
            raise ValueError("readiness response must use the ready state")
        if self.result_digest != self.expected_digest():
            raise ValueError("remote result digest mismatch")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"result_digest"})

    def expected_digest(self) -> str:
        return sha256_json(self.unsigned_payload())
