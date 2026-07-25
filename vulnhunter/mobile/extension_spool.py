"""Signed atomic queue for separately approved MobSF and Android runtime jobs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
ExtensionKind = Literal["mobsf", "runtime"]


class MobileExtensionSpoolError(RuntimeError):
    """Raised when an extension job cannot preserve its queue boundary."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("extension timestamps must be timezone-aware")
    return value.astimezone(UTC)


class SignedMobileExtensionJob(BaseModel):
    """One exact, expiring and attributable extension execution request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    kind: ExtensionKind
    artifact_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by: str = Field(min_length=2, max_length=128)
    approval_reason: str = Field(min_length=8, max_length=500)
    package_name: str | None = None
    runtime_approval: dict[str, object] | None = None
    created_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("job_id", "artifact_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("extension identifier is invalid")
        return value

    @field_validator("package_name")
    @classmethod
    def validate_package(cls, value: str | None) -> str | None:
        if value is not None and _PACKAGE.fullmatch(value) is None:
            raise ValueError("extension package name is invalid")
        return value

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("extension job must expire after creation")
        if self.kind == "runtime" and (self.package_name is None or self.runtime_approval is None):
            raise ValueError("runtime job requires a package and signed runtime approval")
        if self.kind == "mobsf" and self.runtime_approval is not None:
            raise ValueError("MobSF job must not contain a runtime approval")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def expected_signature(self, key: bytes) -> str:
        encoded = json.dumps(
            self.unsigned_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, encoded, hashlib.sha256).hexdigest()

    def verify(self, key: bytes, *, now: datetime) -> None:
        current = _utc(now)
        if current < self.created_at or current >= self.expires_at:
            raise MobileExtensionSpoolError("extension job is not active")
        if not hmac.compare_digest(self.signature, self.expected_signature(key)):
            raise MobileExtensionSpoolError("extension job signature is invalid")

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        kind: ExtensionKind,
        artifact_id: str,
        artifact_sha256: str,
        plan_sha256: str,
        requested_by: str,
        approval_reason: str,
        package_name: str | None,
        runtime_approval: dict[str, object] | None,
        created_at: datetime,
        expires_at: datetime,
        key: bytes,
    ) -> Self:
        provisional = cls.model_construct(
            schema_version="1.0",
            job_id=job_id,
            kind=kind,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            plan_sha256=plan_sha256,
            requested_by=requested_by,
            approval_reason=approval_reason,
            package_name=package_name,
            runtime_approval=runtime_approval,
            created_at=_utc(created_at),
            expires_at=_utc(expires_at),
            signature="0" * 64,
        )
        return cls(
            **provisional.model_dump(exclude={"signature"}),
            signature=provisional.expected_signature(key),
        )


class MobileExtensionReceipt(BaseModel):
    """Bounded terminal receipt; detailed evidence remains owner-private."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    kind: ExtensionKind
    artifact_id: str
    state: Literal["completed", "failed", "rejected"]
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)
    evidence: dict[str, object] = Field(default_factory=dict)

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _utc(value)


class MobileExtensionSpool:
    """Atomic pending/processing/completed/failed queue for extension jobs."""

    def __init__(self, root: Path) -> None:
        lexical = root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise MobileExtensionSpoolError("extension spool root must not be a symbolic link")
        self.root = lexical.resolve(strict=True)
        self.pending = self._directory("pending")
        self.processing = self._directory("processing")
        self.completed = self._directory("completed")
        self.failed = self._directory("failed")

    def _directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise MobileExtensionSpoolError("extension spool directory is unsafe")
        return path

    @staticmethod
    def _filename(job_id: str) -> str:
        if _IDENTIFIER.fullmatch(job_id) is None:
            raise MobileExtensionSpoolError("extension job identifier is invalid")
        return f"{job_id}.json"

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        if path.exists() or path.is_symlink():
            raise MobileExtensionSpoolError("extension spool path already exists")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    def enqueue(self, job: SignedMobileExtensionJob) -> Path:
        filename = self._filename(job.job_id)
        for directory in (self.pending, self.processing, self.completed, self.failed):
            if (directory / filename).exists():
                raise MobileExtensionSpoolError("extension job identifier was already used")
        path = self.pending / filename
        self._write_exclusive(path, job.model_dump_json(indent=2) + "\n")
        return path

    def claim_next(self) -> Path | None:
        for source in sorted(self.pending.glob("*.json")):
            if source.is_symlink() or not source.is_file():
                raise MobileExtensionSpoolError("pending extension job is unsafe")
            destination = self.processing / source.name
            try:
                os.replace(source, destination)
            except FileNotFoundError:
                continue
            return destination
        return None

    def load_claimed(
        self,
        path: Path,
        *,
        key: bytes,
        now: datetime,
    ) -> SignedMobileExtensionJob:
        if path.parent != self.processing or path.is_symlink() or not path.is_file():
            raise MobileExtensionSpoolError("claimed extension job path is unsafe")
        try:
            job = SignedMobileExtensionJob.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MobileExtensionSpoolError("claimed extension job is invalid") from exc
        job.verify(key, now=now)
        if path.name != self._filename(job.job_id):
            raise MobileExtensionSpoolError("extension job filename does not match payload")
        return job

    def finish(
        self,
        claimed: Path,
        *,
        receipt: MobileExtensionReceipt,
        success: bool,
    ) -> Path:
        if claimed.parent != self.processing or claimed.is_symlink() or not claimed.is_file():
            raise MobileExtensionSpoolError("claimed extension job path is unsafe")
        if claimed.name != self._filename(receipt.job_id):
            raise MobileExtensionSpoolError("extension receipt does not match claimed job")
        target_root = self.completed if success else self.failed
        target = target_root / claimed.name
        self._write_exclusive(target, receipt.model_dump_json(indent=2) + "\n")
        claimed.unlink(missing_ok=True)
        return target

    def reject(self, claimed: Path, *, reason: str, now: datetime) -> Path:
        if claimed.parent != self.processing or claimed.is_symlink() or not claimed.is_file():
            raise MobileExtensionSpoolError("claimed extension job path is unsafe")
        try:
            raw = json.loads(claimed.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        raw_job_id = str(raw.get("job_id") or claimed.stem)
        if _IDENTIFIER.fullmatch(raw_job_id) is None:
            identity = hashlib.sha256(claimed.name.encode()).hexdigest()[:20]
            job_id = f"rejected-{identity}"
        else:
            job_id = raw_job_id
        raw_kind = str(raw.get("kind") or "")
        kind: ExtensionKind = raw_kind if raw_kind in {"mobsf", "runtime"} else "mobsf"
        raw_artifact_id = str(raw.get("artifact_id") or "")
        artifact_id = (
            raw_artifact_id
            if _IDENTIFIER.fullmatch(raw_artifact_id) is not None
            else "unknown-artifact"
        )
        safe_reason = " ".join(reason.split())[:500]
        if len(safe_reason) < 3:
            safe_reason = "Extension job was rejected."
        unsigned = {
            "job_id": job_id,
            "kind": kind,
            "artifact_id": artifact_id,
            "state": "rejected",
            "completed_at": _utc(now).isoformat(),
            "reason": safe_reason,
            "evidence": {},
        }
        receipt = MobileExtensionReceipt(
            **unsigned,
            result_sha256=hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        target = self.failed / self._filename(job_id)
        self._write_exclusive(target, receipt.model_dump_json(indent=2) + "\n")
        claimed.unlink(missing_ok=True)
        return target

    def recover_processing(self, *, now: datetime) -> None:
        for claimed in sorted(self.processing.glob("*.json")):
            self.reject(
                claimed,
                reason="Extension worker restarted while this job was processing.",
                now=now,
            )

    def status(self, job_id: str) -> dict[str, object] | None:
        filename = self._filename(job_id)
        locations = (
            (self.pending, "queued"),
            (self.processing, "running"),
            (self.completed, "completed"),
            (self.failed, "failed"),
        )
        for directory, state in locations:
            path = directory / filename
            if not path.is_file() or path.is_symlink():
                continue
            if state in {"queued", "running"}:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return {"job_id": job_id, "state": "failed"}
                return {
                    "job_id": job_id,
                    "kind": payload.get("kind"),
                    "state": state,
                    "created_at": payload.get("created_at"),
                }
            try:
                receipt = MobileExtensionReceipt.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                return {"job_id": job_id, "state": "failed"}
            return receipt.model_dump(mode="json")
        return None


__all__ = [
    "ExtensionKind",
    "MobileExtensionReceipt",
    "MobileExtensionSpool",
    "MobileExtensionSpoolError",
    "SignedMobileExtensionJob",
]
