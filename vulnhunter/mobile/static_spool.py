"""Signed, atomic spool for networkless Android static-analysis jobs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.static_worker import MobileStaticAnalysisResult


class MobileStaticSpoolError(RuntimeError):
    """Raised when a mobile job cannot preserve its queue boundary."""


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


class SignedMobileStaticJob(BaseModel):
    """Immutable, expiring request for one already-ingested APK."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    job_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    artifact_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hunt_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by: str = Field(min_length=2, max_length=128)
    created_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime, info) -> datetime:
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("mobile worker job expiry must be later than creation")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def expected_signature(self, key: bytes) -> str:
        payload = json.dumps(
            self.unsigned_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def verify(self, key: bytes, *, now: datetime) -> None:
        current = _utc(now, field="now")
        if current < self.created_at or current >= self.expires_at:
            raise MobileStaticSpoolError("mobile worker job is not active")
        if not hmac.compare_digest(self.signature, self.expected_signature(key)):
            raise MobileStaticSpoolError("mobile worker job signature is invalid")

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        run_id: str,
        artifact_id: str,
        artifact_sha256: str,
        hunt_plan_sha256: str,
        requested_by: str,
        key: bytes,
        created_at: datetime,
        expires_at: datetime,
    ) -> Self:
        provisional = cls.model_construct(
            schema_version="1.0",
            job_id=job_id,
            run_id=run_id,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            hunt_plan_sha256=hunt_plan_sha256,
            requested_by=requested_by,
            created_at=_utc(created_at, field="created_at"),
            expires_at=_utc(expires_at, field="expires_at"),
            signature="0" * 64,
        )
        return cls(
            **provisional.model_dump(exclude={"signature"}),
            signature=provisional.expected_signature(key),
        )


class MobileCaptureReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    return_code: int
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool


class MobileStaticJobReceipt(BaseModel):
    """Bounded terminal receipt; raw output stays in the worker workspace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str
    run_id: str
    artifact_id: str
    state: Literal["completed", "blocked", "failed", "rejected"]
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)
    captures: tuple[MobileCaptureReceipt, ...] = ()
    candidate_observations: tuple[dict[str, object], ...] = ()

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _utc(value, field="completed_at")

    @classmethod
    def from_result(
        cls,
        *,
        job: SignedMobileStaticJob,
        result: MobileStaticAnalysisResult,
    ) -> Self:
        return cls(
            job_id=job.job_id,
            run_id=job.run_id,
            artifact_id=job.artifact_id,
            state=result.state,
            result_sha256=sha256_json(result.model_dump(mode="json")),
            completed_at=result.completed_at,
            reason=result.reason,
            captures=tuple(
                MobileCaptureReceipt(
                    tool=item.tool,
                    return_code=item.return_code,
                    output_sha256=item.output_sha256,
                    truncated=item.truncated,
                )
                for item in result.captures
            ),
            candidate_observations=result.candidate_observations,
        )


class MobileStaticSpool:
    """Atomic pending/processing/terminal queue for mobile static work."""

    def __init__(self, root: Path) -> None:
        lexical = root.expanduser().absolute()
        lexical.mkdir(parents=True, exist_ok=True)
        if lexical.is_symlink():
            raise MobileStaticSpoolError("mobile worker spool root must not be a symbolic link")
        self.root = lexical.resolve(strict=True)
        self.pending = self._directory("pending")
        self.processing = self._directory("processing")
        self.completed = self._directory("completed")
        self.failed = self._directory("failed")

    def _directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise MobileStaticSpoolError("mobile worker spool directory is unsafe")
        return path

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        if path.exists() or path.is_symlink():
            raise MobileStaticSpoolError("mobile worker job path already exists")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)

    def enqueue(self, job: SignedMobileStaticJob) -> Path:
        for directory in (self.pending, self.processing, self.completed, self.failed):
            if (directory / f"{job.job_id}.json").exists():
                raise MobileStaticSpoolError("mobile worker job identifier was already used")
        path = self.pending / f"{job.job_id}.json"
        self._write_exclusive(path, job.model_dump_json(indent=2) + "\n")
        return path

    def claim_next(self) -> Path | None:
        for source in sorted(self.pending.glob("*.json")):
            if source.is_symlink():
                raise MobileStaticSpoolError("pending mobile worker job is unsafe")
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
    ) -> SignedMobileStaticJob:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.processing)
        except (OSError, ValueError) as exc:
            raise MobileStaticSpoolError(
                "claimed mobile job is outside the processing spool"
            ) from exc
        if path.is_symlink() or not resolved.is_file():
            raise MobileStaticSpoolError("claimed mobile worker job is unsafe")
        try:
            job = SignedMobileStaticJob.model_validate_json(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MobileStaticSpoolError("claimed mobile worker job is invalid") from exc
        job.verify(key, now=now)
        return job

    def finish(
        self,
        claimed_path: Path,
        *,
        receipt: MobileStaticJobReceipt,
        success: bool,
    ) -> Path:
        target_root = self.completed if success else self.failed
        destination = target_root / claimed_path.name
        receipt_path = target_root / f"{claimed_path.stem}.receipt.json"
        self._write_exclusive(receipt_path, receipt.model_dump_json(indent=2) + "\n")
        os.replace(claimed_path, destination)
        return destination

    def reject(self, claimed_path: Path, *, reason: str, now: datetime) -> Path:
        safe_reason = " ".join(reason.split())[:500] or "Mobile worker job rejected."
        digest = hashlib.sha256(safe_reason.encode()).hexdigest()
        job_id = claimed_path.stem
        receipt = MobileStaticJobReceipt(
            job_id=job_id,
            run_id=job_id,
            artifact_id="unknown-artifact",
            state="rejected",
            result_sha256=digest,
            completed_at=now,
            reason=safe_reason,
        )
        return self.finish(claimed_path, receipt=receipt, success=False)

    def recover_processing(self, *, now: datetime) -> tuple[Path, ...]:
        return tuple(
            self.reject(
                path,
                reason="Claimed mobile worker job recovered fail-closed after restart.",
                now=now,
            )
            for path in sorted(self.processing.glob("*.json"))
        )

    def status(self, job_id: str) -> dict[str, object] | None:
        for state, directory in (
            ("queued", self.pending),
            ("running", self.processing),
            ("completed", self.completed),
            ("failed", self.failed),
        ):
            job_path = directory / f"{job_id}.json"
            if not job_path.is_file() or job_path.is_symlink():
                continue
            payload: dict[str, object] = {"job_id": job_id, "state": state}
            receipt_path = directory / f"{job_id}.receipt.json"
            if receipt_path.is_file() and not receipt_path.is_symlink():
                try:
                    receipt = MobileStaticJobReceipt.model_validate_json(
                        receipt_path.read_text(encoding="utf-8")
                    )
                except (OSError, ValueError) as exc:
                    raise MobileStaticSpoolError("mobile worker receipt is invalid") from exc
                payload["state"] = receipt.state
                payload["receipt"] = receipt.model_dump(mode="json")
            return payload
        return None


__all__ = [
    "MobileCaptureReceipt",
    "MobileStaticJobReceipt",
    "MobileStaticSpool",
    "MobileStaticSpoolError",
    "SignedMobileStaticJob",
]
