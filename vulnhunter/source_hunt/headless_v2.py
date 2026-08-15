"""Fail-closed headless/CI admission for local Source Hunt V2 jobs.

The headless path never clones an arbitrary repository, creates target authorization,
expands permitted paths, or infers approval from CI configuration. A distinct human
must approve an immutable, expiring, one-use manifest bound to an exact local source
snapshot before a job can be enqueued.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.source_hunt.jobs import SourceHuntJob, SourceHuntJobStore
from vulnhunter.source_hunt.models import RemoteSourceProcessingApproval, RepositorySnapshot
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy


def _normalize_paths(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise ValueError("headless manifest requires at least one permitted path")
    normalized: list[str] = []
    for value in values:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("headless permitted paths must be repository-relative")
        normalized.append(path.as_posix())
    return tuple(dict.fromkeys(normalized))


class HeadlessPermissionManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str = Field(pattern=r"^source-headless-[0-9a-f]{24}$")
    repository_id: str
    revision: str = Field(min_length=1, max_length=256)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    permitted_paths: tuple[str, ...]
    requester_id: str = Field(min_length=2, max_length=128)
    approver_id: str = Field(min_length=2, max_length=128)
    allow_remote_source_processing: bool
    maximum_runs: int = Field(ge=1, le=1)
    created_at: datetime
    expires_at: datetime
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("permitted_paths")
    @classmethod
    def validate_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _normalize_paths(values)

    @model_validator(mode="after")
    def validate_authority(self) -> HeadlessPermissionManifest:
        if self.requester_id == self.approver_id:
            raise ValueError("headless requester and approver must be distinct identities")
        if self.expires_at <= self.created_at:
            raise ValueError("headless permission expiry must follow creation")
        if not self.allow_remote_source_processing:
            raise ValueError(
                "Source Hunt V2 requires an explicit remote-source-processing permission"
            )
        canonical = {
            "repository_id": self.repository_id,
            "revision": self.revision,
            "snapshot_sha256": self.snapshot_sha256,
            "permitted_paths": list(self.permitted_paths),
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "allow_remote_source_processing": self.allow_remote_source_processing,
            "maximum_runs": self.maximum_runs,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
            "expires_at": self.expires_at.astimezone(UTC).isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.manifest_sha256:
            raise ValueError("headless permission manifest digest does not match its contents")
        if self.manifest_id != f"source-headless-{digest[:24]}":
            raise ValueError("headless permission manifest ID does not match its digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        snapshot: RepositorySnapshot,
        permitted_paths: tuple[str, ...],
        requester_id: str,
        approver_id: str,
        allow_remote_source_processing: bool,
        created_at: datetime,
        expires_at: datetime,
    ) -> HeadlessPermissionManifest:
        normalized_paths = _normalize_paths(permitted_paths)
        canonical = {
            "repository_id": snapshot.repository_id,
            "revision": snapshot.revision,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "permitted_paths": list(normalized_paths),
            "requester_id": requester_id,
            "approver_id": approver_id,
            "allow_remote_source_processing": allow_remote_source_processing,
            "maximum_runs": 1,
            "created_at": created_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(
            manifest_id=f"source-headless-{digest[:24]}",
            repository_id=snapshot.repository_id,
            revision=snapshot.revision,
            snapshot_sha256=snapshot.snapshot_sha256,
            permitted_paths=normalized_paths,
            requester_id=requester_id,
            approver_id=approver_id,
            allow_remote_source_processing=allow_remote_source_processing,
            maximum_runs=1,
            created_at=created_at,
            expires_at=expires_at,
            manifest_sha256=digest,
        )

    def validate_for(
        self,
        snapshot: RepositorySnapshot,
        approval: RemoteSourceProcessingApproval,
        *,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if current >= self.expires_at:
            raise ValueError("headless source-hunt permission has expired")
        if (
            snapshot.repository_id != self.repository_id
            or snapshot.revision != self.revision
            or snapshot.snapshot_sha256 != self.snapshot_sha256
        ):
            raise ValueError("headless permission does not match the repository snapshot")
        approval.validate_for(snapshot, now=current)
        if tuple(approval.permitted_paths) != tuple(self.permitted_paths):
            raise ValueError("headless and Groq source-processing path approvals differ")


class HeadlessManifestConsumption(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str
    consumed_at: datetime


class HeadlessManifestLedger:
    """One-use manifest ledger using an atomic exclusive-create claim."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def claim(
        self,
        manifest: HeadlessPermissionManifest,
        *,
        job_id: str,
        now: datetime | None = None,
    ) -> HeadlessManifestConsumption:
        self.root.mkdir(parents=True, exist_ok=True)
        receipt = HeadlessManifestConsumption(
            manifest_id=manifest.manifest_id,
            manifest_sha256=manifest.manifest_sha256,
            job_id=job_id,
            consumed_at=now or datetime.now(UTC),
        )
        destination = self.root / f"{manifest.manifest_id}.json"
        payload = json.dumps(receipt.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
        try:
            with destination.open("x", encoding="utf-8") as handle:
                handle.write(payload)
        except FileExistsError as exc:
            raise ValueError("headless source-hunt manifest has already been consumed") from exc
        return receipt

    def load(self, manifest_id: str) -> HeadlessManifestConsumption:
        if not manifest_id.startswith("source-headless-"):
            raise ValueError("invalid headless source-hunt manifest identifier")
        return HeadlessManifestConsumption.model_validate_json(
            (self.root / f"{manifest_id}.json").read_text(encoding="utf-8")
        )


class HeadlessSourceHuntService:
    """Prepare one local queued Source Hunt job from exact pre-existing human authority."""

    def __init__(
        self,
        *,
        policy: SourceHuntPolicy,
        job_store: SourceHuntJobStore,
        manifest_ledger: HeadlessManifestLedger,
    ) -> None:
        self.policy = policy
        self.job_store = job_store
        self.manifest_ledger = manifest_ledger

    def enqueue(
        self,
        repository_root: Path,
        *,
        revision: str,
        approval: RemoteSourceProcessingApproval,
        manifest: HeadlessPermissionManifest,
        now: datetime | None = None,
    ) -> SourceHuntJob:
        snapshot = RepositorySnapshotBuilder(self.policy).build(
            repository_root,
            revision=revision,
        )
        manifest.validate_for(snapshot, approval, now=now)
        job = SourceHuntJob.create(
            repository_root=repository_root,
            snapshot=snapshot,
            approval=approval,
            model=self.policy.model,
            now=now,
        )
        self.manifest_ledger.claim(manifest, job_id=job.job_id, now=now)
        self.job_store.enqueue(job)
        return job
