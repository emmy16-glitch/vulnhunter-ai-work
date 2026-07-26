"""File-backed, fail-closed job queue for Groq source hunts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.source_hunt.models import (
    RemoteSourceProcessingApproval,
    RepositorySnapshot,
    SourceHuntReport,
)
from vulnhunter.source_hunt.service import GroqSourceHunt, SourceHuntConnector, SourceHuntPolicy
from vulnhunter.source_hunt.store import SourceHuntStore


class SourceHuntJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SourceHuntJob(BaseModel):
    """A non-secret source-hunt request bound to one exact repository snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str = Field(pattern=r"^source-job-[0-9a-f]{32}$")
    repository_root: str
    snapshot: RepositorySnapshot
    approval: RemoteSourceProcessingApproval
    model: str
    status: SourceHuntJobStatus
    report_id: str | None = None
    safe_error: str | None = Field(default=None, max_length=1_000)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @classmethod
    def create(
        cls,
        *,
        repository_root: Path,
        snapshot: RepositorySnapshot,
        approval: RemoteSourceProcessingApproval,
        model: str,
        now: datetime | None = None,
    ) -> SourceHuntJob:
        created_at = now or datetime.now(UTC)
        return cls(
            job_id=f"source-job-{uuid4().hex}",
            repository_root=str(repository_root.expanduser().resolve(strict=True)),
            snapshot=snapshot,
            approval=approval,
            model=model,
            status=SourceHuntJobStatus.QUEUED,
            created_at=created_at,
        )


class SourceHuntJobStore:
    """Atomic spool with queued, running, completed and failed states."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.queued = self.root / "queued"
        self.running = self.root / "running"
        self.completed = self.root / "completed"
        self.failed = self.root / "failed"

    def initialize(self) -> None:
        for directory in (self.queued, self.running, self.completed, self.failed):
            directory.mkdir(parents=True, exist_ok=True)

    def enqueue(self, job: SourceHuntJob) -> Path:
        if job.status != SourceHuntJobStatus.QUEUED:
            raise ValueError("only queued source-hunt jobs may be enqueued")
        self.initialize()
        destination = self._path(self.queued, job.job_id)
        if destination.exists():
            raise ValueError("source-hunt job already exists")
        self._atomic_write(destination, job)
        return destination

    def claim_next(self, *, now: datetime | None = None) -> SourceHuntJob | None:
        self.initialize()
        for queued_path in sorted(self.queued.glob("source-job-*.json")):
            running_path = self._path(self.running, queued_path.stem)
            try:
                queued_path.replace(running_path)
            except FileNotFoundError:
                continue
            try:
                queued_job = self._load_path(running_path)
                running_job = queued_job.model_copy(
                    update={
                        "status": SourceHuntJobStatus.RUNNING,
                        "started_at": now or datetime.now(UTC),
                    }
                )
                self._atomic_write(running_path, running_job)
                return running_job
            except Exception:
                failed_path = self._path(self.failed, running_path.stem)
                running_path.replace(failed_path)
                raise
        return None

    def complete(
        self,
        job: SourceHuntJob,
        report: SourceHuntReport,
        *,
        now: datetime | None = None,
    ) -> SourceHuntJob:
        if job.status != SourceHuntJobStatus.RUNNING:
            raise ValueError("only running source-hunt jobs may complete")
        completed_job = job.model_copy(
            update={
                "status": SourceHuntJobStatus.COMPLETED,
                "report_id": report.report_id,
                "safe_error": None,
                "completed_at": now or datetime.now(UTC),
            }
        )
        self._move_and_write(job.job_id, self.running, self.completed, completed_job)
        return completed_job

    def fail(
        self,
        job: SourceHuntJob,
        safe_error: str,
        *,
        now: datetime | None = None,
    ) -> SourceHuntJob:
        if job.status != SourceHuntJobStatus.RUNNING:
            raise ValueError("only running source-hunt jobs may fail")
        failed_job = job.model_copy(
            update={
                "status": SourceHuntJobStatus.FAILED,
                "safe_error": " ".join(safe_error.split())[:1_000],
                "completed_at": now or datetime.now(UTC),
            }
        )
        self._move_and_write(job.job_id, self.running, self.failed, failed_job)
        return failed_job

    def load(self, job_id: str) -> SourceHuntJob:
        self._validate_job_id(job_id)
        self.initialize()
        for directory in (self.queued, self.running, self.completed, self.failed):
            path = self._path(directory, job_id)
            if path.is_file():
                return self._load_path(path)
        raise FileNotFoundError(f"source-hunt job not found: {job_id}")

    def list(self, *, limit: int = 50) -> tuple[SourceHuntJob, ...]:
        self.initialize()
        jobs: list[SourceHuntJob] = []
        for directory in (self.queued, self.running, self.completed, self.failed):
            for path in directory.glob("source-job-*.json"):
                try:
                    jobs.append(self._load_path(path))
                except (OSError, ValueError):
                    continue
        return tuple(
            sorted(jobs, key=lambda item: item.created_at, reverse=True)[:limit]
        )

    def _move_and_write(
        self,
        job_id: str,
        source_directory: Path,
        destination_directory: Path,
        updated: SourceHuntJob,
    ) -> None:
        self.initialize()
        source = self._path(source_directory, job_id)
        destination = self._path(destination_directory, job_id)
        source.replace(destination)
        self._atomic_write(destination, updated)

    @staticmethod
    def _validate_job_id(job_id: str) -> None:
        if (
            not job_id.startswith("source-job-")
            or len(job_id) != len("source-job-") + 32
            or any(character not in "0123456789abcdef" for character in job_id[11:])
        ):
            raise ValueError("source-hunt job identifier is invalid")

    def _path(self, directory: Path, job_id: str) -> Path:
        self._validate_job_id(job_id)
        return directory / f"{job_id}.json"

    @staticmethod
    def _load_path(path: Path) -> SourceHuntJob:
        return SourceHuntJob.model_validate_json(path.read_text(encoding="utf-8"))

    @staticmethod
    def _atomic_write(path: Path, job: SourceHuntJob) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(job.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


def process_next_source_hunt_job(
    *,
    job_store: SourceHuntJobStore,
    report_store: SourceHuntStore,
    connector: SourceHuntConnector,
    policy: SourceHuntPolicy,
) -> SourceHuntJob | None:
    """Claim and execute one job, preserving a terminal state on every failure."""

    job = job_store.claim_next()
    if job is None:
        return None
    try:
        report = GroqSourceHunt(connector=connector, policy=policy).run(
            Path(job.repository_root),
            approval=job.approval,
            revision=job.snapshot.revision,
        )
        report_store.save(report)
        return job_store.complete(job, report)
    except Exception as exc:
        safe_error = str(exc) or type(exc).__name__
        return job_store.fail(job, safe_error)
