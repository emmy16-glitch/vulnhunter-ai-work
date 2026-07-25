"""Manager and worker services for queued networkless APK inspection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from vulnhunter.mobile.artifacts import MobileArtifactIngestor
from vulnhunter.mobile.static_spool import (
    MobileStaticJobReceipt,
    MobileStaticSpool,
    MobileStaticSpoolError,
    SignedMobileStaticJob,
)
from vulnhunter.mobile.static_worker import MobileStaticWorker, MobileStaticWorkerPolicy


class MobileStaticQueueServiceError(RuntimeError):
    """Raised when queued mobile analysis cannot preserve its contracts."""


class MobileStaticQueueService:
    """Claim signed jobs, revalidate artifact identity and run the fixed worker."""

    def __init__(
        self,
        *,
        spool: MobileStaticSpool,
        signing_key: bytes,
        policy: MobileStaticWorkerPolicy,
        ingestor: MobileArtifactIngestor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.spool = spool
        self.signing_key = signing_key
        self.policy = policy
        self.ingestor = ingestor
        self.clock = clock or (lambda: datetime.now(UTC))

    def run_once(self) -> MobileStaticJobReceipt | None:
        claimed = self.spool.claim_next()
        if claimed is None:
            return None
        now = self.clock()
        try:
            job = self.spool.load_claimed(claimed, key=self.signing_key, now=now)
            record = next(
                (
                    item
                    for item in self.ingestor.list_records()
                    if item.artifact_id == job.artifact_id and item.sha256 == job.artifact_sha256
                ),
                None,
            )
            if record is None:
                raise MobileStaticQueueServiceError(
                    "The queued APK no longer matches the ingested artifact record."
                )
            result = MobileStaticWorker(self.policy).analyze(record)
            receipt = MobileStaticJobReceipt.from_result(job=job, result=result)
            self.spool.finish(
                claimed,
                receipt=receipt,
                success=result.state == "completed",
            )
            return receipt
        except (OSError, ValueError, MobileStaticSpoolError, MobileStaticQueueServiceError) as exc:
            self.spool.reject(
                claimed,
                reason=f"Mobile static job failed closed: {type(exc).__name__}.",
                now=now,
            )
            raise MobileStaticQueueServiceError(str(exc)) from exc


def create_mobile_static_job(
    *,
    run_id: str,
    artifact_id: str,
    artifact_sha256: str,
    hunt_plan_sha256: str,
    requested_by: str,
    signing_key: bytes,
    now: datetime | None = None,
) -> SignedMobileStaticJob:
    created_at = (now or datetime.now(UTC)).astimezone(UTC)
    return SignedMobileStaticJob.create(
        job_id=run_id,
        run_id=run_id,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        hunt_plan_sha256=hunt_plan_sha256,
        requested_by=requested_by,
        key=signing_key,
        created_at=created_at,
        expires_at=created_at + timedelta(hours=2),
    )


__all__ = [
    "MobileStaticQueueService",
    "MobileStaticQueueServiceError",
    "create_mobile_static_job",
]
