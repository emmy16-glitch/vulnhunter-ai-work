"""Manager and worker services for queued isolated APK inspection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import sha256_json
from vulnhunter.hunt.mobile_graph import build_mobile_evidence_graph
from vulnhunter.hunt.mobile_runtime import MobileHuntExecutionReceipt, run_mobile_evidence_hunt
from vulnhunter.mobile.artifacts import MobileArtifactIngestor
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_progress import (
    MobileStaticProgressError,
    MobileStaticProgressStore,
)
from vulnhunter.mobile.static_spool import (
    MobileStaticJobReceipt,
    MobileStaticSpool,
    MobileStaticSpoolError,
    SignedMobileStaticJob,
)
from vulnhunter.mobile.static_worker import MobileStaticWorker, MobileStaticWorkerPolicy


class MobileStaticQueueServiceError(RuntimeError):
    """Raised when queued mobile analysis cannot preserve its contracts."""


def _verification_summary(hunt: MobileHuntExecutionReceipt) -> dict[str, object]:
    verified = hunt.verified_count
    rejected = hunt.rejected_count
    abstained = hunt.evidence_required_count
    non_zero = sum(value > 0 for value in (verified, rejected, abstained))
    if non_zero > 1:
        status = "mixed"
    elif verified:
        status = "verified"
    elif rejected:
        status = "rejected"
    else:
        status = "abstained"
    if not hunt.candidates:
        reason = "No candidate vulnerability was generated; verification completed without a claim."
    elif abstained:
        reason = (
            "Candidates without sufficient deterministic evidence remain abstained rather than "
            "being promoted to findings."
        )
    else:
        reason = "Every candidate received a deterministic evidence-bound disposition."
    return {
        "status": status,
        "verified_count": verified,
        "rejected_count": rejected,
        "abstained_count": abstained,
        "reason": reason,
    }


def _review_summary(
    *,
    hunt: MobileHuntExecutionReceipt,
    verification: dict[str, object],
) -> dict[str, object]:
    payload = {
        "hunt_receipt_sha256": hunt.receipt_sha256,
        "verification": verification,
        "candidate_ids": [item.candidate_id for item in hunt.candidates],
        "judge_receipts": sorted(
            {receipt for item in hunt.candidates for receipt in item.judge_receipts}
        ),
        "scope": "deterministic_evidence_disposition",
        "finding_confirmation": False,
        "publication_authority": False,
    }
    return {
        "status": "completed",
        "receipt_sha256": sha256_json(payload),
        "summary": payload,
    }


def _report_summary(
    *,
    job: SignedMobileStaticJob,
    artifact: MobileArtifactRecord,
    hunt: MobileHuntExecutionReceipt,
    verification: dict[str, object],
    review: dict[str, object],
) -> dict[str, object]:
    report_payload = {
        "assessment_id": job.run_id,
        "artifact_id": artifact.artifact_id,
        "artifact_sha256": artifact.sha256,
        "hunt_receipt_sha256": hunt.receipt_sha256,
        "verification": verification,
        "review_receipt_sha256": review["receipt_sha256"],
        "candidate_ids": [item.candidate_id for item in hunt.candidates],
        "evidence_receipts": sorted(
            {
                receipt
                for item in hunt.candidates
                for receipt in (*item.evidence_receipts, *item.judge_receipts)
            }
        ),
    }
    digest = sha256_json(report_payload)
    return {
        "status": "ready",
        "report_id": f"{job.run_id}-report-{digest[:12]}",
        "digest": digest,
        "summary": report_payload,
    }


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
        self.progress = MobileStaticProgressStore(spool.root)

    def run_once(self) -> MobileStaticJobReceipt | None:
        claimed = self.spool.claim_next()
        if claimed is None:
            return None
        now = self.clock()
        job: SignedMobileStaticJob | None = None
        canonical_finished = False
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

            def publish(event: dict[str, object]) -> None:
                self.progress.append_event(
                    job_id=job.job_id,
                    event=event,
                    key=self.signing_key,
                )

            result = MobileStaticWorker(self.policy).analyze(
                record,
                analysis_reference=job.job_id,
                progress_callback=publish,
            )
            hunt = run_mobile_evidence_hunt(result)
            graph = build_mobile_evidence_graph(artifact=record, hunt=hunt)
            success = result.state == "completed"
            summary = {
                "captures": [
                    {
                        "tool": capture.tool,
                        "return_code": capture.return_code,
                        "output_sha256": capture.output_sha256,
                        "truncated": capture.truncated,
                        "started_at": capture.started_at.isoformat(),
                        "completed_at": capture.completed_at.isoformat(),
                        "duration_ms": capture.duration_ms,
                        "evidence": capture.evidence,
                    }
                    for capture in result.captures
                ],
                "hunt": hunt.model_dump(mode="json"),
                "graph": graph.model_dump(mode="json"),
            }
            if success:
                verification = _verification_summary(hunt)
                review = _review_summary(hunt=hunt, verification=verification)
                summary["verification"] = verification
                summary["review"] = review
                summary["report"] = _report_summary(
                    job=job,
                    artifact=record,
                    hunt=hunt,
                    verification=verification,
                    review=review,
                )
            receipt = MobileStaticJobReceipt.from_result(job=job, result=result)
            self.spool.finish(
                claimed,
                receipt=receipt,
                success=success,
            )
            canonical_finished = True
            try:
                self.progress.finalize(
                    job_id=job.job_id,
                    success=success,
                    result_summary=summary,
                    key=self.signing_key,
                )
            except (OSError, ValueError, MobileStaticProgressError):
                # The canonical terminal receipt is authoritative. A live projection
                # failure must not relabel a completed evidence job as rejected.
                pass
            return receipt
        except (
            OSError,
            ValueError,
            MobileStaticProgressError,
            MobileStaticSpoolError,
            MobileStaticQueueServiceError,
        ) as exc:
            if not canonical_finished:
                self.spool.reject(
                    claimed,
                    reason=f"Mobile static job failed closed: {type(exc).__name__}.",
                    now=now,
                )
            if job is not None:
                try:
                    self.progress.finalize(
                        job_id=job.job_id,
                        success=False,
                        result_summary={
                            "error": f"Mobile static job failed closed: {type(exc).__name__}."
                        },
                        key=self.signing_key,
                    )
                except (OSError, ValueError, MobileStaticProgressError):
                    pass
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
