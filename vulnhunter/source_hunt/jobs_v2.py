"""V2 Source Hunt job execution using the existing authoritative queue and report store."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from vulnhunter.security import redact_text
from vulnhunter.source_hunt.intelligence import SourceHuntV2
from vulnhunter.source_hunt.intelligence_store import SourceHuntIntelligenceStore
from vulnhunter.source_hunt.jobs import SourceHuntJob, SourceHuntJobStore
from vulnhunter.source_hunt.service import SourceHuntConnector, SourceHuntPolicy
from vulnhunter.source_hunt.store import SourceHuntStore


def process_next_source_hunt_v2_job(
    *,
    job_store: SourceHuntJobStore,
    report_store: SourceHuntStore,
    intelligence_store: SourceHuntIntelligenceStore,
    connector: SourceHuntConnector,
    policy: SourceHuntPolicy,
    on_state_change: Callable[[SourceHuntJob], None] | None = None,
) -> SourceHuntJob | None:
    """Claim and execute one V2 job while preserving the original queue semantics."""

    job = job_store.claim_next()
    if job is None:
        return None
    try:
        if on_state_change is not None:
            on_state_change(job)

        try:
            existing = report_store.load(job.expected_report_id)
        except FileNotFoundError:
            existing = None

        if existing is not None:
            if (
                existing.approval_id != job.approval.approval_id
                or existing.snapshot.snapshot_sha256 != job.snapshot.snapshot_sha256
            ):
                raise ValueError("persisted source-hunt report does not match the claimed job")
            if not intelligence_store.exists(existing.report_id):
                raise ValueError(
                    "existing source-hunt report has no V2 intelligence sidecar; "
                    "refusing to claim V2 completion"
                )
            intelligence = intelligence_store.load(existing.report_id)
            if intelligence.report_id != existing.report_id:
                raise ValueError("persisted V2 sidecar report binding is invalid")
            if intelligence.snapshot_sha256 != existing.snapshot.snapshot_sha256:
                raise ValueError("persisted V2 sidecar snapshot binding is invalid")
            completed = job_store.complete(job, existing)
            if on_state_change is not None:
                on_state_change(completed)
            return completed

        engine = SourceHuntV2(connector=connector, policy=policy)
        report, intelligence = engine.run_with_intelligence(
            Path(job.repository_root),
            approval=job.approval,
            revision=job.snapshot.revision,
        )
        if report.report_id != intelligence.report_id:
            raise ValueError("V2 intelligence sidecar is not bound to the source-hunt report")
        if report.snapshot.snapshot_sha256 != intelligence.snapshot_sha256:
            raise ValueError("V2 intelligence sidecar is not bound to the repository snapshot")

        report_store.save(report)
        intelligence_store.save(intelligence)
        completed = job_store.complete(job, report)
        if on_state_change is not None:
            on_state_change(completed)
        return completed
    except Exception as exc:
        safe_error = redact_text(str(exc) or type(exc).__name__)
        failed = job_store.fail(job, safe_error)
        if on_state_change is not None:
            try:
                on_state_change(failed)
            except Exception:
                pass
        return failed
