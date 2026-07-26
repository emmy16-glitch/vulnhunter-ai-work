from __future__ import annotations

from pathlib import Path

import pytest
from django.core.management.base import CommandError
from test_source_hunt_jobs import _QueueGroq, _job

from vulnhunter.source_hunt import (
    SourceHuntJob,
    SourceHuntJobStatus,
    SourceHuntJobStore,
    SourceHuntStore,
    process_next_source_hunt_job,
)
from vulnhunter.web.management.commands.vh_run_source_hunt_worker import (
    _acquire_worker_lock,
)


class _UnexpectedGroq:
    def invoke(self, invocation, content, *, cancelled=None):
        raise AssertionError("an existing matching report must not trigger another Groq call")


def test_interrupted_running_job_is_requeued_for_single_worker_recovery(tmp_path):
    job, _policy = _job(tmp_path)
    store = SourceHuntJobStore(tmp_path / "jobs")
    store.enqueue(job)
    running = store.claim_next()

    recovered = store.recover_running()

    assert running is not None
    assert running.status == SourceHuntJobStatus.RUNNING
    assert recovered[0].status == SourceHuntJobStatus.QUEUED
    assert recovered[0].started_at is None
    assert store.load(job.job_id) == recovered[0]


def test_recovered_job_reuses_matching_report_without_duplicate_groq_calls(tmp_path):
    job, policy = _job(tmp_path)
    report_store = SourceHuntStore(tmp_path / "reports")
    first_store = SourceHuntJobStore(tmp_path / "first-jobs")
    first_store.enqueue(job)
    first = process_next_source_hunt_job(
        job_store=first_store,
        report_store=report_store,
        connector=_QueueGroq(),
        policy=policy,
    )
    assert first is not None and first.report_id == job.expected_report_id

    duplicate = SourceHuntJob.create(
        repository_root=Path(job.repository_root),
        snapshot=job.snapshot,
        approval=job.approval,
        model=job.model,
    )
    second_store = SourceHuntJobStore(tmp_path / "second-jobs")
    second_store.enqueue(duplicate)

    second = process_next_source_hunt_job(
        job_store=second_store,
        report_store=report_store,
        connector=_UnexpectedGroq(),
        policy=policy,
    )

    assert second is not None
    assert second.status == SourceHuntJobStatus.COMPLETED
    assert second.report_id == job.expected_report_id


def test_report_store_refuses_different_evidence_under_existing_identifier(tmp_path):
    job, policy = _job(tmp_path)
    report_store = SourceHuntStore(tmp_path / "reports")
    job_store = SourceHuntJobStore(tmp_path / "jobs")
    job_store.enqueue(job)
    completed = process_next_source_hunt_job(
        job_store=job_store,
        report_store=report_store,
        connector=_QueueGroq(),
        policy=policy,
    )
    assert completed is not None and completed.report_id is not None
    report = report_store.load(completed.report_id)

    with pytest.raises(ValueError, match="different evidence"):
        report_store.save(report.model_copy(update={"safe_error": "different"}))


def test_source_hunt_worker_lock_prevents_two_queue_consumers(tmp_path):
    store = SourceHuntJobStore(tmp_path / "jobs")
    first = _acquire_worker_lock(store)
    try:
        with pytest.raises(CommandError, match="another Source Hunt worker"):
            _acquire_worker_lock(store)
    finally:
        first.close()
