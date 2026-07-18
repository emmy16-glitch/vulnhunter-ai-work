from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.adversary_lab.models import LabState
from vulnhunter.adversary_lab.runner import LabWorkerPolicy, SyntheticScenarioRunner
from vulnhunter.adversary_lab.service import AdversaryLabService, AdversaryLabServiceError
from vulnhunter.adversary_lab.store import AdversaryLabStore
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore


def _service(
    tmp_path: Path, *, enabled: bool = True
) -> tuple[AdversaryLabService, AgentActivityService]:
    activity = AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity"))
    policy = LabWorkerPolicy(
        enabled=enabled,
        workspace_root=(tmp_path / "workspace").resolve(),
        evidence_root=(tmp_path / "evidence").resolve(),
        maximum_trials=10,
    )
    return (
        AdversaryLabService(
            store=AdversaryLabStore(tmp_path / "adversary-lab.sqlite3"),
            activity_service=activity,
            runner=SyntheticScenarioRunner(policy),
        ),
        activity,
    )


def _created(service: AdversaryLabService, *, maximum_trials: int = 10):
    return service.create_plan(
        assessment_id="assessment-lab-01",
        finding_reference="evidence-lab-01",
        authorization_id="authorization-lab-01",
        target_reference="http://10.23.0.15:8080/",
        scenario_id="synthetic-file-impact",
        maximum_trials=maximum_trials,
        requested_by="operator-a",
    )


def test_controlled_lab_runs_clean_snapshot_retry_loop_and_cleans_up(tmp_path: Path) -> None:
    service, activity = _service(tmp_path)
    created = _created(service, maximum_trials=10)

    approved = service.approve(created.plan.lab_id, approved_by="approver-b")
    assert approved.approved_plan_digest == approved.plan.plan_digest
    queued = service.queue(created.plan.lab_id, queued_by="operator-a")
    assert queued.state is LabState.QUEUED

    completed = service.run_next()

    assert completed is not None
    assert completed.state is LabState.COMPLETED
    assert completed.result == "confirmed"
    assert completed.cleanup_verified is True
    assert 3 <= len(completed.trials) <= 10
    assert completed.confirmed_trials >= completed.plan.required_confirmations
    assert all(trial.snapshot_restored for trial in completed.trials)
    assert all(trial.metadata["network_contacted"] is False for trial in completed.trials)
    assert not (tmp_path / "workspace" / completed.plan.lab_id).exists()
    assert len(tuple((tmp_path / "evidence" / completed.plan.lab_id).glob("trial-*.json"))) == len(
        completed.trials
    )

    feed = activity.feed(completed.plan.lab_id)
    event_types = [event.event_type for event in feed.events]
    assert "approval_requested" in event_types
    assert "approval_granted" in event_types
    assert "tool_execution_started" in event_types
    assert "retry_scheduled" in event_types
    assert event_types[-1] == "run_completed"
    assert all("secret" not in event.summary.lower() for event in feed.events)


def test_requester_cannot_approve_same_plan(tmp_path: Path) -> None:
    service, _activity = _service(tmp_path)
    created = _created(service, maximum_trials=3)

    with pytest.raises(AdversaryLabServiceError, match="requester cannot approve"):
        service.approve(created.plan.lab_id, approved_by="operator-a")


def test_queued_lab_can_be_cancelled_before_worker_claim(tmp_path: Path) -> None:
    service, activity = _service(tmp_path)
    created = _created(service, maximum_trials=5)
    service.approve(created.plan.lab_id, approved_by="approver-b")
    service.queue(created.plan.lab_id, queued_by="operator-a")

    cancelled = service.request_cancel(
        created.plan.lab_id,
        actor_id="operator-a",
        reason="Stop before the worker starts.",
    )

    assert cancelled.state is LabState.CANCELLED
    assert service.run_next() is None
    assert activity.feed(created.plan.lab_id).events[-1].event_type == "run_stopped"


def test_worker_policy_blocks_disabled_lab_and_trial_ceiling_is_ten(tmp_path: Path) -> None:
    service, _activity = _service(tmp_path, enabled=False)
    created = _created(service, maximum_trials=3)
    service.approve(created.plan.lab_id, approved_by="approver-b")
    service.queue(created.plan.lab_id, queued_by="operator-a")

    failed = service.run_next()

    assert failed is not None
    assert failed.state is LabState.FAILED
    assert failed.cleanup_verified is True

    with pytest.raises((ValidationError, ValueError)):
        _created(service, maximum_trials=11)
