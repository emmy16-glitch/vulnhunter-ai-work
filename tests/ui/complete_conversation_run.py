#!/usr/bin/env python3
"""Simulate the isolated worker transitions after a real browser approval."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import os
import time
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")

import django

django.setup()

from django.conf import settings

from vulnhunter.agent.models import TaskStatus
from vulnhunter.agent.store import AgentStore
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.evidence import EvidenceStore, FindingStatus


def transition(
    store: AgentStore,
    activity: AgentActivityService,
    run_id: str,
    *,
    workflow_state: str,
    status: TaskStatus,
    event_type: str,
    summary: str,
    source: str,
) -> None:
    current = store.get_task(run_id)
    workflow = dict(current.memory.get("assessment_workflow", {}))
    updated = current.evolved(
        status=status,
        paused_reason=None,
        memory={
            **current.memory,
            "assessment_workflow": {
                **workflow,
                "workflow_state": workflow_state,
                "approval_state": "approved",
                "execution_state": workflow_state,
                "blocking_reason": None,
            },
        },
        final_summary=(
            "One informational passive finding was verified."
            if workflow_state == "completed"
            else current.final_summary
        ),
    )
    store.save_task(updated, expected_revision=current.revision)
    store.append_event(run_id, event_type, {"summary": summary})
    activity.record_transition(
        run_id=run_id,
        timestamp=datetime.now(UTC),
        event_type=event_type,
        summary=summary,
        run_state=workflow_state,
        source=source,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    store = AgentStore(Path(settings.VULNHUNTER_AGENT_DATABASE))
    activity = AgentActivityService(
        AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
    )
    transition(
        store,
        activity,
        args.run_id,
        workflow_state="executing",
        status=TaskStatus.RUNNING,
        event_type="tool_execution_started",
        summary="Running passive checks…",
        source="tool",
    )
    time.sleep(1.6)
    transition(
        store,
        activity,
        args.run_id,
        workflow_state="evaluating",
        status=TaskStatus.RUNNING,
        event_type="evaluation_started",
        summary="Verifying one possible finding…",
        source="evaluator",
    )
    evidence_root = Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)
    evidence_root.mkdir(parents=True, exist_ok=True)
    artifact = evidence_root / f"{args.run_id}-headers.json"
    artifact.write_text('{"header":"x-content-type-options","value":"missing"}\n', encoding="utf-8")
    task = store.get_task(args.run_id)
    workflow = dict(task.memory.get("assessment_workflow", {}))
    plan_digest = str(workflow.get("plan_digest") or "a" * 64)
    EvidenceStore(evidence_root).append(
        evidence_id=f"finding-{args.run_id}",
        campaign_id=f"campaign-{args.run_id}",
        run_id=args.run_id,
        action_manifest_sha256=plan_digest,
        tool_id="nuclei",
        target_reference="http://10.0.11.34:8010/",
        finding_status=FindingStatus.VALIDATED,
        title="Missing X-Content-Type-Options header",
        severity="info",
        confidence="high",
        recorded_by="browser-e2e-worker",
        artifact_path=artifact,
        metadata={},
    )
    time.sleep(1.6)
    transition(
        store,
        activity,
        args.run_id,
        workflow_state="completed",
        status=TaskStatus.COMPLETED,
        event_type="run_completed",
        summary="Analysis complete.",
        source="system",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
