#!/usr/bin/env python3
# ruff: noqa: E501
"""Apply the final reviewed phone-lab wiring repairs.

This temporary script is executed once by the PR quality workflow and removed in
the same implementation commit.
"""

from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"Expected block was not found in {path}: {old[:120]!r}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''            event_type=(
                "scanner_queued"
                if queued_job is not None
                else "run_blocked"
                if approved
                else "approval_rejected"
            ),
            run_state=(
                "queued" if queued_job is not None else "blocked" if approved else "cancelled"
            ),
''',
        '''            event_type=(
                "tool_progress"
                if queued_job is not None
                else "run_blocked"
                if approved
                else "approval_rejected"
            ),
            run_state=(
                "executing" if queued_job is not None else "blocked" if approved else "cancelled"
            ),
''',
    )

    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        "import resource\nimport signal\n",
        "import resource\nimport shutil\nimport signal\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''        environment = {
            "PATH": str(executable.parent),
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        request = specification.request
        output_root = request.output_directory
        stdout_path = output_root / f".{request.execution_id}.stdout"
''',
        '''        request = specification.request
        output_root = request.output_directory
        runtime_home = output_root / f".{request.execution_id}.home"
        runtime_home.mkdir(mode=0o700, exist_ok=False)
        environment = {
            "PATH": str(executable.parent),
            "HOME": str(runtime_home),
            "XDG_CONFIG_HOME": str(runtime_home / ".config"),
            "XDG_CACHE_HOME": str(runtime_home / ".cache"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        stdout_path = output_root / f".{request.execution_id}.stdout"
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''        finally:
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
''',
        '''        finally:
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            shutil.rmtree(runtime_home, ignore_errors=True)
''',
    )

    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''        self._activity(
            job.job_id,
            "tool_execution_started",
            "Starting isolated passive scan.",
            "executing",
        )
        record = harness.execute_pilot(invocation)
''',
        '''        self._activity(
            job.job_id,
            "tool_execution_started",
            "The isolated worker accepted the signed job and is starting Nuclei.",
            "executing",
            metadata={"profile": invocation.request.exact_profile},
        )
        self._activity(
            job.job_id,
            "tool_progress",
            "Nuclei is evaluating the reviewed passive template against the approved target.",
            "executing",
            metadata={
                "profile": invocation.request.exact_profile,
                "target_count": len(invocation.request.exact_targets),
                "template_count": len(invocation.request.template_manifest_hashes),
            },
        )
        record = harness.execute_pilot(invocation)
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''        outcomes = ()
        if record.state is ScannerJobState.COMPLETED:
            pipeline = EvidenceVerificationPipeline(
''',
        '''        outcomes = ()
        if record.state is ScannerJobState.COMPLETED:
            self._activity(
                job.job_id,
                "evaluation_started",
                "Scanner observations are being normalized and verified against persisted evidence.",
                "evaluating",
                metadata={"candidate_observations": len(record.observations)},
            )
            pipeline = EvidenceVerificationPipeline(
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''            outcomes = pipeline.process(
                adapter_result,
                campaign_id=invocation.approval.approval_id,
                run_id=job.job_id,
                authorization_reference=invocation.authorization.authorization_id,
                approval_reference=invocation.approval.approval_id,
                action_manifest_sha256=invocation.plan.plan_digest,
                target_reference=invocation.plan.exact_targets[0].url,
                adapter_version=(
                    self.compatibility_manifest.get("nuclei").version_pin.adapter_version
                ),
                tool_version=invocation.readiness.engine_version,
                recorded_by=invocation.actor_id,
            )
        self._project_run_state(
''',
        '''            outcomes = pipeline.process(
                adapter_result,
                campaign_id=invocation.approval.approval_id,
                run_id=job.job_id,
                authorization_reference=invocation.authorization.authorization_id,
                approval_reference=invocation.approval.approval_id,
                action_manifest_sha256=invocation.plan.plan_digest,
                target_reference=invocation.plan.exact_targets[0].url,
                adapter_version=(
                    self.compatibility_manifest.get("nuclei").version_pin.adapter_version
                ),
                tool_version=invocation.readiness.engine_version,
                recorded_by=invocation.actor_id,
            )
            self._activity(
                job.job_id,
                "evaluation_completed",
                f"Evidence verification completed with {len(outcomes)} persisted finding outcome(s).",
                "evaluating",
                metadata={"unified_findings": len(outcomes)},
            )
        self._project_run_state(
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=self.clock(),
            event_type=event_type,
            summary=summary,
            run_state=run_state,
            source="tool",
            metadata=metadata or {},
        )
''',
        '''        execution_state = {
            "tool_execution_started": "running",
            "tool_progress": "running",
            "tool_execution_completed": "succeeded",
            "tool_execution_failed": "failed",
            "evaluation_started": "running",
            "evaluation_completed": "succeeded",
        }.get(event_type, "not_started")
        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=self.clock(),
            event_type=event_type,
            summary=summary,
            run_state=run_state,
            source="tool",
            tool_id="nuclei",
            execution_state=execution_state,
            metadata=metadata or {},
        )
''',
    )

    stream_path = Path("vulnhunter/web/stream_views.py")
    stream_text = stream_path.read_text(encoding="utf-8")
    marker = "def _event_stream(*, sequence: int, payload: dict[str, object]) -> Iterator[str]:\n"
    helper = '''def _active_summary(run) -> str:
    """Return a safe operational explanation, never hidden chain-of-thought."""

    state = getattr(run, "workflow_state", None) or run.current_state
    summaries = {
        "authorization_required": "Checking the active authorization boundary.",
        "scope_validated": "Scope is valid; checking local scanner readiness.",
        "readiness_checked": "Pinned scanner readiness passed; building the immutable plan.",
        "plan_generated": "The plan is ready and waiting for an independent approval.",
        "awaiting_approval": "Waiting for a separate approver to review the exact plan digest.",
        "queued": "The approved job is queued for the isolated Nuclei worker.",
        "running": "The isolated worker is processing the approved passive assessment.",
        "executing": "Nuclei is running the reviewed passive template.",
        "evaluating": "Scanner evidence is being normalized and verified.",
        "completed": "The assessment completed and persisted its evidence-backed results.",
        "failed": "The assessment failed closed; inspect the activity and audit evidence.",
        "timed_out": "The worker reached its immutable timeout and stopped safely.",
        "cancelled": "The assessment was cancelled and no further scanner work will run.",
        "blocked": "A governance or readiness gate blocked execution.",
        "execution_blocked": "Approval was recorded, but worker activation remains unavailable.",
        "readiness_blocked": "Scanner readiness did not pass, so no job was created.",
        "denied": "The exact plan was denied and will not execute.",
    }
    return summaries.get(
        str(state),
        getattr(run, "execution_blocking_reason", None)
        or "Waiting for the next persisted assessment transition.",
    )


'''
    if marker not in stream_text:
        raise SystemExit("Stream helper insertion point was not found")
    stream_text = stream_text.replace(marker, helper + marker, 1)
    old_payload = '''            "run_id": run.run_id,
            "run_state": run.current_state,
            "approval_state": run.approval_state.value,
'''
    new_payload = '''            "run_id": run.run_id,
            "task_state": run.current_state,
            "run_state": payload.get("run_state") or run.current_state,
            "active_summary": _active_summary(run),
            "approval_state": run.approval_state.value,
'''
    if old_payload not in stream_text:
        raise SystemExit("Stream payload block was not found")
    stream_path.write_text(stream_text.replace(old_payload, new_payload, 1), encoding="utf-8")

    replace_once(
        "vulnhunter/web/static/web/activity.js",
        '''      awaiting_approval: 52,
      approved: 60,
      execution_blocked: 60,
      readiness_blocked: 35,
      denied: 52,
''',
        '''      awaiting_approval: 52,
      approved: 60,
      queued: 68,
      running: 74,
      executing: 78,
      evaluating: 88,
      completed: 100,
      failed: 100,
      timed_out: 100,
      cancelled: 100,
      execution_blocked: 60,
      readiness_blocked: 35,
      denied: 52,
''',
    )
    replace_once(
        "vulnhunter/web/static/web/activity.js",
        '''    if (payload.execution_state === "tool_executed") return 78;
    if (payload.approval_state === "pending") return 52;
''',
        '''    if (["completed", "succeeded", "tool_executed"].includes(payload.execution_state)) {
      return 100;
    }
    if (["running", "queued"].includes(payload.execution_state)) return 78;
    if (payload.approval_state === "pending") return 52;
''',
    )

    replace_once(
        "vulnhunter/web/templates/web/agent_run_detail.html",
        '''        <li class="vh-stage {% if run.execution_state == 'tool_executed' %}is-complete{% elif run.execution_state == 'tool_failed' %}is-danger{% elif run.execution_enabled %}is-active{% else %}is-warning{% endif %}">
          <span class="vh-stage-marker">{% if run.execution_state == 'tool_executed' %}✓{% else %}04{% endif %}</span>
''',
        '''        <li class="vh-stage {% if run.workflow_state == 'completed' or run.execution_state == 'tool_executed' %}is-complete{% elif run.workflow_state == 'failed' or run.workflow_state == 'timed_out' or run.execution_state == 'tool_failed' %}is-danger{% elif run.workflow_state == 'queued' or run.workflow_state == 'executing' or run.execution_enabled %}is-active{% else %}is-warning{% endif %}">
          <span class="vh-stage-marker">{% if run.workflow_state == 'completed' or run.execution_state == 'tool_executed' %}✓{% else %}04{% endif %}</span>
''',
    )
    replace_once(
        "vulnhunter/web/templates/web/agent_run_detail.html",
        '''            <summary><span class="vh-stage-number">04</span><span class="vh-stage-copy"><strong>Scanner — {{ run.requested_tool|default:"Not selected" }}</strong><small>{{ run.execution_blocking_reason|default:"No scanner state recorded." }}</small></span><span class="vh-stage-state">{{ run.execution_state }}</span><svg class="vh-stage-chevron"><use href="#vh-i-chevron"></use></svg></summary>
''',
        '''            <summary><span class="vh-stage-number">04</span><span class="vh-stage-copy"><strong>Scanner — {{ run.requested_tool|default:"Not selected" }}</strong><small>{{ run.execution_blocking_reason|default:"Live worker transitions appear below as they are persisted." }}</small></span><span class="vh-stage-state">{{ run.workflow_state|default:run.execution_state }}</span><svg class="vh-stage-chevron"><use href="#vh-i-chevron"></use></svg></summary>
''',
    )

    Path("tests/unit/test_phone_lab_live_activity.py").write_text(
        '''from types import SimpleNamespace

from vulnhunter.web.stream_views import _active_summary


def test_active_summary_explains_queued_and_evaluating_states_without_private_reasoning():
    queued = SimpleNamespace(
        workflow_state="queued",
        current_state="running",
        execution_blocking_reason=None,
    )
    evaluating = SimpleNamespace(
        workflow_state="evaluating",
        current_state="running",
        execution_blocking_reason=None,
    )

    assert "queued" in _active_summary(queued).lower()
    assert "verified" in _active_summary(evaluating).lower()
''',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
