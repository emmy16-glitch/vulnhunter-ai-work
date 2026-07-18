from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block missing from {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def append_once(relative: str, marker: str, addition: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if addition.strip() in text:
        return
    if marker not in text:
        raise RuntimeError(f"append marker missing from {relative}")
    path.write_text(text + addition, encoding="utf-8")


def main() -> None:
    replace_once(
        "tests/unit/test_provider_runtime.py",
        "GroqProvider(transport=_groq_transport())",
        'GroqProvider(api_key="test-key", transport=_groq_transport())',
    )
    replace_once(
        "tests/unit/test_security_tool_governance.py",
        """        "bearer",
        "greenbone",
        "amass",
""",
        """        "bearer",
        "amass",
""",
    )
    replace_once(
        "tests/unit/test_web_settings.py",
        """def test_resource_safe_local_model_defaults():
    assert settings.VULNHUNTER_OLLAMA_MODEL == "qwen3.5:2b-q4_k_m"
    assert settings.VULNHUNTER_OLLAMA_CONTEXT_TOKENS == 1_024
    assert settings.VULNHUNTER_OLLAMA_TIMEOUT_SECONDS == 600


""",
        """def test_local_model_runtime_has_been_removed():
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_MODEL")
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_CONTEXT_TOKENS")
    assert not hasattr(settings, "VULNHUNTER_OLLAMA_TIMEOUT_SECONDS")


""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        """        harness = NucleiPilotExecutionHarness(
            policy=self.policy,
            store=self.execution_store,
            runner=runner,
            resolver=resolver,
            approved_output_root=self.evidence_store.root,
            compatibility_manifest=self.compatibility_manifest,
        )
        self._activity(job.job_id, "scanner_starting", "Starting isolated passive scan.", "running")
""",
        """        harness = NucleiPilotExecutionHarness(
            policy=self.policy,
            store=self.execution_store,
            runner=runner,
            resolver=resolver,
            approved_output_root=self.evidence_store.root,
            compatibility_manifest=self.compatibility_manifest,
            external_cancellation=lambda: self.spool.cancellation_requested(job.job_id),
        )
        self._activity(
            job.job_id,
            "tool_execution_started",
            "Starting isolated passive scan.",
            "executing",
        )
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        """            "scanner_completed" if record.state is ScannerJobState.COMPLETED else "scanner_failed",
""",
        """            (
                "tool_execution_completed"
                if record.state is ScannerJobState.COMPLETED
                else "tool_execution_failed"
            ),
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        """        workflow = task.memory.get("assessment_workflow")
        if not isinstance(workflow, dict):
            return
        if state is ScannerJobState.COMPLETED:
""",
        """        workflow = task.memory.get("assessment_workflow")
        if not isinstance(workflow, dict):
            return
        if task.status is TaskStatus.CANCELLED and state is not ScannerJobState.CANCELLED:
            state = ScannerJobState.CANCELLED
            finding_count = 0
        if state is ScannerJobState.COMPLETED:
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        """            source="isolated-nuclei-worker",
""",
        """            source="tool",
""",
    )
    replace_once(
        "tests/unit/test_milestone32_worker_pilot.py",
        """    assert [event.event_type for event in feed.events] == [
        "scanner_starting",
        "scanner_completed",
    ]
""",
        """    assert [event.event_type for event in feed.events] == [
        "tool_execution_started",
        "tool_execution_completed",
    ]
""",
    )
    replace_once(
        "tests/unit/test_milestone32_worker_pilot.py",
        """    assert records[0].metadata["verification_status"] in {"verified", "abstain"}
""",
        """    assert records[0].metadata["verification_status"] in {"verified", "abstain"}
    assert records[0].finding_status.value in {"candidate", "validated"}
""",
    )

    replace_once(
        "vulnhunter/security_tools/worker_spool.py",
        """        self.completed = self._directory("completed")
        self.failed = self._directory("failed")
""",
        """        self.completed = self._directory("completed")
        self.failed = self._directory("failed")
        self.cancellations = self._directory("cancellations")
""",
    )
    replace_once(
        "vulnhunter/security_tools/worker_spool.py",
        """    def load_claimed(
        self,
        path: Path,
""",
        """    def request_cancellation(self, job_id: str, *, reason: str, now: datetime) -> str:
        if self.cancel_pending(job_id, reason=reason, now=now):
            return "pending_cancelled"
        marker = self.cancellations / f"{job_id}.json"
        if marker.exists():
            if marker.is_symlink():
                raise WorkerSpoolError("worker cancellation marker is unsafe")
            return "requested"
        safe_reason = " ".join(reason.split())[:500] or "Worker cancellation requested."
        payload = json.dumps(
            {
                "job_id": job_id,
                "reason": safe_reason,
                "requested_at": _utc(now, field="now").isoformat(),
            },
            sort_keys=True,
        )
        self._write_exclusive(marker, payload + "\\n")
        return "requested"

    def cancellation_requested(self, job_id: str) -> bool:
        marker = self.cancellations / f"{job_id}.json"
        if marker.is_symlink():
            raise WorkerSpoolError("worker cancellation marker is unsafe")
        return marker.is_file()

    def recover_processing(self, *, now: datetime) -> tuple[Path, ...]:
        recovered: list[Path] = []
        for claimed in sorted(self.processing.glob("*.json")):
            recovered.append(
                self.reject(
                    claimed,
                    reason="Claimed worker job recovered fail-closed after restart.",
                    now=now,
                )
            )
        return tuple(recovered)

    def load_claimed(
        self,
        path: Path,
""",
    )
    replace_once(
        "vulnhunter/security_tools/worker_spool.py",
        """        self._write_exclusive(receipt_path, receipt.model_dump_json(indent=2) + "\\n")
        os.replace(claimed_path, destination)
        return destination
""",
        """        self._write_exclusive(receipt_path, receipt.model_dump_json(indent=2) + "\\n")
        os.replace(claimed_path, destination)
        (self.cancellations / f"{claimed_path.stem}.json").unlink(missing_ok=True)
        return destination
""",
    )

    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """class NucleiPilotExecutionHarness(NucleiExecutionHarness):
""",
        """class _PilotRunControl(_StoreAwareRunControl):
    def __init__(self, *, external_cancellation: Callable[[], bool], **kwargs) -> None:
        super().__init__(**kwargs)
        self._external_cancellation = external_cancellation

    def checkpoint(self, *, process_group_id: int | None = None) -> None:
        if self._external_cancellation():
            self.cancel("External worker cancellation requested.")
        super().checkpoint(process_group_id=process_group_id)


class NucleiPilotExecutionHarness(NucleiExecutionHarness):
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """        policy: NucleiPilotPolicy,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        **kwargs,
    ) -> None:
""",
        """        policy: NucleiPilotPolicy,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        external_cancellation: Callable[[], bool] = lambda: False,
        **kwargs,
    ) -> None:
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """        self.policy = policy
        self.clock = clock
""",
        """        self.policy = policy
        self.clock = clock
        self.external_cancellation = external_cancellation
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """        if not self.policy.enabled:
            return self.store.transition(
""",
        """        if self.external_cancellation():
            return self.store.transition(
                request.execution_id,
                ScannerJobState.CANCELLED,
                actor_id=invocation.actor_id,
                reason="External worker cancellation was already requested.",
                now=self.clock(),
            )
        if not self.policy.enabled:
            return self.store.transition(
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """        acquired = self._slots.acquire(blocking=False)
""",
        """        if self.external_cancellation():
            return self.store.transition(
                request.execution_id,
                ScannerJobState.CANCELLED,
                actor_id=invocation.actor_id,
                reason="External worker cancellation was requested before process start.",
                now=self.clock(),
            )
        acquired = self._slots.acquire(blocking=False)
""",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        """        control = _StoreAwareRunControl(
""",
        """        control = _PilotRunControl(
            external_cancellation=self.external_cancellation,
""",
    )

    replace_once(
        "vulnhunter/web/services.py",
        """from vulnhunter.repository_graph import GraphifyAdapter, GraphifyAdapterError
from vulnhunter.roles import RoleRegistry
""",
        """from vulnhunter.repository_graph import GraphifyAdapter, GraphifyAdapterError
from vulnhunter.roles import RoleRegistry
from vulnhunter.security_tools.nuclei_execution import (
    NucleiExecutionError,
    NucleiExecutionStore,
)
from vulnhunter.security_tools.worker_spool import SignedWorkerSpool, WorkerSpoolError
""",
    )
    replace_once(
        "vulnhunter/web/services.py",
        """    activity = activity_service()
    stop_request = activity.request_stop(
        run_id=run_id,
        timestamp=datetime.now(UTC),
        actor_id=actor.governance_identity.reviewer_id,
        reason=reason,
    )
    controller = AgentController(
        AgentRuntime(
            config=load_runtime_config(Path(settings.VULNHUNTER_RUNTIME_CONFIG)),
            store=AgentStore.open_existing(Path(settings.VULNHUNTER_AGENT_DATABASE)),
""",
        """    now = datetime.now(UTC)
    activity = activity_service()
    stop_request = activity.request_stop(
        run_id=run_id,
        timestamp=now,
        actor_id=actor.governance_identity.reviewer_id,
        reason=reason,
    )
    agent_store = AgentStore.open_existing(Path(settings.VULNHUNTER_AGENT_DATABASE))
    try:
        task = agent_store.get_task(run_id)
    except AgentStoreError as exc:
        raise WebCapabilityUnavailable("The run could not be loaded for cancellation.") from exc
    workflow = task.memory.get("assessment_workflow")
    if isinstance(workflow, dict):
        try:
            SignedWorkerSpool(
                Path(settings.VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT)
            ).request_cancellation(run_id, reason=reason, now=now)
        except WorkerSpoolError as exc:
            raise WebCapabilityUnavailable(
                "The worker cancellation request could not be recorded safely."
            ) from exc
        execution_id = workflow.get("execution_id")
        if isinstance(execution_id, str) and execution_id:
            try:
                NucleiExecutionStore(
                    Path(settings.VULNHUNTER_NUCLEI_EXECUTION_ROOT)
                ).request_cancellation(
                    execution_id,
                    reason=reason,
                    actor_id=actor.governance_identity.reviewer_id,
                    now=now,
                )
            except NucleiExecutionError:
                pass
    controller = AgentController(
        AgentRuntime(
            config=load_runtime_config(Path(settings.VULNHUNTER_RUNTIME_CONFIG)),
            store=agent_store,
""",
    )

    replace_once(
        "vulnhunter/web/management/commands/vh_run_nuclei_worker.py",
        """from pathlib import Path
""",
        """from datetime import UTC, datetime
from pathlib import Path
""",
    )
    replace_once(
        "vulnhunter/web/management/commands/vh_run_nuclei_worker.py",
        """            service = NucleiPilotWorkerService(
                spool=SignedWorkerSpool(spool_root),
""",
        """            now = datetime.now(UTC)
            spool = SignedWorkerSpool(spool_root)
            execution_store = NucleiExecutionStore(execution_root)
            spool.recover_processing(now=now)
            execution_store.recover_unfinished(actor_id=policy.worker_id, now=now)
            service = NucleiPilotWorkerService(
                spool=spool,
""",
    )
    replace_once(
        "vulnhunter/web/management/commands/vh_run_nuclei_worker.py",
        """                execution_store=NucleiExecutionStore(execution_root),
""",
        """                execution_store=execution_store,
""",
    )

    append_once(
        "tests/unit/test_milestone32_worker_pilot.py",
        "def test_mobile_static_worker_uses_read_only_copy_and_fixed_tool",
        """


def test_worker_spool_cancels_pending_and_recovers_claimed_jobs(tmp_path):
    invocation = _invocation(tmp_path)
    key = b"r" * 32
    spool = SignedWorkerSpool(tmp_path / "recovery-spool")
    pending = SignedNucleiWorkerJob.create(
        job_id="assessment-pending",
        invocation=invocation,
        key=key,
        created_at=NOW,
    )
    spool.enqueue(pending)
    assert (
        spool.request_cancellation(
            "assessment-pending",
            reason="Operator requested stop.",
            now=NOW + timedelta(seconds=1),
        )
        == "pending_cancelled"
    )
    assert not (spool.pending / "assessment-pending.json").exists()
    assert (spool.failed / "assessment-pending.receipt.json").is_file()

    claimed_job = SignedNucleiWorkerJob.create(
        job_id="assessment-recovery",
        invocation=invocation,
        key=key,
        created_at=NOW,
    )
    spool.enqueue(claimed_job)
    claimed = spool.claim_next()
    assert claimed is not None
    spool.request_cancellation(
        "assessment-recovery",
        reason="Stop claimed job.",
        now=NOW + timedelta(seconds=2),
    )
    assert spool.cancellation_requested("assessment-recovery") is True
    recovered = spool.recover_processing(now=NOW + timedelta(seconds=3))
    assert len(recovered) == 1
    assert recovered[0].parent == spool.failed
    assert not spool.cancellation_requested("assessment-recovery")
""",
    )


if __name__ == "__main__":
    main()
