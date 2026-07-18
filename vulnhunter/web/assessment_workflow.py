"""Connect the web assessment workflow to existing governed stores.

The service in this module plans only.  It has no subprocess adapter, accepts no
command arguments, and performs no network resolution.  A resolver must be
injected explicitly; the web composition root uses the authorization's frozen
address snapshot and therefore cannot cause an external DNS request.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from django.conf import settings
from pydantic import BaseModel, ConfigDict

from vulnhunter.agent.models import AgentTask, PermissionManifest, TaskStatus, ToolRisk
from vulnhunter.agent.store import AgentStore, AgentStoreError
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.approvals.models import ApprovalRequest
from vulnhunter.approvals.store import ApprovalStore, ApprovalStoreError
from vulnhunter.authorization.models import AuthorizationRecord
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.security import redact_text
from vulnhunter.security_tools.nuclei_pilot_service import (
    NucleiPilotServiceError,
    build_approved_pilot_job,
)
from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest
from vulnhunter.security_tools.worker_spool import (
    SignedWorkerSpool,
    WorkerSpoolError,
    load_worker_signing_key,
)
from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiActivationError,
    NucleiCommandPlan,
    NucleiTemplateManifest,
    ScopedNucleiTarget,
    TemplateApprovalLevel,
    TemplateRiskClass,
    validate_evidence_directory,
    validate_nuclei_target_scope,
)

ScanProfile = Literal["passive", "standard", "intrusive", "retest"]
_PROHIBITED_ACTIONS = (
    "automatic-updates",
    "cloud-upload",
    "public-oast",
    "raw-command-arguments",
)
_PROFILE_APPROVAL = {
    "passive": TemplateApprovalLevel.REVIEWED,
    "standard": TemplateApprovalLevel.EXPLICIT,
    "intrusive": TemplateApprovalLevel.INTRUSIVE,
    "retest": TemplateApprovalLevel.EXPLICIT,
}
_PROFILE_RISK = {
    "passive": TemplateRiskClass.PASSIVE,
    "standard": TemplateRiskClass.STANDARD,
    "intrusive": TemplateRiskClass.INTRUSIVE,
    "retest": TemplateRiskClass.STANDARD,
}


class AssessmentWorkflowError(RuntimeError):
    """Raised when the governed assessment workflow fails closed."""


class NucleiReadiness(BaseModel):
    """Safe, read-only projection of a locally produced readiness report."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    ready: bool = False
    installed: bool = False
    expected_engine: str = "v3.11.0"
    expected_templates: str = "v10.4.5"
    engine_pin_matches: bool = False
    templates_pin_matches: bool = False
    execution_enabled: Literal[False] = False
    reason: str = "A verified local readiness report is not available."

    @property
    def verified(self) -> bool:
        return bool(
            self.ready
            and self.installed
            and self.engine_pin_matches
            and self.templates_pin_matches
            and self.expected_engine == "v3.11.0"
            and self.expected_templates == "v10.4.5"
        )


class AuthorizationChoice(BaseModel):
    """Minimum safe authorization fields exposed to the assessment modal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_id: str
    display_label: str
    expires_at: datetime
    approved_targets: tuple[str, ...]
    approved_protocols: tuple[str, ...]
    approved_ports: tuple[int, ...]
    approved_profiles: tuple[str, ...]


@dataclass(frozen=True)
class AssessmentCreationResult:
    task: AgentTask
    approval_request: ApprovalRequest | None


def bind_nuclei_authorization(
    store: AuthorizationStore,
    *,
    authorization_id: str,
    approved_profiles: tuple[ScanProfile, ...],
    private_network_approved: bool,
    recorded_by: str,
    approval_basis: str,
    now: datetime | None = None,
) -> EngagementAuthorization:
    """Append one immutable Milestone 29 binding to the authorization ledger."""

    record = store.get(authorization_id)
    instant = (now or datetime.now(UTC)).astimezone(UTC)
    starts_at = max(record.valid_from, instant)
    if starts_at >= record.expires_at:
        raise AssessmentWorkflowError("An expired authorization cannot receive a Nuclei binding.")
    engagement = EngagementAuthorization.issue(
        authorization_id=record.authorization_id,
        target_owner=record.owner,
        approving_person=record.approved_by,
        approved_targets=(record.target_url,),
        approved_addresses=record.approved_addresses,
        approved_ports=(record.port,),
        approved_protocols=(record.scheme,),
        approved_scan_profiles=approved_profiles,
        starts_at=starts_at,
        expires_at=record.expires_at,
        private_network_approved=private_network_approved,
        prohibited_actions=_PROHIBITED_ACTIONS,
        audit={
            "recorded_at": instant,
            "recorded_by": recorded_by,
            "approval_basis": approval_basis,
            "previous_record_sha256": record.record_sha256,
        },
    )
    store.append_event(
        authorization_id,
        "nuclei_activation_bound",
        {
            "source_record_sha256": record.record_sha256,
            "engagement_record": engagement.model_dump(mode="json"),
        },
    )
    return engagement


def load_nuclei_authorization(
    store: AuthorizationStore,
    authorization_id: str,
) -> tuple[AuthorizationRecord, EngagementAuthorization]:
    """Load the newest valid activation binding for one authorization."""

    record = store.get(authorization_id)
    for event in store.list_events(authorization_id):
        if event.event_type != "nuclei_activation_bound":
            continue
        if event.detail.get("source_record_sha256") != record.record_sha256:
            raise AssessmentWorkflowError(
                "The Nuclei binding does not match the current authorization record."
            )
        try:
            engagement = EngagementAuthorization.model_validate(
                event.detail.get("engagement_record")
            )
        except (TypeError, ValueError) as exc:
            raise AssessmentWorkflowError("The Nuclei authorization binding is invalid.") from exc
        if engagement.authorization_id != record.authorization_id:
            raise AssessmentWorkflowError("The Nuclei binding references another authorization.")
        return record, engagement
    raise AssessmentWorkflowError("No reviewed Nuclei activation binding exists.")


def _actor_can_use(record: AuthorizationRecord, *, identity_id: str, username: str) -> bool:
    permitted = {identity_id.strip().casefold(), username.strip().casefold()}
    return record.owner.strip().casefold() in permitted


def _load_readiness(path: Path) -> NucleiReadiness:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return NucleiReadiness()
    try:
        return NucleiReadiness.model_validate(payload)
    except ValueError:
        return NucleiReadiness(reason="The local readiness report is invalid.")


class AssessmentWorkflowService:
    """Create governed assessment plans and record decisions without execution."""

    def __init__(
        self,
        *,
        authorization_store: AuthorizationStore,
        agent_store: AgentStore,
        approval_store: ApprovalStore,
        activity_service: AgentActivityService,
        profile_config: Path,
        template_manifest: Path,
        template_root: Path,
        evidence_root: Path,
        readiness_report: Path,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.authorization_store = authorization_store
        self.agent_store = agent_store
        self.approval_store = approval_store
        self.activity_service = activity_service
        self.profile_config = profile_config
        self.template_manifest_path = template_manifest
        self.template_root = template_root
        self.evidence_root = evidence_root
        self.readiness_report = readiness_report
        self.clock = clock
        self.authorization_store.initialize()
        self.approval_store.initialize()

    @classmethod
    def from_settings(cls) -> AssessmentWorkflowService:
        return cls(
            authorization_store=AuthorizationStore.from_path(
                Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)
            ),
            agent_store=AgentStore(Path(settings.VULNHUNTER_AGENT_DATABASE)),
            approval_store=ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE)),
            activity_service=AgentActivityService(
                AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
            ),
            profile_config=Path(settings.VULNHUNTER_NUCLEI_PROFILE_CONFIG),
            template_manifest=Path(settings.VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST),
            template_root=Path(settings.VULNHUNTER_NUCLEI_TEMPLATE_ROOT),
            evidence_root=Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT),
            readiness_report=Path(settings.VULNHUNTER_NUCLEI_READINESS_REPORT),
        )

    def list_authorizations(
        self,
        *,
        identity_id: str,
        username: str,
    ) -> tuple[AuthorizationChoice, ...]:
        now = self.clock().astimezone(UTC)
        choices: list[AuthorizationChoice] = []
        for record in self.authorization_store.list(limit=250):
            if (
                record.status != "active"
                or now < record.valid_from
                or now >= record.expires_at
                or not _actor_can_use(record, identity_id=identity_id, username=username)
            ):
                continue
            try:
                _, engagement = load_nuclei_authorization(
                    self.authorization_store, record.authorization_id
                )
                engagement.require_active(now=now)
            except (AssessmentWorkflowError, NucleiActivationError):
                continue
            choices.append(
                AuthorizationChoice(
                    authorization_id=record.authorization_id,
                    display_label=f"{record.hostname}:{record.port}{record.path_boundary}",
                    expires_at=engagement.expires_at,
                    approved_targets=engagement.approved_targets,
                    approved_protocols=engagement.approved_protocols,
                    approved_ports=engagement.approved_ports,
                    approved_profiles=engagement.approved_scan_profiles,
                )
            )
        return tuple(choices)

    def create_assessment(
        self,
        *,
        authorization_id: str,
        target: str,
        protocol: str,
        port: int,
        profile: str,
        identity_id: str,
        username: str,
        resolver: Callable[[str], Iterable[str]] | None = None,
    ) -> AssessmentCreationResult:
        now = self.clock().astimezone(UTC)
        record, engagement = load_nuclei_authorization(self.authorization_store, authorization_id)
        if not _actor_can_use(record, identity_id=identity_id, username=username):
            raise AssessmentWorkflowError("This authorization is not available to the actor.")
        engagement.require_active(now=now)
        if profile not in engagement.approved_scan_profiles:
            raise AssessmentWorkflowError("The selected profile is not authorized.")
        if protocol not in engagement.approved_protocols or port not in engagement.approved_ports:
            raise AssessmentWorkflowError("The selected protocol or port is not authorized.")
        try:
            parsed_port = urlsplit(target).port
        except ValueError as exc:
            raise AssessmentWorkflowError("The selected target is malformed.") from exc
        parsed = urlsplit(target)
        effective_port = parsed_port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != protocol or effective_port != port:
            raise AssessmentWorkflowError("The selected target, protocol and port disagree.")
        fixed_resolver = resolver or (lambda _hostname: record.approved_addresses)
        try:
            scoped_target = validate_nuclei_target_scope(
                target,
                authorization=engagement,
                resolver=fixed_resolver,
                now=now,
            )
        except NucleiActivationError as exc:
            raise AssessmentWorkflowError(str(exc)) from exc

        run_id = f"assessment-{uuid4().hex[:16]}"
        readiness = _load_readiness(self.readiness_report)
        if not readiness.verified:
            task = self._create_task(
                run_id=run_id,
                record=record,
                engagement=engagement,
                scoped_target=scoped_target,
                profile=profile,
                identity_id=identity_id,
                status=TaskStatus.BLOCKED,
                workflow_state="readiness_blocked",
                plan=None,
                readiness=readiness,
                blocking_reason=readiness.reason,
            )
            self._record_transition(
                task,
                previous_state="scope_validated",
                new_state="readiness_blocked",
                reason=readiness.reason,
                event_type="run_blocked",
                run_state="blocked",
            )
            return AssessmentCreationResult(task=task, approval_request=None)

        manifest = self._load_template_manifest()
        selected_ids = tuple(
            entry.template_id
            for entry in manifest.entries
            if entry.enabled and entry.risk_class == _PROFILE_RISK[profile]
        )
        try:
            manifest_hashes = manifest.validate_selection(
                selected_ids,
                template_root=self.template_root,
                approval_level=_PROFILE_APPROVAL[profile],
            )
        except (OSError, ValueError, NucleiActivationError) as exc:
            raise AssessmentWorkflowError(str(exc)) from exc

        self.evidence_root.mkdir(parents=True, exist_ok=True)
        output_directory = self.evidence_root / run_id
        output_directory.mkdir(mode=0o700)
        try:
            validated_output = validate_evidence_directory(
                output_directory,
                approved_root=self.evidence_root,
            )
            rate_limit, concurrency = self._profile_limits(profile)
            plan = NucleiCommandPlan.create(
                authorization_id=engagement.authorization_id,
                exact_targets=(scoped_target,),
                exact_profile=profile,
                template_manifest_hashes=manifest_hashes,
                output_directory=validated_output,
                rate_limit=rate_limit,
                concurrency=concurrency,
                expires_at=min(engagement.expires_at, now + timedelta(minutes=15)),
                requires_isolation=profile == "intrusive",
            )
        except (OSError, ValueError, NucleiActivationError) as exc:
            output_directory.rmdir()
            raise AssessmentWorkflowError(str(exc)) from exc

        task = self._create_task(
            run_id=run_id,
            record=record,
            engagement=engagement,
            scoped_target=scoped_target,
            profile=profile,
            identity_id=identity_id,
            status=TaskStatus.PAUSED_APPROVAL,
            workflow_state="awaiting_approval",
            plan=plan,
            readiness=readiness,
            blocking_reason="Human approval of the exact command-plan digest is required.",
        )
        approval = ApprovalRequest(
            request_id=f"approval-{uuid4().hex[:16]}",
            campaign_id=f"assessment-{uuid4().hex[:12]}",
            run_id=run_id,
            action_manifest_sha256=plan.plan_digest,
            requested_by=identity_id,
            summary="Approve the exact governed Nuclei command plan.",
            risk_summary=(
                "Intrusive isolated plan; external execution remains globally disabled."
                if profile == "intrusive"
                else "Reviewed plan; external execution remains globally disabled."
            ),
            requested_at=now,
            expires_at=plan.expires_at,
        )
        try:
            self.approval_store.create(approval)
        except ApprovalStoreError as exc:
            blocked = task.evolved(
                status=TaskStatus.BLOCKED,
                paused_reason="Approval request could not be recorded safely.",
                memory={**task.memory, "workflow_state": "approval_blocked"},
            )
            self.agent_store.save_task(blocked, expected_revision=task.revision)
            raise AssessmentWorkflowError("Approval request could not be recorded safely.") from exc
        self.agent_store.append_event(
            run_id,
            "approval.required",
            {
                "request_id": approval.request_id,
                "plan_digest": plan.plan_digest,
                "expires_at": approval.expires_at.isoformat(),
            },
        )
        self._record_transition(
            task,
            previous_state="plan_generated",
            new_state="awaiting_approval",
            reason="Exact human approval is required before any future execution.",
            event_type="approval_requested",
            run_state="awaiting_approval",
        )
        return AssessmentCreationResult(task=task, approval_request=approval)

    def record_approval_decision(
        self,
        *,
        request: ApprovalRequest,
        actor_id: str,
    ) -> AgentTask | None:
        """Project a real approval decision into the authoritative run state."""

        try:
            task = self.agent_store.get_task(request.run_id)
        except AgentStoreError:
            return None
        workflow = task.memory.get("assessment_workflow")
        if not isinstance(workflow, dict):
            return None
        plan_payload = workflow.get("command_plan")
        if not isinstance(plan_payload, dict):
            raise AssessmentWorkflowError("The assessment command plan is missing.")
        try:
            plan = NucleiCommandPlan.model_validate(plan_payload)
        except ValueError as exc:
            raise AssessmentWorkflowError("The assessment command plan is invalid.") from exc
        if request.action_manifest_sha256 != plan.plan_digest:
            raise AssessmentWorkflowError("Approval does not reference the current plan digest.")
        now = self.clock().astimezone(UTC)
        if now >= plan.expires_at:
            raise AssessmentWorkflowError("The command plan has expired.")

        approved = request.decision is not None and request.decision.value.startswith("approve_")
        queued_job = None
        queue_error = None
        if (
            approved
            and plan.exact_profile == "passive"
            and getattr(settings, "VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED", False)
        ):
            try:
                signing_key = load_worker_signing_key(
                    Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)
                )
                compatibility = ScannerCompatibilityManifest.load(
                    Path(settings.VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST)
                )
                compatibility.verify_repository_manifests(Path(settings.BASE_DIR))
                queued_job = build_approved_pilot_job(
                    task=task,
                    approval_request=request,
                    authorization_store=self.authorization_store,
                    compatibility_manifest=compatibility,
                    signing_key=signing_key,
                    actor_id=actor_id,
                    now=now,
                )
                SignedWorkerSpool(
                    Path(settings.VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT)
                ).enqueue(queued_job)
            except (
                OSError,
                ValueError,
                NucleiPilotServiceError,
                WorkerSpoolError,
            ) as exc:
                queue_error = type(exc).__name__
        if queued_job is not None:
            new_state = "queued"
            new_status = TaskStatus.RUNNING
            reason = "Approved passive plan queued for the isolated Nuclei worker."
        elif approved:
            new_state = "execution_blocked"
            new_status = TaskStatus.BLOCKED
            reason = (
                "Approval recorded; the isolated Nuclei worker remains disabled."
                if queue_error is None
                else "Approval recorded; worker queue activation failed closed."
            )
        else:
            new_state = "denied"
            new_status = TaskStatus.CANCELLED
            reason = "The exact command plan was denied by a human approver."
        updated = task.evolved(
            status=new_status,
            paused_reason=None if queued_job is not None else reason,
            memory={
                **task.memory,
                "assessment_workflow": {
                    **workflow,
                    "workflow_state": new_state,
                    "approval_state": "approved" if approved else "denied",
                    "decision_actor": actor_id,
                    "execution_enabled": False,
                    "execution_id": (
                        queued_job.invocation.request.execution_id if queued_job else None
                    ),
                    "queue_error": queue_error,
                    "blocking_reason": None if queued_job is not None else reason,
                },
            },
        )
        self.agent_store.save_task(updated, expected_revision=task.revision)
        event = self.agent_store.append_event(
            task.task_id,
            "approval.recorded",
            {
                "request_id": request.request_id,
                "plan_digest": plan.plan_digest,
                "decision": request.decision.value if request.decision else "unknown",
                "actor": actor_id,
                "execution_enabled": False,
                "pilot_queued": queued_job is not None,
                "queue_error": queue_error,
            },
        )
        self._record_transition(
            updated,
            previous_state=str(workflow.get("workflow_state", "awaiting_approval")),
            new_state=new_state,
            reason=reason,
            event_type=(
                "scanner_queued"
                if queued_job is not None
                else "run_blocked" if approved else "approval_rejected"
            ),
            run_state=("queued" if queued_job is not None else "blocked" if approved else "cancelled"),
            audit_reference=event.event_sha256,
        )
        return updated

    def validate_approval_binding(
        self,
        *,
        request: ApprovalRequest,
        submitted_plan_digest: str,
    ) -> None:
        """Reject browser-modified or stale digests before recording a decision."""

        try:
            task = self.agent_store.get_task(request.run_id)
        except AgentStoreError:
            return
        workflow = task.memory.get("assessment_workflow")
        if not isinstance(workflow, dict):
            return
        plan_payload = workflow.get("command_plan")
        if not isinstance(plan_payload, dict):
            raise AssessmentWorkflowError("The assessment command plan is missing.")
        try:
            plan = NucleiCommandPlan.model_validate(plan_payload)
        except ValueError as exc:
            raise AssessmentWorkflowError("The assessment command plan is invalid.") from exc
        if (
            submitted_plan_digest != plan.plan_digest
            or request.action_manifest_sha256 != plan.plan_digest
        ):
            raise AssessmentWorkflowError("Approval does not reference the current plan digest.")
        if self.clock().astimezone(UTC) >= plan.expires_at:
            raise AssessmentWorkflowError("The command plan has expired.")

    def _load_template_manifest(self) -> NucleiTemplateManifest:
        try:
            return NucleiTemplateManifest.model_validate_json(
                self.template_manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise AssessmentWorkflowError("The reviewed template manifest is unavailable.") from exc

    def _profile_limits(self, profile: str) -> tuple[int, int]:
        try:
            payload = json.loads(self.profile_config.read_text(encoding="utf-8"))
            profile_payload = payload["profiles"][profile]
            rate_limit = int(profile_payload["rate_limit"])
            concurrency = int(profile_payload["concurrency"])
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise AssessmentWorkflowError("The governed Nuclei profile is invalid.") from exc
        if not 1 <= rate_limit <= 10 or not 1 <= concurrency <= 2:
            raise AssessmentWorkflowError("The governed Nuclei profile exceeds runtime limits.")
        return rate_limit, concurrency

    def _create_task(
        self,
        *,
        run_id: str,
        record: AuthorizationRecord,
        engagement: EngagementAuthorization,
        scoped_target: ScopedNucleiTarget,
        profile: str,
        identity_id: str,
        status: TaskStatus,
        workflow_state: str,
        plan: NucleiCommandPlan | None,
        readiness: NucleiReadiness,
        blocking_reason: str,
    ) -> AgentTask:
        now = self.clock().astimezone(UTC)
        correlation_id = f"correlation-{uuid4().hex[:16]}"
        workflow: dict[str, Any] = {
            "schema_version": "1.0",
            "workflow_state": workflow_state,
            "authorization_id": engagement.authorization_id,
            "authorization_record_sha256": record.record_sha256,
            "target": scoped_target.model_dump(mode="json"),
            "profile": profile,
            "command_plan": plan.model_dump(mode="json") if plan else None,
            "plan_digest": plan.plan_digest if plan else None,
            "readiness": readiness.model_dump(mode="json"),
            "execution_enabled": False,
            "blocking_reason": redact_text(blocking_reason)[:500],
            "correlation_id": correlation_id,
            "requested_by": identity_id,
            "approval_state": "pending" if plan else "not_requested",
        }
        task = AgentTask(
            task_id=run_id,
            objective=(
                f"Governed Nuclei assessment for {scoped_target.hostname}{scoped_target.path}"
            ),
            status=status,
            permission_manifest=PermissionManifest(
                manifest_id=f"manifest-{uuid4().hex[:16]}",
                role_id="orchestrator",
                skill_id="bounded-task-routing",
                allowed_actions=("security-tool.plan",),
                allowed_tools=("nuclei.plan",),
                allowed_risks=(ToolRisk.READ_ONLY,),
                approval_required_actions=("security-tool.plan",),
                maximum_runtime_seconds=min(
                    86_400,
                    max(1, int((engagement.expires_at - now).total_seconds())),
                ),
            ),
            memory={
                "assessment_workflow": workflow,
                "input_summary": "Exact authorization-bound assessment request.",
                "scope_summary": scoped_target.url,
            },
            paused_reason=blocking_reason,
            created_at=now,
            updated_at=now,
        )
        self.agent_store.create_task(task)
        created = self.agent_store.append_event(
            run_id,
            "task.created",
            {
                "authorization_id": engagement.authorization_id,
                "workflow_state": workflow_state,
                "correlation_id": correlation_id,
                "execution_enabled": False,
            },
            created_at=now,
        )
        self.agent_store.append_event(
            run_id,
            "policy.decided",
            {
                "status": "requires_approval" if plan else "denied",
                "reason": blocking_reason,
                "plan_digest": plan.plan_digest if plan else None,
            },
            created_at=now,
        )
        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=now,
            event_type="run_created",
            summary="A governed assessment record was created.",
            run_state="created",
            source="runtime",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            authorization_reference=engagement.authorization_id,
            audit_reference=created.event_sha256,
            metadata={"correlation_id": correlation_id},
        )
        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=now,
            event_type="authorization_check_passed",
            summary="The active engagement authorization was validated.",
            run_state="checking_authorization",
            source="policy",
            authorization_reference=engagement.authorization_id,
            policy_outcome="allowed",
            metadata={"correlation_id": correlation_id},
        )
        self.activity_service.record_transition(
            run_id=run_id,
            timestamp=now,
            event_type="scope_check_passed",
            summary="The exact target, protocol, port and address set were validated.",
            run_state="checking_scope",
            source="policy",
            scope_reference=scoped_target.url,
            policy_outcome="allowed",
            metadata={"correlation_id": correlation_id},
        )
        if plan:
            self.activity_service.record_transition(
                run_id=run_id,
                timestamp=now,
                event_type="plan_proposed",
                summary="An immutable Nuclei command plan was generated without command text.",
                run_state="checking_policy",
                source="planner",
                tool_id="nuclei",
                approval_requirement="required",
                execution_state="not_started",
                metadata={"plan_digest": plan.plan_digest, "correlation_id": correlation_id},
            )
        self._append_transition_audit(
            task,
            previous_state="draft",
            new_state="authorization_required",
            reason="An active engagement authorization was required.",
        )
        self._append_transition_audit(
            task,
            previous_state="authorization_required",
            new_state="scope_validated",
            reason="Exact target, protocol, port and address scope passed validation.",
        )
        if plan:
            self._append_transition_audit(
                task,
                previous_state="scope_validated",
                new_state="readiness_checked",
                reason="Pinned local readiness evidence passed validation.",
            )
            self._append_transition_audit(
                task,
                previous_state="readiness_checked",
                new_state="plan_generated",
                reason="An immutable command plan was generated from reviewed inputs.",
            )
        return task

    def _append_transition_audit(
        self,
        task: AgentTask,
        *,
        previous_state: str,
        new_state: str,
        reason: str,
    ):
        workflow = task.memory.get("assessment_workflow", {})
        return self.agent_store.append_event(
            task.task_id,
            "assessment.transition",
            {
                "assessment_id": task.task_id,
                "actor": workflow.get("requested_by") if isinstance(workflow, dict) else "system",
                "timestamp": self.clock().astimezone(UTC).isoformat(),
                "previous_state": previous_state,
                "new_state": new_state,
                "reason": redact_text(reason)[:500],
                "authorization_id": (
                    workflow.get("authorization_id") if isinstance(workflow, dict) else None
                ),
                "plan_digest": (
                    workflow.get("plan_digest") if isinstance(workflow, dict) else None
                ),
                "correlation_id": (
                    workflow.get("correlation_id") if isinstance(workflow, dict) else None
                ),
                "execution_enabled": False,
            },
        )

    def _record_transition(
        self,
        task: AgentTask,
        *,
        previous_state: str,
        new_state: str,
        reason: str,
        event_type: str,
        run_state: str,
        audit_reference: str | None = None,
    ) -> None:
        workflow = task.memory.get("assessment_workflow", {})
        plan_digest = workflow.get("plan_digest") if isinstance(workflow, dict) else None
        correlation_id = workflow.get("correlation_id") if isinstance(workflow, dict) else None
        authorization_id = workflow.get("authorization_id") if isinstance(workflow, dict) else None
        event = self._append_transition_audit(
            task,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
        )
        self.activity_service.record_transition(
            run_id=task.task_id,
            timestamp=self.clock().astimezone(UTC),
            event_type=event_type,
            summary=reason,
            run_state=run_state,
            source="approval" if "approval" in event_type else "system",
            tool_id="nuclei",
            authorization_reference=str(authorization_id) if authorization_id else None,
            approval_requirement="required" if plan_digest else "not_required",
            approval_state=(
                "granted"
                if new_state == "execution_blocked"
                else "rejected"
                if new_state == "denied"
                else "pending"
                if new_state == "awaiting_approval"
                else "not_applicable"
            ),
            execution_state="blocked" if run_state in {"blocked", "cancelled"} else "not_started",
            audit_reference=audit_reference or event.event_sha256,
            metadata={"plan_digest": plan_digest, "correlation_id": correlation_id},
        )


__all__ = [
    "AssessmentCreationResult",
    "AssessmentWorkflowError",
    "AssessmentWorkflowService",
    "AuthorizationChoice",
    "NucleiReadiness",
    "bind_nuclei_authorization",
    "load_nuclei_authorization",
]
