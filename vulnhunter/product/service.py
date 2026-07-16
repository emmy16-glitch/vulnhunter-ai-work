"""Framework-independent product application services."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnhunter.agent.config import (
    RuntimeConfigError,
    load_runtime_config,
    runtime_config_fingerprint,
)
from vulnhunter.agent.models import TaskStatus
from vulnhunter.agent.store import AgentStore, AgentStoreError
from vulnhunter.authorization.models import AuthorizationRecord
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.readiness import PilotReadinessReport, assess_pilot_readiness
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.product.models import (
    AgentRunDetail,
    AgentRunSummary,
    ApprovalState,
    AuditActivitySummary,
    AvailabilityState,
    CampaignDetail,
    CampaignScanSummary,
    CampaignSummary,
    CapabilityStatus,
    DashboardSummary,
    PolicyResultState,
    ProductStatusSummary,
    ReadinessSummary,
    ReviewAssignmentSummary,
    RoleDetail,
    RoleSummary,
    SkillDetail,
    SkillSummary,
)
from vulnhunter.product_spec.registry import ProductInterfaceSpec, SpecValidationError
from vulnhunter.roles import RegistryError, RoleRegistry


class ProductServiceError(RuntimeError):
    """Base error for the product application layer."""


@dataclass(frozen=True)
class ProductPaths:
    """Repository and local store locations used by the product layer."""

    authorization_database: Path = Path(".local/runtime/authorization/authorizations.db")
    governance_database: Path = Path(".local/runtime/governance/governance.db")
    agent_database: Path = Path(".local/runtime/agent/agent.db")
    role_registry_root: Path = Path("config/roles")
    runtime_config: Path = Path("config/agent_runtime/runtime.json")
    product_spec_root: Path = Path("config/product_interface")


class ProductApplicationService:
    """Read-only application layer for operational product surfaces."""

    def __init__(self, paths: ProductPaths | None = None) -> None:
        self.paths = paths or ProductPaths()

    def load_status(self) -> ProductStatusSummary:
        blueprint_fingerprint: str | None = None
        runtime_fingerprint: str | None = None

        try:
            blueprint = ProductInterfaceSpec.from_path(self.paths.product_spec_root)
        except SpecValidationError:
            pass
        else:
            blueprint_fingerprint = blueprint.fingerprint()

        try:
            runtime = load_runtime_config(self.paths.runtime_config)
        except RuntimeConfigError as exc:
            agent_runtime = CapabilityStatus(
                name="agent_runtime",
                state=AvailabilityState.INVALID,
                detail=str(exc),
            )
        else:
            runtime_fingerprint = runtime_config_fingerprint(runtime)
            try:
                agent_store = self._open_agent_store(required=True)
                task_count = len(agent_store.list_tasks())
            except (ProductServiceError, AgentStoreError) as exc:
                agent_runtime = CapabilityStatus(
                    name="agent_runtime",
                    state=AvailabilityState.INVALID,
                    detail=f"Bounded runtime store is unavailable: {exc}",
                    evidence_reference=runtime_fingerprint,
                )
            else:
                agent_runtime = CapabilityStatus(
                    name="agent_runtime",
                    state=(
                        AvailabilityState.EMPTY if task_count == 0 else AvailabilityState.AVAILABLE
                    ),
                    detail=(
                        "Bounded runtime configuration and schema-versioned store are available. "
                        "Connectors, unrestricted shell, and public scanning remain disabled."
                    ),
                    evidence_reference=runtime_fingerprint,
                )

        role_registry_status = self._role_registry_status()
        authorization_status = self._authorization_store_status()
        governance_status = self._governance_store_status()
        readiness_status = self._readiness_status()
        audit_status = self._audit_status()

        return ProductStatusSummary(
            blueprint_fingerprint=blueprint_fingerprint,
            runtime_config_fingerprint=runtime_fingerprint,
            authorization_store=authorization_status,
            governance_store=governance_status,
            role_registry=role_registry_status,
            agent_runtime=agent_runtime,
            readiness=readiness_status,
            audit_evidence=audit_status,
        )

    def load_dashboard(self) -> DashboardSummary:
        status = self.load_status()
        governance = self._open_governance_store()
        if governance is None:
            return DashboardSummary(status=status)

        campaigns = governance.list_campaigns()
        totals = dict(Counter(campaign.status for campaign in campaigns))
        pending_reviews = 0
        pending_adjudications = 0
        released_campaigns = 0
        readiness_reports = 0

        for campaign in campaigns:
            try:
                detail = self.get_campaign(campaign.campaign_id)
            except ProductServiceError:
                continue
            pending_reviews += sum(
                count
                for state, count in detail.review_state.items()
                if state not in {"consensus", "adjudicated", "disputed", "missing"}
            )
            pending_adjudications += detail.adjudication_state.get("disputed", 0)
            if detail.release_manifest_state == "present":
                released_campaigns += 1
            if detail.readiness is not None:
                readiness_reports += 1

        pending_human_approvals: int | None = None
        audit_activity: list[AuditActivitySummary] = []

        agent_store = self._open_agent_store()
        if agent_store is not None:
            pending_human_approvals = sum(
                task.status == TaskStatus.PAUSED_APPROVAL for task in agent_store.list_tasks()
            )
            for event in agent_store.list_recent_events(limit=5):
                audit_activity.append(
                    AuditActivitySummary(
                        source="agent",
                        subject=event.task_id,
                        event_type=event.event_type,
                        occurred_at=event.created_at,
                        evidence_reference=event.event_sha256,
                    )
                )

        for event in governance.list_events(limit=5):
            audit_activity.append(
                AuditActivitySummary(
                    source="governance",
                    subject=event.subject_id,
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    actor_id=event.actor_id,
                    evidence_reference=event.event_sha256,
                )
            )

        audit_activity.sort(key=lambda item: item.occurred_at, reverse=True)

        return DashboardSummary(
            status=status,
            campaign_totals_by_status=totals,
            pending_reviews=pending_reviews,
            pending_adjudications=pending_adjudications,
            released_campaigns=released_campaigns,
            readiness_report_available=readiness_reports,
            pending_human_approvals=pending_human_approvals,
            recent_audit_activity=tuple(audit_activity[:10]),
        )

    def list_campaigns(self) -> tuple[CampaignSummary, ...]:
        governance = self._open_governance_store(required=True)
        return tuple(
            self._campaign_summary(campaign.campaign_id) for campaign in governance.list_campaigns()
        )

    def get_campaign(self, campaign_id: str) -> CampaignDetail:
        governance = self._open_governance_store(required=True)
        campaign = governance.get_campaign(campaign_id)
        applications = governance.list_applications(campaign_id)
        scans = governance.list_scans(campaign_id)
        assignments = governance.list_assignments(campaign_id)
        authorizations = self._load_authorizations(applications)
        scope_summary = tuple(
            sorted(
                {
                    f"{record.scheme}://{record.hostname}:{record.port}{record.path_boundary}"
                    for record in authorizations
                }
            )
        )
        review_counts, adjudication_counts, assignment_summaries = self._assignment_state(
            assignments
        )

        try:
            release = governance.get_release(campaign_id)
            release_state = "present"
            release_sha256 = release.manifest_sha256
        except GovernanceNotFoundError:
            release_state = "missing"
            release_sha256 = None
        except GovernanceError as exc:
            release_state = f"invalid: {exc}"
            release_sha256 = None

        readiness = self._readiness_summary(campaign_id)
        return CampaignDetail(
            campaign_id=campaign.campaign_id,
            status=campaign.status,
            title=campaign.title,
            purpose=campaign.purpose,
            owner_id=campaign.owner_id,
            authorization_references=tuple(
                sorted(application.authorization_id for application in applications)
            ),
            scope_summary=scope_summary,
            applications=tuple(
                {
                    "application_id": application.application_id,
                    "application_family": application.application_family,
                    "environment": application.environment,
                    "target_url": application.target_url,
                    "authorization_id": application.authorization_id,
                    "authorization_record_sha256": application.authorization_record_sha256,
                }
                for application in applications
            ),
            scans=tuple(
                CampaignScanSummary(
                    application_id=scan.application_id,
                    scan_database=scan.scan_database,
                    scan_id=scan.scan_id,
                    target_url=scan.target_url,
                    pages_visited=scan.pages_visited,
                    observations_count=scan.observations_count,
                    validation_event_id=scan.validation_event_id,
                    scan_started_event_id=scan.scan_started_event_id,
                    scan_completed_event_id=scan.scan_completed_event_id,
                    scan_snapshot_sha256=scan.scan_snapshot_sha256,
                )
                for scan in scans
            ),
            assignments=assignment_summaries,
            review_state=dict(review_counts),
            adjudication_state=dict(adjudication_counts),
            release_manifest_state=release_state,
            release_manifest_sha256=release_sha256,
            readiness=readiness,
        )

    def list_roles(self) -> tuple[RoleSummary, ...]:
        registry = self._load_registry(required=True)
        return tuple(self._role_summary(role) for role in registry.roles)

    def get_role(self, role_id: str) -> RoleDetail:
        registry = self._load_registry(required=True)
        role = registry.get_role(role_id)
        summary = self._role_summary(role)
        return RoleDetail(
            **summary.model_dump(),
            data_permissions=tuple(
                permission.model_dump(mode="json") for permission in role.data_permissions
            ),
            verification_requirements=role.verification_requirements,
            required_tests=role.required_tests,
            rollback_procedure=role.rollback_procedure,
            skill_ids=role.skill_ids,
            trust_warning="Specialist instructions do not make a role automatically trustworthy.",
        )

    def list_skills(self) -> tuple[SkillSummary, ...]:
        registry = self._load_registry(required=True)
        return tuple(self._skill_summary(skill) for skill in registry.skills)

    def get_skill(self, skill_id: str) -> SkillDetail:
        registry = self._load_registry(required=True)
        skill = registry.get_skill(skill_id)
        summary = self._skill_summary(skill)
        return SkillDetail(
            **summary.model_dump(),
            verification_requirements=skill.verification_requirements,
            required_tests=skill.required_tests,
            rollback_procedure=skill.rollback_procedure,
        )

    def list_agent_runs(self) -> tuple[AgentRunSummary, ...]:
        store = self._open_agent_store(required=True)
        return tuple(self._agent_run_summary(task.task_id) for task in store.list_tasks())

    def get_agent_run(self, run_id: str) -> AgentRunDetail:
        store = self._open_agent_store(required=True)
        task = store.get_task(run_id)
        events = store.list_events(run_id)
        summary = self._agent_run_summary(run_id)
        planner_output = None
        recent_events = []
        for event in events[-10:]:
            recent_events.append(
                {
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "payload": event.payload,
                    "created_at": event.created_at.isoformat(),
                    "event_sha256": event.event_sha256,
                }
            )
            if event.event_type == "planner.proposed":
                planner_output = str(event.payload.get("rationale"))

        latest_proposal = self._latest_payload(events, "planner.proposed")
        latest_call = latest_proposal.get("call") if latest_proposal else {}
        call = latest_call if isinstance(latest_call, dict) else {}
        return AgentRunDetail(
            **summary.model_dump(),
            planner_output=planner_output,
            input_summary=str(task.memory.get("input_summary"))
            if task.memory.get("input_summary")
            else None,
            scope_summary=str(task.memory.get("scope_summary"))
            if task.memory.get("scope_summary")
            else None,
            requested_operation=call.get("operation"),
            audit_references=tuple(
                reference for reference in (summary.final_event_sha256,) if reference
            ),
            recent_events=tuple(recent_events),
        )

    def _campaign_summary(self, campaign_id: str) -> CampaignSummary:
        detail = self.get_campaign(campaign_id)
        return CampaignSummary(
            campaign_id=detail.campaign_id,
            status=detail.status,
            authorization_references=detail.authorization_references,
            scope_summary=detail.scope_summary,
            application_count=len(detail.applications),
            scan_count=len(detail.scans),
            assignment_count=len(detail.assignments),
            review_state=detail.review_state,
            adjudication_state=detail.adjudication_state,
            release_manifest_state=detail.release_manifest_state,
            readiness_state=(
                "pilot_ready"
                if detail.readiness and detail.readiness.pilot_ready
                else "blocked"
                if detail.readiness
                else "unavailable"
            ),
            release_manifest_sha256=detail.release_manifest_sha256,
            dataset_sha256=detail.readiness.dataset_sha256 if detail.readiness else None,
            readiness_report_sha256=detail.readiness.report_sha256 if detail.readiness else None,
        )

    def _role_summary(self, role) -> RoleSummary:
        connector_policy = (
            "disabled"
            if not role.connector_policy.grants
            else f"restricted:{len(role.connector_policy.grants)}"
        )
        operational_state = "untrusted" if role.trust_assumption == "untrusted" else role.status
        return RoleSummary(
            role_id=role.role_id,
            display_name=role.display_name,
            purpose=role.purpose,
            version=role.version,
            risk_level=role.risk_level.value,
            status=role.status.value,
            trust_assumption=role.trust_assumption,
            allowed_actions=role.allowed_actions,
            denied_actions=role.denied_actions,
            tool_ids=tuple(tool.tool_id for tool in role.tools),
            human_approval_points=role.human_approval_points,
            connector_policy=connector_policy,
            last_reviewed_on=role.last_reviewed_on.isoformat(),
            operational_state=operational_state,
        )

    def _skill_summary(self, skill) -> SkillSummary:
        operational_state = (
            "untrusted" if skill.trust_assumption == "untrusted" else skill.status.value
        )
        return SkillSummary(
            skill_id=skill.skill_id,
            display_name=skill.display_name,
            purpose=skill.purpose,
            version=skill.version,
            risk_level=skill.risk_level.value,
            status=skill.status.value,
            trust_assumption=skill.trust_assumption,
            allowed_actions=skill.allowed_actions,
            denied_actions=skill.denied_actions,
            required_tools=skill.required_tools,
            last_reviewed_on=skill.last_reviewed_on.isoformat(),
            operational_state=operational_state,
        )

    def _agent_run_summary(self, run_id: str) -> AgentRunSummary:
        store = self._open_agent_store(required=True)
        task = store.get_task(run_id)
        events = store.list_events(run_id)
        final_event_sha256 = store.verify_integrity(run_id)
        latest_proposal = self._latest_payload(events, "planner.proposed")
        latest_policy = self._latest_payload(events, "policy.decided")
        latest_evaluation = self._latest_payload(events, "result.evaluated")
        latest_tool = self._latest_payload(events, "tool.executed")
        call = latest_proposal.get("call", {}) if latest_proposal else {}
        if not call and latest_tool:
            call = latest_tool.get("call", {})

        policy_state = PolicyResultState.UNAVAILABLE
        policy_reason = "No recorded policy decision."
        if latest_policy:
            policy_state = PolicyResultState(str(latest_policy.get("status")))
            policy_reason = str(latest_policy.get("reason"))

        approval_state = ApprovalState.NOT_REQUIRED
        if self._latest_payload(events, "approval.required"):
            approval_state = ApprovalState.PENDING
        if self._latest_payload(events, "approval.recorded"):
            approval_state = ApprovalState.APPROVED
        if task.status == TaskStatus.PAUSED_APPROVAL:
            approval_state = ApprovalState.PENDING

        execution_state = task.status.value
        if latest_tool and latest_tool.get("result", {}).get("success") is False:
            execution_state = "tool_failed"
        elif latest_tool and latest_tool.get("result", {}).get("success") is True:
            execution_state = "tool_executed"

        evaluation_result = str(latest_evaluation.get("status")) if latest_evaluation else None
        registry_result, registry_reason = self._validate_role_skill(task, call)

        return AgentRunSummary(
            run_id=task.task_id,
            objective=task.objective,
            selected_role=task.permission_manifest.role_id,
            selected_skill=task.permission_manifest.skill_id,
            current_state=task.status.value,
            proposed_action=call.get("action"),
            requested_tool=call.get("tool_id"),
            risk_classification=(
                task.permission_manifest.allowed_risks[0].value
                if len(task.permission_manifest.allowed_risks) == 1
                else None
            ),
            policy_result=policy_state,
            policy_reason=policy_reason,
            approval_requirement=bool(task.permission_manifest.approval_required_actions),
            approval_state=approval_state,
            execution_state=execution_state,
            evaluation_result=evaluation_result,
            retry_decision=str(latest_evaluation.get("reason")) if latest_evaluation else None,
            created_at=task.created_at,
            updated_at=task.updated_at,
            final_event_sha256=final_event_sha256,
            denial_or_failure_reason=task.paused_reason,
            registry_validation_result=registry_result,
            registry_validation_reason=registry_reason,
        )

    def _validate_role_skill(self, task, call: dict[str, Any]) -> tuple[PolicyResultState, str]:
        try:
            registry = self._load_registry(required=True)
        except ProductServiceError as exc:
            return PolicyResultState.UNAVAILABLE, str(exc)

        try:
            role = registry.get_role(task.permission_manifest.role_id)
        except RegistryError as exc:
            return PolicyResultState.DENIED, str(exc)
        skill_id = task.permission_manifest.skill_id
        if not skill_id:
            return PolicyResultState.DENIED, "Permission manifest is missing a selected skill."
        try:
            skill = registry.get_skill(skill_id)
        except RegistryError as exc:
            return PolicyResultState.DENIED, str(exc)
        if role.status.value != "active":
            return PolicyResultState.DENIED, f"Role {role.role_id} is {role.status.value}."
        if skill.status.value != "active":
            return PolicyResultState.DENIED, f"Skill {skill.skill_id} is {skill.status.value}."
        if skill_id not in role.skill_ids:
            return PolicyResultState.DENIED, (
                f"Role {role.role_id} is not permitted to use skill {skill_id}."
            )
        action = str(call.get("action") or "")
        if action and action in role.denied_actions:
            return PolicyResultState.DENIED, f"Action {action} is denied for role {role.role_id}."
        if action and action not in role.allowed_actions:
            return (
                PolicyResultState.DENIED,
                f"Action {action} is not allowed for role {role.role_id}.",
            )
        tool_id = call.get("tool_id")
        if tool_id and tool_id not in {tool.tool_id for tool in role.tools}:
            return (
                PolicyResultState.DENIED,
                f"Tool {tool_id} is not granted to role {role.role_id}.",
            )
        if action and action in role.human_approval_points:
            return PolicyResultState.REQUIRES_APPROVAL, "Role policy requires human approval."
        return PolicyResultState.ALLOWED, "Role and skill validation passed."

    def _assignment_state(
        self,
        assignments,
    ) -> tuple[Counter[str], Counter[str], tuple[ReviewAssignmentSummary, ...]]:
        review_counts: Counter[str] = Counter()
        adjudication_counts: Counter[str] = Counter()
        summaries: list[ReviewAssignmentSummary] = []
        for assignment in assignments:
            repository = self._repository_for_path(assignment.scan_database)
            try:
                case = repository.get_review_case(assignment.observation_id)
            except ValueError:
                state = "missing"
                effective_label = "needs_review"
            else:
                state = case.state
                effective_label = case.effective_label
            review_counts[state] += 1
            if state in {"disputed", "adjudicated"}:
                adjudication_counts[state] += 1
            summaries.append(
                ReviewAssignmentSummary(
                    scan_database=assignment.scan_database,
                    observation_id=assignment.observation_id,
                    primary_reviewers=assignment.primary_reviewers,
                    adjudicator_id=assignment.adjudicator_id,
                    state=state,
                    effective_label=effective_label,
                )
            )
        return review_counts, adjudication_counts, tuple(summaries)

    def _readiness_summary(self, campaign_id: str) -> ReadinessSummary | None:
        governance = self._open_governance_store()
        authorization = self._open_authorization_store()
        if governance is None or authorization is None:
            return None
        repositories = self._repositories_for_campaign(campaign_id)
        if not repositories:
            return None
        try:
            report = assess_pilot_readiness(
                governance,
                authorization,
                repositories,
                campaign_id=campaign_id,
            )
        except Exception:
            return None
        return self._to_readiness_summary(report)

    def _to_readiness_summary(self, report: PilotReadinessReport) -> ReadinessSummary:
        metrics = dict(report.informational_metrics)
        class_balance_raw = metrics.get("class_counts", {})
        class_balance = (
            {str(key): int(value) for key, value in class_balance_raw.items()}
            if isinstance(class_balance_raw, dict)
            else {}
        )
        return ReadinessSummary(
            campaign_id=report.campaign_id,
            pilot_ready=report.pilot_ready,
            model_training_ready=report.model_training_ready,
            hard_release_blockers=report.hard_release_blockers,
            model_training_blockers=report.model_training_blockers,
            warnings=report.warnings,
            application_family_diversity=(
                int(metrics["application_family_count"])
                if "application_family_count" in metrics
                else None
            ),
            class_balance=class_balance,
            review_agreement_count=(
                int(metrics["review_agreement_count"])
                if "review_agreement_count" in metrics
                else None
            ),
            review_disagreement_count=(
                int(metrics["review_disagreement_count"])
                if "review_disagreement_count" in metrics
                else None
            ),
            adjudication_count=(
                int(metrics["adjudicated_count"]) if "adjudicated_count" in metrics else None
            ),
            release_manifest_sha256=report.release_manifest_sha256,
            dataset_sha256=report.dataset_sha256,
            report_sha256=report.report_sha256,
            informational_metrics=report.informational_metrics,
        )

    def _load_authorizations(self, applications) -> tuple[AuthorizationRecord, ...]:
        store = self._open_authorization_store()
        if store is None:
            return ()
        loaded: list[AuthorizationRecord] = []
        for application in applications:
            try:
                loaded.append(store.get(application.authorization_id))
            except Exception:
                continue
        return tuple(loaded)

    def _repositories_for_campaign(self, campaign_id: str) -> dict[str, ScanRepository]:
        governance = self._open_governance_store(required=True)
        repositories: dict[str, ScanRepository] = {}
        for scan in governance.list_scans(campaign_id):
            if scan.scan_database not in repositories:
                repositories[scan.scan_database] = self._repository_for_path(scan.scan_database)
        return repositories

    def _repository_for_path(self, value: str | Path) -> ScanRepository:
        return ScanRepository.from_path(Path(value))

    def _authorization_store_status(self) -> CapabilityStatus:
        path = self.paths.authorization_database.expanduser().resolve()
        if not path.is_file():
            return CapabilityStatus(
                name="authorization_store",
                state=AvailabilityState.MISSING,
                detail=f"Authorization store is missing: {path}",
            )
        try:
            store = AuthorizationStore.from_path(path)
            records = store.list(limit=1)
        except Exception as exc:
            return CapabilityStatus(
                name="authorization_store",
                state=AvailabilityState.INVALID,
                detail=f"Authorization store could not be read safely: {exc}",
            )
        return CapabilityStatus(
            name="authorization_store",
            state=AvailabilityState.EMPTY if not records else AvailabilityState.AVAILABLE,
            detail=(
                "Authorization store is available but contains no records."
                if not records
                else "Authorization store is available."
            ),
            evidence_reference=str(path),
        )

    def _governance_store_status(self) -> CapabilityStatus:
        path = self.paths.governance_database.expanduser().resolve()
        if not path.is_file():
            return CapabilityStatus(
                name="governance_store",
                state=AvailabilityState.MISSING,
                detail=f"Governance store is missing: {path}",
            )
        try:
            store = GovernanceStore.from_path(path)
            campaigns = store.list_campaigns()
        except Exception as exc:
            return CapabilityStatus(
                name="governance_store",
                state=AvailabilityState.INVALID,
                detail=f"Governance store could not be read safely: {exc}",
            )
        return CapabilityStatus(
            name="governance_store",
            state=AvailabilityState.EMPTY if not campaigns else AvailabilityState.AVAILABLE,
            detail=(
                "Governance store is available but contains no campaigns."
                if not campaigns
                else "Governance store is available."
            ),
            evidence_reference=str(path),
        )

    def _role_registry_status(self) -> CapabilityStatus:
        try:
            registry = self._load_registry(required=True)
        except ProductServiceError as exc:
            return CapabilityStatus(
                name="role_registry",
                state=AvailabilityState.INVALID,
                detail=str(exc),
            )
        report = registry.validate()
        detail = "Role and skill registry loaded."
        if report.warnings:
            detail += " " + " ".join(report.warnings)
        return CapabilityStatus(
            name="role_registry",
            state=AvailabilityState.AVAILABLE,
            detail=detail,
            evidence_reference=report.fingerprint_sha256,
        )

    def _readiness_status(self) -> CapabilityStatus:
        governance = self._open_governance_store()
        authorization = self._open_authorization_store()
        if governance is None or authorization is None:
            return CapabilityStatus(
                name="readiness",
                state=AvailabilityState.UNAVAILABLE,
                detail="Readiness requires both governance and authorization stores.",
            )
        return CapabilityStatus(
            name="readiness",
            state=AvailabilityState.AVAILABLE,
            detail="Governed pilot readiness assessment is available through existing services.",
        )

    def _audit_status(self) -> CapabilityStatus:
        messages: list[str] = []
        states: list[AvailabilityState] = []
        governance = self._open_governance_store()
        if governance is not None:
            try:
                governance.verify_integrity()
            except Exception as exc:
                states.append(AvailabilityState.INVALID)
                messages.append(f"governance audit invalid: {exc}")
            else:
                states.append(AvailabilityState.AVAILABLE)
                messages.append("governance audit verified")

        agent_store = self._open_agent_store()
        if agent_store is not None:
            try:
                for task in agent_store.list_tasks():
                    agent_store.verify_integrity(task.task_id)
            except Exception as exc:
                states.append(AvailabilityState.INVALID)
                messages.append(f"agent audit invalid: {exc}")
            else:
                states.append(AvailabilityState.AVAILABLE)
                messages.append("agent audit verified")

        if not states:
            return CapabilityStatus(
                name="audit_evidence",
                state=AvailabilityState.UNAVAILABLE,
                detail="No audit-backed stores are available.",
            )
        state = (
            AvailabilityState.INVALID
            if AvailabilityState.INVALID in states
            else AvailabilityState.AVAILABLE
        )
        return CapabilityStatus(
            name="audit_evidence",
            state=state,
            detail="; ".join(messages),
        )

    def _load_registry(self, *, required: bool = False) -> RoleRegistry | None:
        try:
            return RoleRegistry.from_path(self.paths.role_registry_root)
        except Exception as exc:
            if required:
                raise ProductServiceError(f"Role registry could not be loaded: {exc}") from exc
            return None

    def _open_governance_store(self, *, required: bool = False) -> GovernanceStore | None:
        path = self.paths.governance_database.expanduser().resolve()
        if not path.is_file():
            if required:
                raise ProductServiceError(f"Governance store is missing: {path}")
            return None
        return GovernanceStore.from_path(path)

    def _open_authorization_store(self, *, required: bool = False) -> AuthorizationStore | None:
        path = self.paths.authorization_database.expanduser().resolve()
        if not path.is_file():
            if required:
                raise ProductServiceError(f"Authorization store is missing: {path}")
            return None
        return AuthorizationStore.from_path(path)

    def _open_agent_store(self, *, required: bool = False) -> AgentStore | None:
        path = self.paths.agent_database.expanduser().resolve()
        if not path.is_file():
            if required:
                raise ProductServiceError(f"Agent store is missing: {path}")
            return None
        try:
            return AgentStore.open_existing(path)
        except AgentStoreError as exc:
            if required:
                raise ProductServiceError(str(exc)) from exc
            return None

    @staticmethod
    def _latest_payload(events, event_type: str) -> dict[str, Any]:
        for event in reversed(events):
            if event.event_type == event_type:
                return dict(event.payload)
        return {}
