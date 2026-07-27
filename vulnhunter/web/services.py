from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from vulnhunter.agent.config import load_runtime_config
from vulnhunter.agent.controller import AgentController, AgentRuntime
from vulnhunter.agent.evaluator import ResultEvaluator
from vulnhunter.agent.models import TaskStatus
from vulnhunter.agent.planner import Planner
from vulnhunter.agent.store import AgentStore, AgentStoreError
from vulnhunter.agent.tools import ToolRegistry
from vulnhunter.agent_activity.read_models import snapshot_to_public_dict
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import ActivityStoreError, AppendOnlyActivityStore
from vulnhunter.exceptions import GovernanceNotFoundError
from vulnhunter.governance.models import ReviewerIdentity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.pilot import PilotPlan, PilotPlanLoadError, assess_pilot_plan, load_pilot_plan
from vulnhunter.product import ProductApplicationService
from vulnhunter.product.service import ProductPaths
from vulnhunter.product_spec.registry import ProductInterfaceSpec
from vulnhunter.providers import GroqProvider, GroqProviderError
from vulnhunter.repository_graph import GraphifyAdapter, GraphifyAdapterError
from vulnhunter.roles import RoleRegistry
from vulnhunter.security_tools.nuclei_execution import (
    NucleiExecutionError,
    NucleiExecutionStore,
)
from vulnhunter.security_tools.worker_spool import SignedWorkerSpool, WorkerSpoolError
from vulnhunter.web.models import WebUserMapping


class WebPermissionDenied(PermissionError):
    """Raised when a browser actor cannot access a protected surface."""


class WebCapabilityUnavailable(RuntimeError):
    """Raised when a requested control does not have a safe backend contract."""


def run_visible_to_actor(run: object, actor: object) -> bool:
    """Keep owner-scoped workflow records limited to their governed creator."""

    owner = getattr(run, "assessment_owner", None)
    if owner is None:
        return True
    identity = getattr(getattr(actor, "governance_identity", None), "reviewer_id", None)
    return owner == identity


def actor_can_read_cross_scope(actor: object) -> bool:
    """Return whether an actor may read assessment records across owners."""

    roles = tuple(
        str(item) for item in getattr(actor, "product_roles", ()) if isinstance(item, str)
    )
    if not roles:
        return False
    return role_policy().any_role_allows(
        roles,
        "settings.manage",
        "campaign.approve",
        "audit.read",
    )


def run_readable_to_actor(run: object, actor: object) -> bool:
    """Apply the shared owner-or-governed-cross-scope read contract."""

    return run_visible_to_actor(run, actor) or actor_can_read_cross_scope(actor)


def run_controllable_by_actor(run: object, actor: object) -> bool:
    """Allow cross-owner controls only to system administrators."""

    if run_visible_to_actor(run, actor):
        return True
    roles = tuple(
        str(item) for item in getattr(actor, "product_roles", ()) if isinstance(item, str)
    )
    return bool(roles and role_policy().any_role_allows(roles, "settings.manage"))


def operational_unavailable(
    request: HttpRequest,
    message: str = "A required backend service is temporarily unavailable. Retry later.",
) -> HttpResponse:
    """Return a safe 503 page without exposing internal storage details."""

    return render(
        request,
        "web/unavailable.html",
        {
            "page_title": "Temporarily Unavailable",
            "current_route": (request.resolver_match.url_name if request.resolver_match else ""),
            "unavailable_message": message,
        },
        status=503,
    )


@dataclass(frozen=True)
class AuthorizedActor:
    user: Any
    mapping: WebUserMapping
    product_roles: tuple[str, ...]
    governance_identity: ReviewerIdentity


@dataclass(frozen=True)
class PilotPlanRecord:
    path: Path
    plan: PilotPlan | None
    report: Any | None
    error: str | None = None

    @property
    def plan_id(self) -> str:
        return self.plan.plan_id if self.plan else self.path.stem


class _UnusedPlanner(Planner):
    def propose(self, task, events, tools):  # pragma: no cover - defensive only
        raise RuntimeError("This planner is not available for stop-only control helpers.")


class ProductRolePolicy:
    def __init__(self, spec: ProductInterfaceSpec) -> None:
        self._roles = {item["role_id"]: item for item in spec.roles}

    def known_role_ids(self) -> set[str]:
        return set(self._roles)

    def action_allowed(self, role_id: str, action: str) -> bool:
        try:
            role = self._roles[role_id]
        except KeyError:
            return False
        allowed = set(role.get("allowed_actions", ()))
        denied = set(role.get("denied_actions", ()))
        return action in allowed and action not in denied

    def any_role_allows(self, role_ids: tuple[str, ...], *actions: str) -> bool:
        return any(
            self.action_allowed(role_id, action) for role_id in role_ids for action in actions
        )


def product_paths() -> ProductPaths:
    return ProductPaths(
        authorization_database=Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE),
        governance_database=Path(settings.VULNHUNTER_GOVERNANCE_DATABASE),
        agent_database=Path(settings.VULNHUNTER_AGENT_DATABASE),
        role_registry_root=Path(settings.VULNHUNTER_ROLE_REGISTRY_ROOT),
        runtime_config=Path(settings.VULNHUNTER_RUNTIME_CONFIG),
        product_spec_root=Path(settings.VULNHUNTER_PRODUCT_SPEC_ROOT),
        evidence_root=Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT),
    )


def product_service() -> ProductApplicationService:
    return ProductApplicationService(product_paths())


def governance_store() -> GovernanceStore:
    return GovernanceStore.from_path(Path(settings.VULNHUNTER_GOVERNANCE_DATABASE))


def role_registry() -> RoleRegistry:
    return RoleRegistry.from_path(Path(settings.VULNHUNTER_ROLE_REGISTRY_ROOT))


def product_spec() -> ProductInterfaceSpec:
    return ProductInterfaceSpec.from_path(Path(settings.VULNHUNTER_PRODUCT_SPEC_ROOT))


def role_policy() -> ProductRolePolicy:
    return ProductRolePolicy(product_spec())


def activity_service() -> AgentActivityService:
    root = Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT)
    return AgentActivityService(AppendOnlyActivityStore(root))


def list_pilot_plan_records() -> tuple[PilotPlanRecord, ...]:
    root = Path(settings.VULNHUNTER_PILOT_PLAN_ROOT)
    if not root.is_dir():
        return ()
    records: list[PilotPlanRecord] = []
    for path in sorted(root.glob("*.json")):
        try:
            plan = load_pilot_plan(path)
            report = assess_pilot_plan(plan, assessed_at=datetime.now(UTC))
        except PilotPlanLoadError as exc:
            records.append(PilotPlanRecord(path=path, plan=None, report=None, error=str(exc)))
        else:
            records.append(PilotPlanRecord(path=path, plan=plan, report=report))
    return tuple(records)


def get_pilot_plan_record(plan_id: str) -> PilotPlanRecord:
    for record in list_pilot_plan_records():
        if record.plan_id == plan_id:
            return record
    raise FileNotFoundError(plan_id)


def authorized_actor(user: Any, *, required_actions: tuple[str, ...]) -> AuthorizedActor:
    if not user.is_authenticated:
        raise WebPermissionDenied("Sign in to continue.")
    if not user.is_active:
        raise WebPermissionDenied("This user account is inactive.")

    try:
        mapping = user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist as exc:
        raise WebPermissionDenied(
            "No VulnHunter identity mapping is configured for this user."
        ) from exc

    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    if not roles:
        raise WebPermissionDenied("This user does not hold any product roles.")

    policy = role_policy()
    if any(role_id not in policy.known_role_ids() for role_id in roles):
        raise WebPermissionDenied("This user has an unknown product role mapping.")
    if not any(policy.any_role_allows(roles, action) for action in required_actions):
        raise WebPermissionDenied("Your role cannot perform this action.")

    if not mapping.governance_identity_id:
        raise WebPermissionDenied("A governed identity mapping is required for this surface.")
    try:
        identity = governance_store().get_identity(mapping.governance_identity_id)
    except GovernanceNotFoundError as exc:
        raise WebPermissionDenied("The mapped governed identity does not exist.") from exc
    if identity.status != "active":
        raise WebPermissionDenied("The mapped governed identity is not active.")

    return AuthorizedActor(
        user=user,
        mapping=mapping,
        product_roles=roles,
        governance_identity=identity,
    )


def control_availability(
    user: Any,
    run_state: str,
    approval_state: str,
) -> dict[str, dict[str, str | bool]]:
    availability: dict[str, dict[str, str | bool]] = {
        "stop": {"available": False, "reason": "Cancellation controls are unavailable."},
        "approve": {
            "available": False,
            "reason": (
                "Approval resume is unavailable because no safe runtime reconstruction contract "
                "exists for persisted bounded tasks."
            ),
        },
        "reject": {
            "available": False,
            "reason": (
                "Approval rejection is unavailable because the backend lacks "
                "a rejection transition."
            ),
        },
        "pause": {
            "available": False,
            "reason": (
                "Manual pause is unavailable because the backend lacks an operator pause contract."
            ),
        },
    }
    if run_state in {"completed", "failed", "cancelled", "stopped", "blocked"}:
        availability["stop"]["reason"] = "The run is already in a terminal state."
        return availability
    try:
        actor = authorized_actor(user, required_actions=("scan.cancel", "settings.manage"))
    except WebPermissionDenied as exc:
        availability["stop"]["reason"] = str(exc)
    else:
        availability["stop"] = {
            "available": True,
            "reason": (
                "Cancellation is available to governed identity "
                f"{actor.governance_identity.reviewer_id}."
            ),
        }
    if approval_state != "pending":
        availability["approve"]["reason"] = "This run is not waiting for approval."
        availability["reject"]["reason"] = "This run is not waiting for approval."
    return availability


def activity_payload(run_id: str, *, after_sequence: int) -> dict[str, object]:
    snapshot = activity_service().feed(run_id, after_sequence=after_sequence)
    return snapshot_to_public_dict(snapshot)


def stop_agent_run(user: Any, *, run_id: str, reason: str) -> None:
    actor = authorized_actor(user, required_actions=("scan.cancel", "settings.manage"))
    service = product_service()
    run = service.get_agent_run(run_id)
    if not run_controllable_by_actor(run, actor):
        raise WebPermissionDenied("Assessment run does not exist.")
    if run.current_state in {"completed", "failed", "cancelled", "stopped", "blocked"}:
        raise WebCapabilityUnavailable("The run is already in a terminal state.")

    now = datetime.now(UTC)
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
            planner=_UnusedPlanner(),
            tools=ToolRegistry(),
            evaluator=ResultEvaluator(),
            activity_service=activity,
        )
    )
    try:
        resulting_task = controller.cancel(
            run_id,
            f"{reason} [audit:{stop_request.event_sha256}]",
        )
    except (AgentStoreError, ActivityStoreError) as exc:
        raise WebCapabilityUnavailable(
            "Cancellation was not fully recorded safely. The stop request remains recorded."
        ) from exc

    if resulting_task.status != TaskStatus.CANCELLED:
        raise WebCapabilityUnavailable(
            "The stop request was recorded, but the run reached "
            f"{resulting_task.status.value} before cancellation could be applied."
        )


def navigation_for(user: Any) -> tuple[dict[str, object], ...]:
    """Return the role-filtered navigation defined by the product blueprint.

    The product specification owns ordering, section labels and user-facing
    labels. This adapter adds only Django route bindings, icons, permissions and
    contextual detail routes so the runtime sidebar cannot drift from the
    machine-readable interface contract.
    """

    if not getattr(user, "is_authenticated", False):
        return ()
    try:
        mapping = user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return ()

    bindings: dict[str, dict[str, object]] = {
        "dashboard": {
            "url_name": "web-dashboard",
            "icon": "grid",
            "actions": ("dashboard.read", "scan.create"),
            "active_routes": ("web-dashboard", "web-mobile-analysis"),
        },
        "authorizations": {
            "url_name": "web-authorization-list",
            "icon": "authorization",
            "actions": ("authorization.read",),
            "active_routes": ("web-authorization-list",),
        },
        "scan-runs": {
            "url_name": "web-scan-run-list",
            "icon": "assessment",
            "actions": ("scan.read", "scan.read_summary", "scan.create", "audit.read"),
            "active_routes": (
                "web-scan-run-list",
                "web-scan-run-detail",
                "web-agent-run-list",
                "web-agent-run-detail",
                "legacy-run-detail",
                "web-agent-run-activity",
                "web-agent-run-activity-stream",
                "web-legacy-agent-run-activity",
                "web-legacy-agent-run-activity-stream",
                "web-agent-run-stop",
                "web-new-scan",
                "web-advanced-profiles",
                "web-oracle-overview",
                "web-approval-list",
                "web-approval-detail",
                "web-approval-decision",
                "web-lab-create",
                "web-lab-detail",
                "web-lab-approve",
                "web-lab-queue",
                "web-lab-stop",
                "web-lab-activity-stream",
            ),
        },
        "findings": {
            "url_name": "web-findings-overview",
            "icon": "finding",
            "actions": ("finding.read", "scan.read", "audit.read"),
            "active_routes": ("web-findings-overview", "web-finding-detail"),
        },
        "review-queue": {
            "url_name": "web-review-queue",
            "icon": "review",
            "actions": ("review.read_assigned",),
            "active_routes": ("web-review-queue", "web-review-detail"),
        },
        "adjudication-queue": {
            "url_name": "web-adjudication-queue",
            "icon": "scale",
            "actions": ("adjudication.read_assigned",),
            "active_routes": ("web-adjudication-queue", "web-adjudication-detail"),
        },
        "campaigns": {
            "url_name": "web-campaign-list",
            "icon": "layers",
            "actions": ("campaign.read", "campaign.read_summary"),
            "active_routes": (
                "web-campaign-list",
                "web-campaign-detail",
                "web-readiness-detail",
                "web-pilot-plan-list",
                "web-pilot-plan-detail",
                "web-pilot-plan-validation",
            ),
        },
        "releases": {
            "url_name": "web-release-list",
            "icon": "release",
            "actions": ("release.read",),
            "active_routes": ("web-release-list", "web-release-detail"),
        },
        "datasets": {
            "url_name": "web-dataset-list",
            "icon": "database",
            "actions": ("dataset.read",),
            "active_routes": ("web-dataset-list", "web-dataset-detail"),
        },
        "models": {
            "url_name": "web-model-list",
            "icon": "model",
            "actions": ("model.read",),
            "active_routes": ("web-model-list", "web-model-detail"),
        },
        "audit": {
            "url_name": "web-audit-overview",
            "icon": "audit",
            "actions": ("audit.read",),
            "active_routes": ("web-audit-overview",),
        },
        "reports": {
            "url_name": "web-reports-overview",
            "icon": "report",
            "actions": ("report.read", "report.read_own", "report.read_public"),
            "active_routes": ("web-reports-overview", "web-pilot-plan-download"),
        },
        "settings": {
            "url_name": "web-settings-overview",
            "icon": "settings",
            "actions": ("settings.manage", "audit.read", "dashboard.read"),
            "active_routes": (
                "web-settings-overview",
                "web-status",
                "web-governance-overview",
                "web-role-list",
                "web-role-detail",
                "web-skill-list",
                "web-skill-detail",
                "web-security-tool-registry",
            ),
        },
    }

    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    spec = product_spec()
    policy = ProductRolePolicy(spec)
    visible: list[dict[str, object]] = []
    previous_section: str | None = None
    sections = sorted(
        spec.documents["navigation.json"].get("sections", []),
        key=lambda item: int(item.get("order", 0)),
    )
    for section in sections:
        section_id = str(section["section_id"])
        section_label = str(section["label"])
        for navigation_item in section.get("items", []):
            page_id = str(navigation_item["page_id"])
            try:
                binding = bindings[page_id]
            except KeyError as exc:
                raise WebCapabilityUnavailable(
                    f"Navigation page {page_id!r} has no Django route binding."
                ) from exc
            page = spec.page(page_id)
            allowed_roles = {str(item) for item in page.get("allowed_roles", ())}
            if not any(role_id in allowed_roles for role_id in roles):
                continue
            actions = tuple(str(item) for item in binding["actions"])
            if not policy.any_role_allows(roles, *actions):
                continue
            item = {
                "section_id": section_id,
                "section_label": section_label,
                "label": str(navigation_item["label"]),
                **binding,
                "section_start": section_id != previous_section,
            }
            previous_section = section_id
            visible.append(item)
    return tuple(visible)


def intelligence_status() -> tuple[dict[str, str], ...]:
    """Return non-secret graph, advisory, and verification states without inference."""

    repository_root = Path(settings.BASE_DIR).resolve()
    try:
        graphify = GraphifyAdapter(
            repository_roots=(repository_root,),
            output_root=Path(settings.VULNHUNTER_GRAPHIFY_OUTPUT_ROOT),
            executable=settings.VULNHUNTER_GRAPHIFY_EXECUTABLE,
            execution_enabled=settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED,
        )
        artifact = graphify.load_artifact(
            Path(settings.VULNHUNTER_GRAPHIFY_OUTPUT_ROOT) / "graph.json",
            repository_root=repository_root,
        )
    except GraphifyAdapterError as exc:
        graphify_row = {
            "name": "Graphify advisory graph",
            "state": "NOT_READY",
            "detail": f"No current validated graph is available ({exc.code}).",
        }
    else:
        graphify_row = {
            "name": "Graphify advisory graph",
            "state": "READY_ENABLED",
            "detail": (
                f"Validated advisory graph {artifact.graph_sha256[:12]} with "
                f"{len(artifact.nodes)} nodes; rebuild execution, hooks, and MCP are disabled."
            ),
        }

    if not settings.VULNHUNTER_GROQ_ENABLED:
        groq_row = {
            "name": "Groq advisory",
            "state": "CODE_READY_DISABLED",
            "detail": "Groq is optional and disabled. Deterministic workflows continue.",
        }
    else:
        try:
            groq = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
                connection_timeout_seconds=3,
                health_timeout_seconds=8,
            )
            health = groq.health()
        except GroqProviderError as exc:
            groq_row = {
                "name": "Groq advisory",
                "state": "NOT_READY",
                "detail": f"Groq configuration was rejected safely: {exc}",
            }
        else:
            ready = health.reachable and health.model is not None
            groq_row = {
                "name": "Groq advisory",
                "state": "READY_ENABLED" if ready else "NOT_READY",
                "detail": (
                    f"Approved advisory model {health.model} is available."
                    if ready
                    else health.reason
                ),
            }

    verification_row = {
        "name": "Deterministic verification",
        "state": "READY_ENABLED",
        "detail": "Verification runs inside assessments and cannot publish findings.",
    }
    return (graphify_row, groq_row, verification_row)
