"""Persist and project authoritative remediation lifecycle graphs."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from vulnhunter.actions.models import ActionClass, ActionManifest, ExecutionLimits
from vulnhunter.assessment_graph.models import (
    AssessmentGraphBundle,
    AssessmentKind,
    AssessmentStage,
)
from vulnhunter.assessment_graph.service import AssessmentGraphError, AssessmentGraphService
from vulnhunter.taskgraph.models import TERMINAL_STATUSES, GraphNode, NodeStatus, TaskGraph
from vulnhunter.taskgraph.store import TaskGraphStoreError

_FAILED_SAFE_PREFIX = "Remediation failed safely: "


class RemediationAssessmentGraphService:
    """Bind one exact verified-finding remediation plan to the shared lifecycle."""

    def __init__(
        self,
        root,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.core = AssessmentGraphService(root, clock=clock)
        self.clock = clock

    def create(
        self,
        *,
        remediation_id: str,
        workspace_id: str,
        owner_id: str,
        campaign_id: str,
        finding_id: str,
        finding_fingerprint: str,
        source_finding_revision: int,
        plan_sha256: str,
        target_references: tuple[str, ...],
        expires_at: datetime,
        state: str,
        reason: str | None = None,
    ) -> AssessmentGraphBundle:
        """Create the child graph without granting patch or merge authority."""

        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AssessmentGraphError("remediation graph expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise AssessmentGraphError("remediation graph expiry must be in the future")
        try:
            parsed_workspace = UUID(workspace_id)
        except ValueError as exc:
            raise AssessmentGraphError("remediation requires a valid chat workspace UUID") from exc
        for label, value in (
            ("finding fingerprint", finding_fingerprint),
            ("plan", plan_sha256),
        ):
            if len(value) != 64:
                raise AssessmentGraphError(f"remediation requires the exact {label} SHA-256")
        if source_finding_revision < 0:
            raise AssessmentGraphError("remediation source finding revision cannot be negative")
        if not target_references:
            raise AssessmentGraphError("remediation requires exact target references")

        graph_id = self.core.graph_id_for_run(remediation_id)
        references = (
            finding_id,
            f"finding-fingerprint:{finding_fingerprint}",
            f"finding-revision:{source_finding_revision}",
            f"remediation-plan:{plan_sha256}",
            *target_references,
        )
        statuses = self._initial_statuses(state)
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        node_stages: dict[str, AssessmentStage] = {}
        previous_node: str | None = None

        for stage in AssessmentStage:
            node_id = f"{remediation_id}-{stage.value}"
            manifest = ActionManifest(
                manifest_id=node_id,
                campaign_id=campaign_id,
                requested_by=owner_id,
                role_id=self._role_for_stage(stage),
                skill_id=self._skill_for_stage(stage),
                action=self._action_for_stage(stage),
                action_class=self._action_class_for_stage(stage),
                tool_id=self._tool_for_stage(stage),
                operation="human-governed-remediation",
                target_references=references,
                authorization_references=(campaign_id,),
                limits=ExecutionLimits(
                    timeout_seconds=86_400 if stage == AssessmentStage.EXECUTION else 900,
                    maximum_requests=1,
                    maximum_output_bytes=10_000_000,
                    maximum_targets=len(references),
                    maximum_attempts=1,
                ),
                approval_required=stage == AssessmentStage.EXECUTION,
                created_at=now,
                expires_at=expiry,
                parent_manifest_sha256=plan_sha256,
                purpose=self._purpose_for_stage(stage),
            )
            manifests.append(manifest)
            status = statuses[stage]
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    role_id=manifest.role_id,
                    skill_id=manifest.skill_id,
                    action_manifest_sha256=manifest.fingerprint(),
                    dependencies=(() if previous_node is None else (previous_node,)),
                    status=status,
                    maximum_attempts=1,
                    last_error=(
                        reason
                        if stage == AssessmentStage.EXECUTION
                        and status in {NodeStatus.BLOCKED, NodeStatus.FAILED}
                        else None
                    ),
                    updated_at=now,
                )
            )
            node_stages[node_id] = stage
            previous_node = node_id

        graph = TaskGraph(
            graph_id=graph_id,
            campaign_id=campaign_id,
            run_id=remediation_id,
            nodes=tuple(nodes),
            created_at=now,
            updated_at=now,
        )
        bundle = AssessmentGraphBundle(
            graph_id=graph_id,
            run_id=remediation_id,
            assessment_kind=AssessmentKind.REMEDIATION,
            workspace_id=parsed_workspace,
            owner_id=owner_id,
            authorization_id=campaign_id,
            target_reference=f"finding:{finding_id}",
            node_stages=node_stages,
            manifests=tuple(manifests),
            created_at=now,
        )
        self.core._validate_graph_binding(graph, bundle)
        bundle_path = self.core._write_bundle(bundle)
        try:
            self.core.graph_store.save(graph)
        except (OSError, TaskGraphStoreError, ValueError) as exc:
            bundle_path.unlink(missing_ok=True)
            raise AssessmentGraphError("remediation graph persistence failed closed") from exc
        return bundle

    def project_state(
        self,
        remediation_id: str,
        *,
        state: str,
        reason: str | None = None,
    ) -> bool:
        """Project finding state without executing or approving source changes."""

        graph = self.core._load_optional(remediation_id)
        if graph is None:
            return False
        normalized = state.strip().casefold()
        execution = self.core._stage_node(graph, AssessmentStage.EXECUTION)

        if normalized == "ready_for_implementation":
            if execution.status == NodeStatus.PENDING:
                self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.READY,
                    last_error=None,
                )
            return True
        if normalized == "cancelled":
            return self.core.project_terminal(
                remediation_id,
                outcome="cancelled",
                reason=reason or "The remediation plan was cancelled by its human owner.",
            )
        if normalized == "failed":
            failure_reason = _FAILED_SAFE_PREFIX + (
                reason or "The remediation plan could not continue safely."
            )
            if execution.status not in TERMINAL_STATUSES:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.CANCELLED,
                    last_error=failure_reason,
                )
            self.core._cancel_downstream(
                graph,
                starting_stage=AssessmentStage.EVIDENCE,
                reason=failure_reason,
            )
            return True
        return True

    def status_payload(self, remediation_id: str) -> dict[str, object] | None:
        payload = self.core.status_payload(remediation_id)
        if payload is None:
            return None
        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            return payload
        by_stage = {str(item.get("stage")): item for item in nodes if isinstance(item, dict)}
        execution_node = by_stage.get(AssessmentStage.EXECUTION.value)
        execution = str(execution_node.get("status")) if isinstance(execution_node, dict) else None
        execution_error = (
            str(execution_node.get("last_error") or "") if isinstance(execution_node, dict) else ""
        )
        if execution == NodeStatus.READY.value:
            payload["chat_stage"] = "awaiting_developer_implementation"
        elif execution == NodeStatus.CANCELLED.value:
            payload["chat_stage"] = (
                "remediation_failed_safe"
                if execution_error.startswith(_FAILED_SAFE_PREFIX)
                else "remediation_cancelled"
            )
        elif execution in {NodeStatus.BLOCKED.value, NodeStatus.FAILED.value}:
            payload["chat_stage"] = "remediation_failed_safe"
        return payload

    @staticmethod
    def _initial_statuses(state: str) -> dict[AssessmentStage, NodeStatus]:
        statuses = {
            AssessmentStage.AUTHORIZATION: NodeStatus.COMPLETED,
            AssessmentStage.PLAN: NodeStatus.COMPLETED,
            AssessmentStage.APPROVAL: NodeStatus.COMPLETED,
            AssessmentStage.EXECUTION: NodeStatus.PENDING,
            AssessmentStage.EVIDENCE: NodeStatus.PENDING,
            AssessmentStage.VERIFICATION: NodeStatus.PENDING,
            AssessmentStage.REVIEW: NodeStatus.PENDING,
            AssessmentStage.REPORT: NodeStatus.PENDING,
        }
        normalized = state.strip().casefold()
        if normalized == "ready_for_implementation":
            statuses[AssessmentStage.EXECUTION] = NodeStatus.READY
        elif normalized == "cancelled":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
                AssessmentStage.REPORT,
            ):
                statuses[stage] = NodeStatus.CANCELLED
        elif normalized == "failed":
            statuses[AssessmentStage.EXECUTION] = NodeStatus.BLOCKED
            for stage in (
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
                AssessmentStage.REPORT,
            ):
                statuses[stage] = NodeStatus.CANCELLED
        return statuses

    @staticmethod
    def _role_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding-governance-guardian",
            AssessmentStage.PLAN: "remediation-planner",
            AssessmentStage.APPROVAL: "remediation-owner",
            AssessmentStage.EXECUTION: "human-developer",
            AssessmentStage.EVIDENCE: "fix-evidence-curator",
            AssessmentStage.VERIFICATION: "read-only-fix-verifier",
            AssessmentStage.REVIEW: "independent-fix-reviewer",
            AssessmentStage.REPORT: "remediation-report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "verified-finding-and-campaign-validation",
            AssessmentStage.PLAN: "bounded-remediation-planning",
            AssessmentStage.APPROVAL: "exact-plan-owner-confirmation",
            AssessmentStage.EXECUTION: "developer-led-bounded-change",
            AssessmentStage.EVIDENCE: "before-and-after-evidence-collection",
            AssessmentStage.VERIFICATION: "read-only-fix-verification",
            AssessmentStage.REVIEW: "independent-remediation-review",
            AssessmentStage.REPORT: "evidence-backed-remediation-reporting",
        }[stage]

    @staticmethod
    def _action_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding.remediation.authorize",
            AssessmentStage.PLAN: "finding.remediation.plan",
            AssessmentStage.APPROVAL: "finding.remediation.confirm",
            AssessmentStage.EXECUTION: "finding.remediation.implement",
            AssessmentStage.EVIDENCE: "finding.remediation.evidence",
            AssessmentStage.VERIFICATION: "finding.fix.verify",
            AssessmentStage.REVIEW: "finding.remediation.review",
            AssessmentStage.REPORT: "finding.remediation.report",
        }[stage]

    @staticmethod
    def _action_class_for_stage(stage: AssessmentStage) -> ActionClass:
        if stage == AssessmentStage.EXECUTION:
            return ActionClass.CONSEQUENTIAL
        if stage in {AssessmentStage.APPROVAL, AssessmentStage.REVIEW}:
            return ActionClass.REVERSIBLE_LOCAL
        return ActionClass.READ_ONLY

    @staticmethod
    def _tool_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding-store",
            AssessmentStage.PLAN: "remediation-plan-service",
            AssessmentStage.APPROVAL: "password-step-up",
            AssessmentStage.EXECUTION: "human-developer-workspace",
            AssessmentStage.EVIDENCE: "fix-evidence-store",
            AssessmentStage.VERIFICATION: "read-only-fix-verifier",
            AssessmentStage.REVIEW: "review-service",
            AssessmentStage.REPORT: "report-service",
        }[stage]

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: (
                "Validate the exact independently verified finding and campaign authority."
            ),
            AssessmentStage.PLAN: (
                "Bind the remediation summary, exact targets, RED test and verification recipe."
            ),
            AssessmentStage.APPROVAL: (
                "Record fresh human confirmation of the exact plan without granting "
                "merge authority."
            ),
            AssessmentStage.EXECUTION: (
                "Wait for developer-led implementation inside separately controlled "
                "engineering tools."
            ),
            AssessmentStage.EVIDENCE: (
                "Collect bounded before-and-after evidence and deterministic test receipts."
            ),
            AssessmentStage.VERIFICATION: (
                "Verify the fix read-only and independently from the builder or model."
            ),
            AssessmentStage.REVIEW: (
                "Request independent human review before any finding or release transition."
            ),
            AssessmentStage.REPORT: (
                "Record remediation and verification limitations without publishing automatically."
            ),
        }[stage]


__all__ = ["RemediationAssessmentGraphService"]
