"""Persist and project authoritative Active Validation lifecycle graphs."""

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


class ActiveValidationAssessmentGraphService:
    """Bind one exact synthetic validation plan to the shared lifecycle."""

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
        run_id: str,
        workspace_id: str | None,
        owner_id: str,
        authorization_id: str,
        assessment_id: str,
        finding_reference: str,
        target_reference: str,
        scenario_id: str,
        plan_digest: str,
        expires_at: datetime,
        state: str,
        reason: str | None = None,
    ) -> AssessmentGraphBundle:
        """Create the eight-stage child graph without replacing the lab worker."""

        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AssessmentGraphError("active validation graph expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise AssessmentGraphError("active validation graph expiry must be in the future")
        try:
            parsed_workspace = UUID(workspace_id) if workspace_id else None
        except ValueError as exc:
            raise AssessmentGraphError("workspace binding must be a valid UUID") from exc
        if len(plan_digest) != 64:
            raise AssessmentGraphError("Active Validation requires the exact plan SHA-256")

        graph_id = self.core.graph_id_for_run(run_id)
        target_references = (
            assessment_id,
            finding_reference,
            target_reference,
            f"lab-scenario:{scenario_id}",
            f"lab-plan:{plan_digest}",
        )
        statuses = self._initial_statuses(state)
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        node_stages: dict[str, AssessmentStage] = {}
        previous_node: str | None = None

        for stage in AssessmentStage:
            node_id = f"{run_id}-{stage.value}"
            manifest = ActionManifest(
                manifest_id=node_id,
                campaign_id=run_id,
                requested_by=owner_id.strip().casefold(),
                role_id=self._role_for_stage(stage),
                skill_id=self._skill_for_stage(stage),
                action=self._action_for_stage(stage),
                action_class=self._action_class_for_stage(stage),
                tool_id=self._tool_for_stage(stage),
                operation="synthetic-active-validation",
                target_references=target_references,
                authorization_references=(authorization_id,),
                limits=ExecutionLimits(
                    timeout_seconds=3_600 if stage == AssessmentStage.EXECUTION else 900,
                    maximum_requests=1,
                    maximum_output_bytes=(
                        50_000_000 if stage == AssessmentStage.EXECUTION else 10_000_000
                    ),
                    maximum_targets=len(target_references),
                    maximum_attempts=1,
                ),
                approval_required=stage == AssessmentStage.EXECUTION,
                created_at=now,
                expires_at=expiry,
                parent_manifest_sha256=plan_digest,
                purpose=self._purpose_for_stage(stage, scenario_id=scenario_id),
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
                    maximum_attempts=manifest.limits.maximum_attempts,
                    last_error=(
                        reason if status in {NodeStatus.BLOCKED, NodeStatus.FAILED} else None
                    ),
                    updated_at=now,
                )
            )
            node_stages[node_id] = stage
            previous_node = node_id

        graph = TaskGraph(
            graph_id=graph_id,
            campaign_id=run_id,
            run_id=run_id,
            nodes=tuple(nodes),
            created_at=now,
            updated_at=now,
        )
        bundle = AssessmentGraphBundle(
            graph_id=graph_id,
            run_id=run_id,
            assessment_kind=AssessmentKind.ACTIVE_VALIDATION,
            workspace_id=parsed_workspace,
            owner_id=owner_id.strip().casefold(),
            authorization_id=authorization_id,
            target_reference=f"active-validation:{finding_reference}",
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
            raise AssessmentGraphError("Active Validation graph persistence failed closed") from exc
        return bundle

    def project_state(
        self,
        run_id: str,
        *,
        state: str,
        reason: str | None = None,
    ) -> bool:
        """Project observed lab state without granting execution authority."""

        graph = self.core._load_optional(run_id)
        if graph is None:
            return False
        normalized = state.strip().casefold()

        if normalized == "awaiting_approval":
            return True
        if normalized == "approved":
            self._complete_stage(graph, AssessmentStage.APPROVAL)
            return True
        if normalized == "queued":
            graph = self._complete_stage(graph, AssessmentStage.APPROVAL)
            self._ready_stage(graph, AssessmentStage.EXECUTION)
            return True
        if normalized in {"provisioning", "running"}:
            graph = self._complete_stage(graph, AssessmentStage.APPROVAL)
            self._run_stage(graph, AssessmentStage.EXECUTION)
            return True
        if normalized in {"evaluating", "cleaning"}:
            graph = self._complete_stage(graph, AssessmentStage.APPROVAL)
            graph = self._complete_stage(graph, AssessmentStage.EXECUTION)
            graph = self._complete_stage(graph, AssessmentStage.EVIDENCE)
            self._run_stage(graph, AssessmentStage.VERIFICATION)
            return True
        if normalized == "completed":
            graph = self._complete_stage(graph, AssessmentStage.APPROVAL)
            graph = self._complete_stage(graph, AssessmentStage.EXECUTION)
            graph = self._complete_stage(graph, AssessmentStage.EVIDENCE)
            graph = self._complete_stage(graph, AssessmentStage.VERIFICATION)
            self._ready_stage(graph, AssessmentStage.REVIEW)
            return True
        if normalized == "cancelled":
            return self.core.project_terminal(
                run_id,
                outcome="cancelled",
                reason=reason or "The Active Validation run was cancelled.",
            )
        if normalized in {"blocked", "failed"}:
            self._project_failure(
                graph,
                failed=normalized == "failed",
                reason=reason or "The Active Validation worker stopped safely.",
            )
            return True
        return True

    def status_payload(self, run_id: str) -> dict[str, object] | None:
        payload = self.core.status_payload(run_id)
        if payload is None:
            return None
        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            return payload
        by_stage = {
            str(item.get("stage")): str(item.get("status"))
            for item in nodes
            if isinstance(item, dict)
        }
        approval = by_stage.get(AssessmentStage.APPROVAL.value)
        execution = by_stage.get(AssessmentStage.EXECUTION.value)
        evidence = by_stage.get(AssessmentStage.EVIDENCE.value)
        verification = by_stage.get(AssessmentStage.VERIFICATION.value)
        review = by_stage.get(AssessmentStage.REVIEW.value)
        if approval == NodeStatus.WAITING_FOR_HUMAN_APPROVAL.value:
            payload["chat_stage"] = "awaiting_independent_approval"
        elif approval == NodeStatus.COMPLETED.value and execution == NodeStatus.PENDING.value:
            payload["chat_stage"] = "ready_to_queue"
        elif execution == NodeStatus.READY.value:
            payload["chat_stage"] = "queued_for_validation"
        elif execution == NodeStatus.RUNNING.value:
            payload["chat_stage"] = "running_validation_trials"
        elif evidence == NodeStatus.COMPLETED.value and verification == NodeStatus.RUNNING.value:
            payload["chat_stage"] = "evaluating_validation_evidence"
        elif verification == NodeStatus.COMPLETED.value and review == NodeStatus.READY.value:
            payload["chat_stage"] = "awaiting_human_review"
        return payload

    def _complete_stage(self, graph: TaskGraph, stage: AssessmentStage) -> TaskGraph:
        node = self.core._stage_node(graph, stage)
        if node.status == NodeStatus.COMPLETED:
            return graph
        if node.status in TERMINAL_STATUSES:
            return graph
        if node.status in {
            NodeStatus.PENDING,
            NodeStatus.READY,
            NodeStatus.WAITING_FOR_HUMAN_APPROVAL,
            NodeStatus.PAUSED,
        }:
            graph = self.core._transition(
                graph,
                node_id=node.node_id,
                status=NodeStatus.RUNNING,
                last_error=None,
            )
            node = self.core._stage_node(graph, stage)
        if node.status == NodeStatus.RUNNING:
            graph = self.core._transition(
                graph,
                node_id=node.node_id,
                status=NodeStatus.COMPLETED,
                last_error=None,
            )
        return graph

    def _ready_stage(self, graph: TaskGraph, stage: AssessmentStage) -> TaskGraph:
        node = self.core._stage_node(graph, stage)
        if node.status == NodeStatus.PENDING:
            return self.core._transition(
                graph,
                node_id=node.node_id,
                status=NodeStatus.READY,
                last_error=None,
            )
        return graph

    def _run_stage(self, graph: TaskGraph, stage: AssessmentStage) -> TaskGraph:
        node = self.core._stage_node(graph, stage)
        if node.status in {NodeStatus.PENDING, NodeStatus.READY, NodeStatus.PAUSED}:
            return self.core._transition(
                graph,
                node_id=node.node_id,
                status=NodeStatus.RUNNING,
                last_error=None,
            )
        return graph

    def _project_failure(self, graph: TaskGraph, *, failed: bool, reason: str) -> TaskGraph:
        current = graph
        stages = (
            AssessmentStage.EXECUTION,
            AssessmentStage.EVIDENCE,
            AssessmentStage.VERIFICATION,
        )
        for stage in stages:
            node = self.core._stage_node(current, stage)
            if node.status in TERMINAL_STATUSES:
                continue
            if failed and node.status != NodeStatus.RUNNING:
                current = self._run_stage(current, stage)
                node = self.core._stage_node(current, stage)
            terminal = NodeStatus.FAILED if failed else NodeStatus.BLOCKED
            current = self.core._transition(
                current,
                node_id=node.node_id,
                status=terminal,
                last_error=reason,
            )
            next_stage = {
                AssessmentStage.EXECUTION: AssessmentStage.EVIDENCE,
                AssessmentStage.EVIDENCE: AssessmentStage.VERIFICATION,
                AssessmentStage.VERIFICATION: AssessmentStage.REVIEW,
            }[stage]
            self.core._cancel_downstream(
                current,
                starting_stage=next_stage,
                reason=reason,
            )
            return current
        self.core._cancel_downstream(
            current,
            starting_stage=AssessmentStage.REVIEW,
            reason=reason,
        )
        return current

    @staticmethod
    def _initial_statuses(state: str) -> dict[AssessmentStage, NodeStatus]:
        normalized = state.strip().casefold()
        statuses = {
            AssessmentStage.AUTHORIZATION: NodeStatus.COMPLETED,
            AssessmentStage.PLAN: NodeStatus.COMPLETED,
            AssessmentStage.APPROVAL: NodeStatus.WAITING_FOR_HUMAN_APPROVAL,
            AssessmentStage.EXECUTION: NodeStatus.PENDING,
            AssessmentStage.EVIDENCE: NodeStatus.PENDING,
            AssessmentStage.VERIFICATION: NodeStatus.PENDING,
            AssessmentStage.REVIEW: NodeStatus.PENDING,
            AssessmentStage.REPORT: NodeStatus.PENDING,
        }
        if normalized == "approved":
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
        elif normalized == "queued":
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EXECUTION] = NodeStatus.READY
        elif normalized in {"provisioning", "running"}:
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EXECUTION] = NodeStatus.RUNNING
        elif normalized in {"evaluating", "cleaning"}:
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EXECUTION] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EVIDENCE] = NodeStatus.COMPLETED
            statuses[AssessmentStage.VERIFICATION] = NodeStatus.RUNNING
        elif normalized == "completed":
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EXECUTION] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EVIDENCE] = NodeStatus.COMPLETED
            statuses[AssessmentStage.VERIFICATION] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REVIEW] = NodeStatus.READY
        elif normalized == "cancelled":
            for stage in (
                AssessmentStage.APPROVAL,
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
                AssessmentStage.REPORT,
            ):
                statuses[stage] = NodeStatus.CANCELLED
        elif normalized in {"blocked", "failed"}:
            statuses[AssessmentStage.APPROVAL] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EXECUTION] = (
                NodeStatus.FAILED if normalized == "failed" else NodeStatus.BLOCKED
            )
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
            AssessmentStage.AUTHORIZATION: "active-validation-scope-guardian",
            AssessmentStage.PLAN: "active-validation-planner",
            AssessmentStage.APPROVAL: "independent-validation-approver",
            AssessmentStage.EXECUTION: "isolated-validation-worker",
            AssessmentStage.EVIDENCE: "validation-evidence-curator",
            AssessmentStage.VERIFICATION: "impact-verification-evaluator",
            AssessmentStage.REVIEW: "review-coordinator",
            AssessmentStage.REPORT: "report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding-and-authorization-binding",
            AssessmentStage.PLAN: "synthetic-validation-planning",
            AssessmentStage.APPROVAL: "independent-plan-digest-approval",
            AssessmentStage.EXECUTION: "isolated-clean-snapshot-validation",
            AssessmentStage.EVIDENCE: "synthetic-trial-evidence-validation",
            AssessmentStage.VERIFICATION: "bounded-impact-evaluation",
            AssessmentStage.REVIEW: "governed-independent-review",
            AssessmentStage.REPORT: "evidence-backed-reporting",
        }[stage]

    @staticmethod
    def _action_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "active-validation.authorization.validate",
            AssessmentStage.PLAN: "active-validation.plan.create",
            AssessmentStage.APPROVAL: "active-validation.approval.validate",
            AssessmentStage.EXECUTION: "active-validation.trials.execute",
            AssessmentStage.EVIDENCE: "active-validation.evidence.normalize",
            AssessmentStage.VERIFICATION: "active-validation.result.evaluate",
            AssessmentStage.REVIEW: "active-validation.review.request",
            AssessmentStage.REPORT: "active-validation.report.generate",
        }[stage]

    @staticmethod
    def _action_class_for_stage(stage: AssessmentStage) -> ActionClass:
        if stage == AssessmentStage.EXECUTION:
            return ActionClass.CONSEQUENTIAL
        if stage == AssessmentStage.REVIEW:
            return ActionClass.REVERSIBLE_LOCAL
        return ActionClass.READ_ONLY

    @staticmethod
    def _tool_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "authorization-store",
            AssessmentStage.PLAN: "active-validation-planner",
            AssessmentStage.APPROVAL: "approval-service",
            AssessmentStage.EXECUTION: "adversary-lab-synthetic-runner",
            AssessmentStage.EVIDENCE: "validation-evidence-store",
            AssessmentStage.VERIFICATION: "active-validation-evaluator",
            AssessmentStage.REVIEW: "review-service",
            AssessmentStage.REPORT: "report-service",
        }[stage]

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage, *, scenario_id: str) -> str:
        return {
            AssessmentStage.AUTHORIZATION: (
                "Validate the parent assessment, finding and exact authorization binding."
            ),
            AssessmentStage.PLAN: (
                f"Create the immutable synthetic-only plan for reviewed scenario {scenario_id}."
            ),
            AssessmentStage.APPROVAL: (
                "Require an independent approver and password step-up for the exact plan digest."
            ),
            AssessmentStage.EXECUTION: (
                "Run only reviewed generated-data trials in the isolated no-egress worker."
            ),
            AssessmentStage.EVIDENCE: (
                "Validate trial hashes, snapshot restoration and cleanup evidence."
            ),
            AssessmentStage.VERIFICATION: (
                "Evaluate the bounded trial evidence without bypassing human review."
            ),
            AssessmentStage.REVIEW: "Request governed human review of the validation result.",
            AssessmentStage.REPORT: "Generate an evidence-backed validation report.",
        }[stage]


__all__ = ["ActiveValidationAssessmentGraphService"]
