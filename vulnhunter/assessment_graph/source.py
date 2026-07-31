"""Persist and project authoritative Source Hunt lifecycle graphs."""

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


class SourceAssessmentGraphService:
    """Bind one exact Source Hunt job to the shared assessment lifecycle."""

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
        repository_id: str,
        revision: str,
        snapshot_sha256: str,
        approval_sha256: str,
        plan_digest: str,
        expires_at: datetime,
        model: str,
        execution_state: str,
        execution_reason: str | None = None,
    ) -> AssessmentGraphBundle:
        """Create the eight-stage source graph without replacing the queue worker."""

        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AssessmentGraphError("source assessment graph expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise AssessmentGraphError("source assessment graph expiry must be in the future")
        try:
            parsed_workspace = UUID(workspace_id) if workspace_id else None
        except ValueError as exc:
            raise AssessmentGraphError("workspace binding must be a valid UUID") from exc
        for label, value in (
            ("snapshot", snapshot_sha256),
            ("approval", approval_sha256),
            ("plan", plan_digest),
        ):
            if len(value) != 64:
                raise AssessmentGraphError(f"Source Hunt requires the exact {label} SHA-256")

        graph_id = self.core.graph_id_for_run(run_id)
        target_references = (
            repository_id,
            f"source-revision:{revision}",
            f"source-snapshot:{snapshot_sha256}",
            f"source-plan:{plan_digest}",
        )
        statuses = self._initial_statuses(execution_state)
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        node_stages: dict[str, AssessmentStage] = {}
        previous_node: str | None = None

        for stage in AssessmentStage:
            node_id = f"{run_id}-{stage.value}"
            manifest = ActionManifest(
                manifest_id=node_id,
                campaign_id=run_id,
                requested_by=owner_id,
                role_id=self._role_for_stage(stage),
                skill_id=self._skill_for_stage(stage),
                action=self._action_for_stage(stage),
                action_class=self._action_class_for_stage(stage),
                tool_id=self._tool_for_stage(stage),
                operation="groq-source-hunt",
                target_references=target_references,
                authorization_references=(authorization_id,),
                limits=ExecutionLimits(
                    timeout_seconds=3_600 if stage == AssessmentStage.EXECUTION else 900,
                    maximum_requests=1,
                    maximum_output_bytes=(
                        50_000_000 if stage == AssessmentStage.EXECUTION else 10_000_000
                    ),
                    maximum_targets=4,
                    maximum_attempts=2 if stage == AssessmentStage.EXECUTION else 1,
                ),
                approval_required=False,
                created_at=now,
                expires_at=expiry,
                parent_manifest_sha256=plan_digest,
                purpose=self._purpose_for_stage(stage, model=model),
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
                        execution_reason
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
            campaign_id=run_id,
            run_id=run_id,
            nodes=tuple(nodes),
            created_at=now,
            updated_at=now,
        )
        bundle = AssessmentGraphBundle(
            graph_id=graph_id,
            run_id=run_id,
            assessment_kind=AssessmentKind.SOURCE,
            workspace_id=parsed_workspace,
            owner_id=owner_id,
            authorization_id=authorization_id,
            target_reference=f"source-snapshot:{snapshot_sha256}",
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
            raise AssessmentGraphError("Source Hunt graph persistence failed closed") from exc
        return bundle

    def project_execution(
        self,
        run_id: str,
        *,
        state: str,
        reason: str | None = None,
    ) -> bool:
        """Project observed queue and worker state without execution authority."""

        graph = self.core._load_optional(run_id)
        if graph is None:
            return False
        normalized = state.strip().casefold()
        execution = self.core._stage_node(graph, AssessmentStage.EXECUTION)

        if normalized in {"prepared", "queued"}:
            return True
        if normalized == "running":
            if execution.status in {NodeStatus.PENDING, NodeStatus.READY}:
                self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
            return True

        if normalized == "completed":
            if execution.status in {NodeStatus.PENDING, NodeStatus.READY}:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
                execution = self.core._stage_node(graph, AssessmentStage.EXECUTION)
            if execution.status == NodeStatus.RUNNING:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.COMPLETED,
                    last_error=None,
                )
            elif execution.status != NodeStatus.COMPLETED:
                return True
            evidence = self.core._stage_node(graph, AssessmentStage.EVIDENCE)
            if evidence.status == NodeStatus.PENDING:
                graph = self.core._transition(
                    graph,
                    node_id=evidence.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
                evidence = self.core._stage_node(graph, AssessmentStage.EVIDENCE)
            if evidence.status == NodeStatus.RUNNING:
                graph = self.core._transition(
                    graph,
                    node_id=evidence.node_id,
                    status=NodeStatus.COMPLETED,
                    last_error=None,
                )
            verification = self.core._stage_node(graph, AssessmentStage.VERIFICATION)
            if verification.status == NodeStatus.PENDING:
                self.core._transition(
                    graph,
                    node_id=verification.node_id,
                    status=NodeStatus.READY,
                    last_error=None,
                )
            return True

        if normalized in {"gated", "blocked", "rejected"}:
            if execution.status not in TERMINAL_STATUSES:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.BLOCKED,
                    last_error=reason or "The governed Source Hunt worker is unavailable.",
                )
            self.core._cancel_downstream(
                graph,
                starting_stage=AssessmentStage.EVIDENCE,
                reason=reason or "Source Hunt execution did not start.",
            )
            return True

        if normalized == "failed":
            if execution.status in {NodeStatus.PENDING, NodeStatus.READY}:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
                execution = self.core._stage_node(graph, AssessmentStage.EXECUTION)
            if execution.status == NodeStatus.RUNNING:
                graph = self.core._transition(
                    graph,
                    node_id=execution.node_id,
                    status=NodeStatus.FAILED,
                    last_error=reason or "The governed Source Hunt worker failed safely.",
                )
            self.core._cancel_downstream(
                graph,
                starting_stage=AssessmentStage.EVIDENCE,
                reason=reason or "Source Hunt failure prevented evidence completion.",
            )
            return True

        if normalized == "cancelled":
            return self.core.project_terminal(
                run_id,
                outcome="cancelled",
                reason=reason or "The Source Hunt was cancelled from chat.",
            )
        return True

    def status_payload(self, run_id: str) -> dict[str, object] | None:
        payload = self.core.status_payload(run_id)
        if payload is None:
            return None
        nodes = payload.get("nodes")
        if isinstance(nodes, list):
            by_stage = {
                str(item.get("stage")): str(item.get("status"))
                for item in nodes
                if isinstance(item, dict)
            }
            if (
                by_stage.get(AssessmentStage.EVIDENCE.value) == NodeStatus.COMPLETED.value
                and by_stage.get(AssessmentStage.VERIFICATION.value) == NodeStatus.READY.value
            ):
                payload["chat_stage"] = "awaiting_verification"
        return payload

    @staticmethod
    def _initial_statuses(execution_state: str) -> dict[AssessmentStage, NodeStatus]:
        normalized = execution_state.strip().casefold()
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
        if normalized == "running":
            statuses[AssessmentStage.EXECUTION] = NodeStatus.RUNNING
        elif normalized == "completed":
            statuses[AssessmentStage.EXECUTION] = NodeStatus.COMPLETED
            statuses[AssessmentStage.EVIDENCE] = NodeStatus.COMPLETED
            statuses[AssessmentStage.VERIFICATION] = NodeStatus.READY
        elif normalized in {"gated", "blocked", "rejected"}:
            statuses[AssessmentStage.EXECUTION] = NodeStatus.BLOCKED
            for stage in (
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
                AssessmentStage.REPORT,
            ):
                statuses[stage] = NodeStatus.CANCELLED
        elif normalized == "failed":
            statuses[AssessmentStage.EXECUTION] = NodeStatus.FAILED
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
            AssessmentStage.AUTHORIZATION: "source-snapshot-guardian",
            AssessmentStage.PLAN: "source-hunt-orchestrator",
            AssessmentStage.APPROVAL: "remote-source-policy-gate",
            AssessmentStage.EXECUTION: "source-security-analyst",
            AssessmentStage.EVIDENCE: "source-evidence-curator",
            AssessmentStage.VERIFICATION: "source-security-verifier",
            AssessmentStage.REVIEW: "review-coordinator",
            AssessmentStage.REPORT: "report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "exact-source-snapshot-validation",
            AssessmentStage.PLAN: "attacker-first-source-hunt-planning",
            AssessmentStage.APPROVAL: "remote-source-processing-approval-validation",
            AssessmentStage.EXECUTION: "bounded-source-hunt-analysis",
            AssessmentStage.EVIDENCE: "source-reference-and-evidence-validation",
            AssessmentStage.VERIFICATION: "independent-source-finding-verification",
            AssessmentStage.REVIEW: "governed-independent-review",
            AssessmentStage.REPORT: "evidence-backed-reporting",
        }[stage]

    @staticmethod
    def _action_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "source.snapshot.validate",
            AssessmentStage.PLAN: "source.plan.create",
            AssessmentStage.APPROVAL: "source.remote-processing.validate",
            AssessmentStage.EXECUTION: "source.hunt.execute",
            AssessmentStage.EVIDENCE: "source.evidence.normalize",
            AssessmentStage.VERIFICATION: "source.finding.verify",
            AssessmentStage.REVIEW: "source.review.request",
            AssessmentStage.REPORT: "source.report.generate",
        }[stage]

    @staticmethod
    def _action_class_for_stage(stage: AssessmentStage) -> ActionClass:
        if stage in {AssessmentStage.EXECUTION, AssessmentStage.REVIEW}:
            return ActionClass.REVERSIBLE_LOCAL
        return ActionClass.READ_ONLY

    @staticmethod
    def _tool_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "source-snapshot-builder",
            AssessmentStage.PLAN: "source-hunt-planner",
            AssessmentStage.APPROVAL: "source-processing-approval-store",
            AssessmentStage.EXECUTION: "source-hunt-worker",
            AssessmentStage.EVIDENCE: "source-evidence-validator",
            AssessmentStage.VERIFICATION: "machine-oracle",
            AssessmentStage.REVIEW: "review-service",
            AssessmentStage.REPORT: "report-service",
        }[stage]

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage, *, model: str) -> str:
        return {
            AssessmentStage.AUTHORIZATION: (
                "Validate the exact repository revision, snapshot digest and permitted paths."
            ),
            AssessmentStage.PLAN: "Create the immutable bounded attacker-first source hunt plan.",
            AssessmentStage.APPROVAL: (
                "Validate password step-up and the exact Groq source-processing approval."
            ),
            AssessmentStage.EXECUTION: (
                f"Run the bounded Source Hunt through the separate worker using {model}."
            ),
            AssessmentStage.EVIDENCE: (
                "Validate every source path, hash, line range and retained candidate."
            ),
            AssessmentStage.VERIFICATION: (
                "Verify retained source candidates independently from model claims."
            ),
            AssessmentStage.REVIEW: "Request governed independent review of source candidates.",
            AssessmentStage.REPORT: "Generate an evidence-backed source assessment report.",
        }[stage]


__all__ = ["SourceAssessmentGraphService"]
