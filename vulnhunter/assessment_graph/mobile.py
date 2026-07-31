"""Persist and project authoritative APK assessment lifecycle graphs."""

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


class MobileAssessmentGraphService:
    """Bind one chat APK hunt and its real worker state to the shared lifecycle."""

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
        artifact_id: str,
        artifact_sha256: str,
        expires_at: datetime,
        profile: str,
        plan_digest: str,
        execution_state: str,
        execution_reason: str | None = None,
    ) -> AssessmentGraphBundle:
        """Create the shared eight-stage APK graph without replacing the worker."""

        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AssessmentGraphError("assessment graph expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise AssessmentGraphError("assessment graph expiry must be in the future")
        try:
            parsed_workspace = UUID(workspace_id) if workspace_id else None
        except ValueError as exc:
            raise AssessmentGraphError("workspace binding must be a valid UUID") from exc
        if len(artifact_sha256) != 64:
            raise AssessmentGraphError("APK assessment requires the exact artifact SHA-256")
        if len(plan_digest) != 64:
            raise AssessmentGraphError("APK assessment requires the exact hunt plan digest")

        graph_id = self.core.graph_id_for_run(run_id)
        target_references = (
            artifact_id,
            f"apk-sha256:{artifact_sha256}",
            f"plan-sha256:{plan_digest}",
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
                operation=profile,
                target_references=target_references,
                authorization_references=(authorization_id,),
                limits=ExecutionLimits(
                    timeout_seconds=1_800 if stage == AssessmentStage.EXECUTION else 600,
                    maximum_requests=1,
                    maximum_output_bytes=(
                        50_000_000 if stage == AssessmentStage.EXECUTION else 10_000_000
                    ),
                    maximum_targets=3,
                    maximum_attempts=2 if stage == AssessmentStage.EXECUTION else 1,
                ),
                approval_required=False,
                created_at=now,
                expires_at=expiry,
                parent_manifest_sha256=plan_digest,
                purpose=self._purpose_for_stage(stage, profile=profile),
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
            assessment_kind=AssessmentKind.APK,
            workspace_id=parsed_workspace,
            owner_id=owner_id,
            authorization_id=authorization_id,
            target_reference=f"apk-sha256:{artifact_sha256}",
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
            raise AssessmentGraphError("APK assessment graph persistence failed closed") from exc
        return bundle

    def project_execution(
        self,
        run_id: str,
        *,
        state: str,
        reason: str | None = None,
    ) -> bool:
        """Project only observed worker state; never start or approve execution."""

        graph = self.core._load_optional(run_id)
        if graph is None:
            return False
        normalized = state.strip().casefold()
        execution = self.core._stage_node(graph, AssessmentStage.EXECUTION)

        if normalized in {"prepared", "queued", "running"}:
            if normalized in {"queued", "running"} and execution.status in {
                NodeStatus.PENDING,
                NodeStatus.READY,
            }:
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
                    last_error=reason or "The governed APK worker is unavailable.",
                )
            self.core._cancel_downstream(
                graph,
                starting_stage=AssessmentStage.EVIDENCE,
                reason=reason or "APK execution did not start.",
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
                    last_error=reason or "The governed APK worker failed safely.",
                )
            self.core._cancel_downstream(
                graph,
                starting_stage=AssessmentStage.EVIDENCE,
                reason=reason or "APK worker failure prevented evidence completion.",
            )
            return True

        if normalized == "cancelled":
            return self.core.project_terminal(
                run_id,
                outcome="cancelled",
                reason=reason or "The APK assessment was cancelled from chat.",
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
        if normalized in {"queued", "running"}:
            statuses[AssessmentStage.EXECUTION] = NodeStatus.RUNNING
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
            AssessmentStage.AUTHORIZATION: "mobile-artifact-guardian",
            AssessmentStage.PLAN: "mobile-assessment-orchestrator",
            AssessmentStage.APPROVAL: "mobile-policy-gate",
            AssessmentStage.EXECUTION: "mobile-application-security-analyst",
            AssessmentStage.EVIDENCE: "mobile-evidence-curator",
            AssessmentStage.VERIFICATION: "mobile-security-verifier",
            AssessmentStage.REVIEW: "review-coordinator",
            AssessmentStage.REPORT: "report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "uploaded-artifact-integrity-validation",
            AssessmentStage.PLAN: "android-analysis-planning",
            AssessmentStage.APPROVAL: "mobile-worker-policy-validation",
            AssessmentStage.EXECUTION: "android-apk-static-analysis",
            AssessmentStage.EVIDENCE: "mobile-evidence-normalization",
            AssessmentStage.VERIFICATION: "independent-mobile-finding-verification",
            AssessmentStage.REVIEW: "governed-independent-review",
            AssessmentStage.REPORT: "evidence-backed-reporting",
        }[stage]

    @staticmethod
    def _action_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "apk.artifact.validate",
            AssessmentStage.PLAN: "apk.plan.create",
            AssessmentStage.APPROVAL: "apk.policy.validate",
            AssessmentStage.EXECUTION: "apk.static.execute",
            AssessmentStage.EVIDENCE: "apk.evidence.normalize",
            AssessmentStage.VERIFICATION: "apk.finding.verify",
            AssessmentStage.REVIEW: "apk.review.request",
            AssessmentStage.REPORT: "apk.report.generate",
        }[stage]

    @staticmethod
    def _action_class_for_stage(stage: AssessmentStage) -> ActionClass:
        if stage == AssessmentStage.EXECUTION:
            return ActionClass.REVERSIBLE_LOCAL
        if stage == AssessmentStage.REVIEW:
            return ActionClass.REVERSIBLE_LOCAL
        return ActionClass.READ_ONLY

    @staticmethod
    def _tool_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "mobile-artifact-store",
            AssessmentStage.PLAN: "mobile-analysis-planner",
            AssessmentStage.APPROVAL: "mobile-worker-policy",
            AssessmentStage.EXECUTION: "mobile-static-worker",
            AssessmentStage.EVIDENCE: "mobile-evidence-normalizer",
            AssessmentStage.VERIFICATION: "machine-oracle",
            AssessmentStage.REVIEW: "review-service",
            AssessmentStage.REPORT: "report-service",
        }[stage]

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage, *, profile: str) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "Validate the uploaded APK identity and content hash.",
            AssessmentStage.PLAN: "Create the immutable bounded APK hunt plan.",
            AssessmentStage.APPROVAL: "Validate the exact local worker policy and artifact binding.",
            AssessmentStage.EXECUTION: (
                f"Run the bounded {profile} APK analysis through the isolated static worker."
            ),
            AssessmentStage.EVIDENCE: "Normalize and hash bounded APK tool evidence.",
            AssessmentStage.VERIFICATION: "Verify mobile candidates against raw evidence.",
            AssessmentStage.REVIEW: "Request governed independent review of mobile candidates.",
            AssessmentStage.REPORT: "Generate an evidence-backed APK assessment report.",
        }[stage]


__all__ = ["MobileAssessmentGraphService"]
