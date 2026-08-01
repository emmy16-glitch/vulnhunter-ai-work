"""Persist and project authoritative governed retest task graphs."""

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

_RESULT_PREFIX = "Governed retest result: "


class RetestAssessmentGraphService:
    """Bind one exact retest plan to a durable chat workspace and task graph."""

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
        retest_id: str,
        workspace_id: str,
        owner_id: str,
        campaign_id: str,
        finding_id: str,
        finding_fingerprint: str,
        source_finding_revision: int,
        remediation_id: str,
        fix_verification_receipt_id: str,
        fixed_revision: str,
        plan_sha256: str,
        check_references: tuple[str, ...],
        expires_at: datetime,
    ) -> AssessmentGraphBundle:
        now = self.clock().astimezone(UTC)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AssessmentGraphError("retest graph expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise AssessmentGraphError("retest graph expiry must be in the future")
        try:
            parsed_workspace = UUID(workspace_id)
        except ValueError as exc:
            raise AssessmentGraphError("retest requires a valid chat workspace UUID") from exc
        if len(finding_fingerprint) != 64 or len(plan_sha256) != 64:
            raise AssessmentGraphError("retest requires exact finding and plan SHA-256 values")
        if source_finding_revision < 0:
            raise AssessmentGraphError("retest source finding revision cannot be negative")
        if not check_references:
            raise AssessmentGraphError("retest requires exact bounded check references")

        graph_id = self.core.graph_id_for_run(retest_id)
        references = (
            finding_id,
            remediation_id,
            fix_verification_receipt_id,
            f"finding-fingerprint:{finding_fingerprint}",
            f"finding-revision:{source_finding_revision}",
            f"fixed-revision:{fixed_revision}",
            f"retest-plan:{plan_sha256}",
            *check_references,
        )
        statuses = {
            AssessmentStage.AUTHORIZATION: NodeStatus.COMPLETED,
            AssessmentStage.PLAN: NodeStatus.COMPLETED,
            AssessmentStage.APPROVAL: NodeStatus.COMPLETED,
            AssessmentStage.EXECUTION: NodeStatus.READY,
            AssessmentStage.EVIDENCE: NodeStatus.PENDING,
            AssessmentStage.VERIFICATION: NodeStatus.PENDING,
            AssessmentStage.REVIEW: NodeStatus.PENDING,
            AssessmentStage.REPORT: NodeStatus.PENDING,
        }
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        node_stages: dict[str, AssessmentStage] = {}
        previous_node: str | None = None

        for stage in AssessmentStage:
            node_id = f"{retest_id}-{stage.value}"
            manifest = ActionManifest(
                manifest_id=node_id,
                campaign_id=campaign_id,
                requested_by=owner_id,
                role_id=self._role_for_stage(stage),
                skill_id=self._skill_for_stage(stage),
                action=self._action_for_stage(stage),
                action_class=self._action_class_for_stage(stage),
                tool_id=self._tool_for_stage(stage),
                operation="human-governed-retest",
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
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    role_id=manifest.role_id,
                    skill_id=manifest.skill_id,
                    action_manifest_sha256=manifest.fingerprint(),
                    dependencies=(() if previous_node is None else (previous_node,)),
                    status=statuses[stage],
                    maximum_attempts=1,
                    updated_at=now,
                )
            )
            node_stages[node_id] = stage
            previous_node = node_id

        graph = TaskGraph(
            graph_id=graph_id,
            campaign_id=campaign_id,
            run_id=retest_id,
            nodes=tuple(nodes),
            created_at=now,
            updated_at=now,
        )
        bundle = AssessmentGraphBundle(
            graph_id=graph_id,
            run_id=retest_id,
            assessment_kind=AssessmentKind.RETEST,
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
            raise AssessmentGraphError("retest graph persistence failed closed") from exc
        return bundle

    def project_outcome(
        self,
        retest_id: str,
        *,
        receipt_id: str,
        outcome: str,
        reason: str | None = None,
    ) -> bool:
        graph = self.core._load_optional(retest_id)
        if graph is None:
            return False
        normalized = outcome.strip().casefold()
        marker = f"{_RESULT_PREFIX}{normalized}; receipt={receipt_id}"
        verification = self.core._stage_node(graph, AssessmentStage.VERIFICATION)
        if verification.status in TERMINAL_STATUSES and verification.last_error == marker:
            return True
        if normalized == "cancelled":
            return self.core.project_terminal(
                retest_id,
                outcome="cancelled",
                reason=reason or "The governed retest was cancelled by its human operator.",
            )

        graph = self._complete_stage(graph, AssessmentStage.EXECUTION)
        graph = self._complete_stage(graph, AssessmentStage.EVIDENCE)
        if normalized == "passed":
            graph = self._complete_stage(graph, AssessmentStage.VERIFICATION)
            review = self.core._stage_node(graph, AssessmentStage.REVIEW)
            if review.status == NodeStatus.PENDING:
                self.core._transition(
                    graph,
                    node_id=review.node_id,
                    status=NodeStatus.READY,
                    last_error=None,
                )
            return True

        blocked = normalized in {"partial", "cannot_verify", "blocked"}
        verification = self.core._stage_node(graph, AssessmentStage.VERIFICATION)
        if verification.status in {NodeStatus.PENDING, NodeStatus.READY}:
            graph = self.core._transition(
                graph,
                node_id=verification.node_id,
                status=NodeStatus.RUNNING,
                last_error=None,
            )
        verification = self.core._stage_node(graph, AssessmentStage.VERIFICATION)
        if verification.status == NodeStatus.RUNNING:
            graph = self.core._transition(
                graph,
                node_id=verification.node_id,
                status=NodeStatus.BLOCKED if blocked else NodeStatus.FAILED,
                last_error=marker if reason is None else f"{marker}; reason={reason[:1_000]}",
            )
        self.core._cancel_downstream(
            graph,
            starting_stage=AssessmentStage.REVIEW,
            reason=marker,
        )
        return True

    def _complete_stage(self, graph: TaskGraph, stage: AssessmentStage) -> TaskGraph:
        node = self.core._stage_node(graph, stage)
        if node.status == NodeStatus.COMPLETED:
            return graph
        if node.status in TERMINAL_STATUSES:
            raise AssessmentGraphError("terminal retest stages cannot be completed later")
        if node.status in {NodeStatus.PENDING, NodeStatus.READY}:
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

    def status_payload(self, retest_id: str) -> dict[str, object] | None:
        payload = self.core.status_payload(retest_id)
        if payload is None:
            return None
        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            return payload
        by_stage = {str(item.get("stage")): item for item in nodes if isinstance(item, dict)}
        execution = by_stage.get(AssessmentStage.EXECUTION.value, {})
        verification = by_stage.get(AssessmentStage.VERIFICATION.value, {})
        review = by_stage.get(AssessmentStage.REVIEW.value, {})
        execution_status = str(execution.get("status") or "")
        verification_status = str(verification.get("status") or "")
        verification_error = str(verification.get("last_error") or "")
        review_status = str(review.get("status") or "")

        if review_status == NodeStatus.READY.value:
            payload["chat_stage"] = "retest_passed_awaiting_independent_review"
            payload["report_state"] = "blocked_pending_independent_review"
        elif verification_status == NodeStatus.FAILED.value:
            payload["chat_stage"] = "retest_requires_rework"
            payload["report_state"] = "blocked_rework_required"
        elif verification_status == NodeStatus.BLOCKED.value:
            if "cannot_verify" in verification_error:
                payload["chat_stage"] = "retest_cannot_verify"
            elif "partial" in verification_error:
                payload["chat_stage"] = "retest_partial_requires_rework"
            else:
                payload["chat_stage"] = "retest_blocked"
            payload["report_state"] = "blocked_rework_required"
        elif execution_status == NodeStatus.CANCELLED.value:
            payload["chat_stage"] = "retest_cancelled"
            payload["report_state"] = "blocked_pending_retest"
        else:
            payload["chat_stage"] = "retest_ready_for_evidence"
            payload["report_state"] = "blocked_pending_retest"
        return payload

    @staticmethod
    def _role_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding-governance-guardian",
            AssessmentStage.PLAN: "retest-planner",
            AssessmentStage.APPROVAL: "retest-operator",
            AssessmentStage.EXECUTION: "bounded-retest-runner",
            AssessmentStage.EVIDENCE: "before-after-evidence-curator",
            AssessmentStage.VERIFICATION: "independent-retest-verifier",
            AssessmentStage.REVIEW: "independent-remediation-reviewer",
            AssessmentStage.REPORT: "remediation-report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "verified-finding-and-fixed-revision-validation",
            AssessmentStage.PLAN: "bounded-retest-planning",
            AssessmentStage.APPROVAL: "exact-retest-step-up-confirmation",
            AssessmentStage.EXECUTION: "claim-specific-retest-execution",
            AssessmentStage.EVIDENCE: "before-after-evidence-comparison",
            AssessmentStage.VERIFICATION: "deterministic-retest-verification",
            AssessmentStage.REVIEW: "independent-remediation-review-readiness",
            AssessmentStage.REPORT: "preliminary-remediation-report-readiness",
        }[stage]

    @staticmethod
    def _action_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "finding.retest.authorize",
            AssessmentStage.PLAN: "finding.retest.plan",
            AssessmentStage.APPROVAL: "finding.retest.confirm",
            AssessmentStage.EXECUTION: "finding.retest.execute",
            AssessmentStage.EVIDENCE: "finding.retest.evidence",
            AssessmentStage.VERIFICATION: "finding.retest.verify",
            AssessmentStage.REVIEW: "finding.remediation.review.ready",
            AssessmentStage.REPORT: "finding.remediation.report.ready",
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
            AssessmentStage.PLAN: "governed-retest-service",
            AssessmentStage.APPROVAL: "password-step-up",
            AssessmentStage.EXECUTION: "separately-controlled-retest-runner",
            AssessmentStage.EVIDENCE: "retest-receipt-store",
            AssessmentStage.VERIFICATION: "deterministic-retest-verifier",
            AssessmentStage.REVIEW: "review-service",
            AssessmentStage.REPORT: "report-service",
        }[stage]

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: (
                "Validate the exact verified finding, remediation, fixed receipt and campaign."
            ),
            AssessmentStage.PLAN: (
                "Bind the exact fixed revision, original evidence and claim-specific checks."
            ),
            AssessmentStage.APPROVAL: (
                "Record fresh human confirmation without granting review or release authority."
            ),
            AssessmentStage.EXECUTION: (
                "Wait for bounded claim-specific checks through separately controlled tools."
            ),
            AssessmentStage.EVIDENCE: (
                "Persist typed before/after evidence and deterministic check receipts."
            ),
            AssessmentStage.VERIFICATION: (
                "Compute a truthful pass, fail, partial, blocked or cannot-verify outcome."
            ),
            AssessmentStage.REVIEW: (
                "Open independent remediation review only after a passed retest."
            ),
            AssessmentStage.REPORT: (
                "Keep reporting blocked until independent review is completed."
            ),
        }[stage]


__all__ = ["RetestAssessmentGraphService"]
