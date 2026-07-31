"""Persist and project chat-first assessment task graphs without execution authority."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from vulnhunter.actions.models import ActionClass, ActionManifest, ExecutionLimits, sha256_json
from vulnhunter.assessment_graph.models import (
    AssessmentGraphBundle,
    AssessmentKind,
    AssessmentStage,
)
from vulnhunter.taskgraph.models import TERMINAL_STATUSES, GraphNode, NodeStatus, TaskGraph
from vulnhunter.taskgraph.store import TaskGraphStore, TaskGraphStoreError


class AssessmentGraphError(RuntimeError):
    """The authoritative assessment graph could not be created or projected safely."""


class AssessmentGraphService:
    """Own immutable chat bindings and lifecycle projections for assessment graphs."""

    def __init__(
        self,
        root: Path,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.graph_store = TaskGraphStore(self.root)
        self.clock = clock

    @staticmethod
    def graph_id_for_run(run_id: str) -> str:
        return f"{run_id}-graph"

    def create_website_assessment(
        self,
        *,
        run_id: str,
        workspace_id: str | None,
        owner_id: str,
        authorization_id: str,
        target: str,
        expires_at: datetime,
        profile: str,
        plan_digest: str | None,
        readiness_blocked: bool,
    ) -> AssessmentGraphBundle:
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

        graph_id = self.graph_id_for_run(run_id)
        stage_specs = self._website_stage_specs(
            plan_digest=plan_digest,
            readiness_blocked=readiness_blocked,
        )
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        node_stages: dict[str, AssessmentStage] = {}
        previous_node: str | None = None
        parent_reference = f"plan-sha256:{plan_digest}" if plan_digest else "plan-unavailable"

        for (
            stage,
            action,
            action_class,
            tool_id,
            operation,
            approval_required,
            status,
        ) in stage_specs:
            node_id = f"{run_id}-{stage.value}"
            manifest = ActionManifest(
                manifest_id=node_id,
                campaign_id=run_id,
                requested_by=owner_id,
                role_id=self._role_for_stage(stage),
                skill_id=self._skill_for_stage(stage),
                action=action,
                action_class=action_class,
                tool_id=tool_id,
                operation=operation,
                target_references=(target, parent_reference),
                authorization_references=(authorization_id,),
                limits=ExecutionLimits(
                    timeout_seconds=self._timeout_for_stage(stage),
                    maximum_requests=100 if stage == AssessmentStage.EXECUTION else 1,
                    maximum_output_bytes=(
                        10_000_000 if stage == AssessmentStage.EXECUTION else 2_000_000
                    ),
                    maximum_targets=2,
                    maximum_attempts=2 if stage == AssessmentStage.EXECUTION else 1,
                ),
                approval_required=approval_required,
                created_at=now,
                expires_at=expiry,
                parent_manifest_sha256=plan_digest,
                purpose=self._purpose_for_stage(stage, profile=profile),
            )
            manifests.append(manifest)
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    role_id=manifest.role_id,
                    skill_id=manifest.skill_id,
                    action_manifest_sha256=manifest.fingerprint(),
                    dependencies=(() if previous_node is None else (previous_node,)),
                    status=status,
                    maximum_attempts=manifest.limits.maximum_attempts,
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
            assessment_kind=AssessmentKind.WEBSITE,
            workspace_id=parsed_workspace,
            owner_id=owner_id,
            authorization_id=authorization_id,
            target_reference=target,
            node_stages=node_stages,
            manifests=tuple(manifests),
            created_at=now,
        )
        self._validate_graph_binding(graph, bundle)
        bundle_path = self._write_bundle(bundle)
        try:
            self.graph_store.save(graph)
        except (OSError, TaskGraphStoreError, ValueError) as exc:
            bundle_path.unlink(missing_ok=True)
            raise AssessmentGraphError("assessment task graph persistence failed closed") from exc
        return bundle

    def status_payload(self, run_id: str) -> dict[str, object] | None:
        graph_id = self.graph_id_for_run(run_id)
        try:
            graph = self.graph_store.load(graph_id)
        except TaskGraphStoreError as exc:
            if "does not exist" in str(exc):
                return None
            raise AssessmentGraphError("assessment task graph could not be loaded") from exc
        bundle = self._load_bundle(graph_id)
        self._validate_graph_binding(graph, bundle)
        by_stage = {bundle.node_stages[node.node_id]: node for node in graph.nodes}
        return {
            "graph_id": graph.graph_id,
            "run_id": graph.run_id,
            "workspace_id": str(bundle.workspace_id) if bundle.workspace_id else None,
            "assessment_kind": bundle.assessment_kind.value,
            "revision": graph.revision,
            "chat_stage": self._chat_stage(by_stage),
            "nodes": [
                {
                    "node_id": node.node_id,
                    "stage": bundle.node_stages[node.node_id].value,
                    "status": node.status.value,
                    "attempts": node.attempts,
                    "last_error": node.last_error,
                }
                for node in graph.nodes
            ],
        }

    def project_approval(
        self,
        run_id: str,
        *,
        approved: bool,
        execution_intended: bool,
        reason: str,
    ) -> bool:
        graph = self._load_optional(run_id)
        if graph is None:
            return False
        approval = self._stage_node(graph, AssessmentStage.APPROVAL)

        if approved:
            if approval.status == NodeStatus.WAITING_FOR_HUMAN_APPROVAL:
                graph = self._transition(
                    graph,
                    node_id=approval.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
                graph = self._transition(
                    graph,
                    node_id=approval.node_id,
                    status=NodeStatus.COMPLETED,
                    last_error=None,
                )
            elif approval.status != NodeStatus.COMPLETED:
                raise AssessmentGraphError(
                    "approval projection conflicts with terminal graph state"
                )
            execution_status = NodeStatus.RUNNING if execution_intended else NodeStatus.BLOCKED
            execution_reason = None if execution_intended else reason
            execution = self._stage_node(graph, AssessmentStage.EXECUTION)
            if execution.status not in TERMINAL_STATUSES:
                self._transition(
                    graph,
                    node_id=execution.node_id,
                    status=execution_status,
                    last_error=execution_reason,
                )
            return True

        if approval.status == NodeStatus.WAITING_FOR_HUMAN_APPROVAL:
            graph = self._transition(
                graph,
                node_id=approval.node_id,
                status=NodeStatus.CANCELLED,
                last_error=reason,
            )
        elif approval.status != NodeStatus.CANCELLED:
            raise AssessmentGraphError("approval denial conflicts with current graph state")
        self._cancel_downstream(
            graph,
            starting_stage=AssessmentStage.EXECUTION,
            reason=reason,
        )
        return True

    def mark_execution_blocked(self, run_id: str, *, reason: str) -> bool:
        graph = self._load_optional(run_id)
        if graph is None:
            return False
        execution = self._stage_node(graph, AssessmentStage.EXECUTION)
        if execution.status == NodeStatus.BLOCKED:
            return True
        if execution.status in TERMINAL_STATUSES:
            raise AssessmentGraphError("terminal execution stage cannot be blocked again")
        self._transition(
            graph,
            node_id=execution.node_id,
            status=NodeStatus.BLOCKED,
            last_error=reason,
        )
        return True

    def project_terminal(self, run_id: str, *, outcome: str, reason: str) -> bool:
        if outcome != "cancelled":
            raise AssessmentGraphError("only cancellation projection is supported in this slice")
        graph = self._load_optional(run_id)
        if graph is None:
            return False
        for node in graph.nodes:
            current = next(item for item in graph.nodes if item.node_id == node.node_id)
            if current.status in TERMINAL_STATUSES:
                continue
            graph = self._transition(
                graph,
                node_id=current.node_id,
                status=NodeStatus.CANCELLED,
                last_error=reason,
            )
        return True

    def _load_optional(self, run_id: str) -> TaskGraph | None:
        try:
            return self.graph_store.load(self.graph_id_for_run(run_id))
        except TaskGraphStoreError as exc:
            if "does not exist" in str(exc):
                return None
            raise AssessmentGraphError("assessment task graph could not be loaded") from exc

    def _stage_node(self, graph: TaskGraph, stage: AssessmentStage) -> GraphNode:
        bundle = self._load_bundle(graph.graph_id)
        node_id = next(
            (item for item, item_stage in bundle.node_stages.items() if item_stage == stage),
            None,
        )
        if node_id is None:
            raise AssessmentGraphError(f"assessment graph stage is missing: {stage.value}")
        node = next((item for item in graph.nodes if item.node_id == node_id), None)
        if node is None:
            raise AssessmentGraphError(f"assessment graph node is missing: {node_id}")
        return node

    def _transition(
        self,
        graph: TaskGraph,
        *,
        node_id: str,
        status: NodeStatus,
        last_error: str | None,
    ) -> TaskGraph:
        try:
            return self.graph_store.update_status(
                graph.graph_id,
                node_id=node_id,
                status=status,
                last_error=last_error,
                expected_revision=graph.revision,
                now=self.clock().astimezone(UTC),
            )
        except TaskGraphStoreError as exc:
            raise AssessmentGraphError("assessment task graph transition failed closed") from exc

    def _cancel_downstream(
        self,
        graph: TaskGraph,
        *,
        starting_stage: AssessmentStage,
        reason: str,
    ) -> TaskGraph:
        stages = list(AssessmentStage)
        current = graph
        for stage in stages[stages.index(starting_stage) :]:
            node = self._stage_node(current, stage)
            if node.status in TERMINAL_STATUSES:
                continue
            current = self._transition(
                current,
                node_id=node.node_id,
                status=NodeStatus.CANCELLED,
                last_error=reason,
            )
        return current

    def _bundle_path(self, graph_id: str) -> Path:
        return self.root / f"{graph_id}.assessment.json"

    def _write_bundle(self, bundle: AssessmentGraphBundle) -> Path:
        path = self._bundle_path(bundle.graph_id)
        envelope = {
            "bundle": bundle.model_dump(mode="json"),
            "bundle_sha256": bundle.fingerprint(),
        }
        if path.exists():
            existing = self._load_bundle(bundle.graph_id)
            if existing == bundle:
                return path
            raise AssessmentGraphError("assessment graph bundle already exists with other content")
        serialized = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=".assessment-bundle-",
            suffix=".tmp",
            dir=self.root,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return path

    def _load_bundle(self, graph_id: str) -> AssessmentGraphBundle:
        path = self._bundle_path(graph_id)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            payload = envelope["bundle"]
            expected = envelope["bundle_sha256"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise AssessmentGraphError("assessment graph bundle is unavailable or invalid") from exc
        if sha256_json(payload) != expected:
            raise AssessmentGraphError("assessment graph bundle failed integrity verification")
        try:
            return AssessmentGraphBundle.model_validate(payload)
        except ValidationError as exc:
            raise AssessmentGraphError("assessment graph bundle is invalid") from exc

    @staticmethod
    def _validate_graph_binding(graph: TaskGraph, bundle: AssessmentGraphBundle) -> None:
        if graph.graph_id != bundle.graph_id or graph.run_id != bundle.run_id:
            raise AssessmentGraphError("assessment graph and workspace bundle are not bound")
        manifest_hashes = bundle.manifest_by_sha256()
        if set(bundle.node_stages) != {node.node_id for node in graph.nodes}:
            raise AssessmentGraphError("assessment graph nodes do not match the workspace bundle")
        if any(node.action_manifest_sha256 not in manifest_hashes for node in graph.nodes):
            raise AssessmentGraphError("assessment graph references an unknown action manifest")

    @staticmethod
    def _website_stage_specs(
        *,
        plan_digest: str | None,
        readiness_blocked: bool,
    ) -> tuple[tuple[AssessmentStage, str, ActionClass, str, str, bool, NodeStatus], ...]:
        if readiness_blocked:
            statuses = {
                AssessmentStage.AUTHORIZATION: NodeStatus.COMPLETED,
                AssessmentStage.PLAN: NodeStatus.BLOCKED,
                AssessmentStage.APPROVAL: NodeStatus.CANCELLED,
                AssessmentStage.EXECUTION: NodeStatus.CANCELLED,
                AssessmentStage.EVIDENCE: NodeStatus.CANCELLED,
                AssessmentStage.VERIFICATION: NodeStatus.CANCELLED,
                AssessmentStage.REVIEW: NodeStatus.CANCELLED,
                AssessmentStage.REPORT: NodeStatus.CANCELLED,
            }
        else:
            if not plan_digest:
                raise AssessmentGraphError("an executable website graph requires a plan digest")
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
        return (
            (
                AssessmentStage.AUTHORIZATION,
                "website.authorization.validate",
                ActionClass.READ_ONLY,
                "authorization-store",
                "validate",
                False,
                statuses[AssessmentStage.AUTHORIZATION],
            ),
            (
                AssessmentStage.PLAN,
                "website.plan.create",
                ActionClass.READ_ONLY,
                "nuclei-planner",
                "create",
                False,
                statuses[AssessmentStage.PLAN],
            ),
            (
                AssessmentStage.APPROVAL,
                "website.approval.consume",
                ActionClass.CONSEQUENTIAL,
                "approval-centre",
                "consume",
                True,
                statuses[AssessmentStage.APPROVAL],
            ),
            (
                AssessmentStage.EXECUTION,
                "website.scan.execute",
                ActionClass.SENSITIVE,
                "nuclei",
                "passive",
                True,
                statuses[AssessmentStage.EXECUTION],
            ),
            (
                AssessmentStage.EVIDENCE,
                "website.evidence.normalize",
                ActionClass.READ_ONLY,
                "evidence-normalizer",
                "normalize",
                False,
                statuses[AssessmentStage.EVIDENCE],
            ),
            (
                AssessmentStage.VERIFICATION,
                "website.finding.verify",
                ActionClass.READ_ONLY,
                "machine-oracle",
                "verify",
                False,
                statuses[AssessmentStage.VERIFICATION],
            ),
            (
                AssessmentStage.REVIEW,
                "website.review.request",
                ActionClass.REVERSIBLE_LOCAL,
                "review-service",
                "request",
                False,
                statuses[AssessmentStage.REVIEW],
            ),
            (
                AssessmentStage.REPORT,
                "website.report.generate",
                ActionClass.READ_ONLY,
                "report-service",
                "generate",
                False,
                statuses[AssessmentStage.REPORT],
            ),
        )

    @staticmethod
    def _role_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "scope-guardian",
            AssessmentStage.PLAN: "orchestrator",
            AssessmentStage.APPROVAL: "approval-coordinator",
            AssessmentStage.EXECUTION: "scanner-evidence-collector",
            AssessmentStage.EVIDENCE: "evidence-curator",
            AssessmentStage.VERIFICATION: "security-verifier",
            AssessmentStage.REVIEW: "review-coordinator",
            AssessmentStage.REPORT: "report-writer",
        }[stage]

    @staticmethod
    def _skill_for_stage(stage: AssessmentStage) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "exact-scope-validation",
            AssessmentStage.PLAN: "bounded-assessment-planning",
            AssessmentStage.APPROVAL: "authoritative-approval-consumption",
            AssessmentStage.EXECUTION: "controlled-nuclei-execution",
            AssessmentStage.EVIDENCE: "evidence-normalization",
            AssessmentStage.VERIFICATION: "independent-finding-verification",
            AssessmentStage.REVIEW: "governed-independent-review",
            AssessmentStage.REPORT: "evidence-backed-reporting",
        }[stage]

    @staticmethod
    def _timeout_for_stage(stage: AssessmentStage) -> int:
        if stage == AssessmentStage.EXECUTION:
            return 900
        if stage in {AssessmentStage.VERIFICATION, AssessmentStage.REVIEW}:
            return 600
        return 300

    @staticmethod
    def _purpose_for_stage(stage: AssessmentStage, *, profile: str) -> str:
        return {
            AssessmentStage.AUTHORIZATION: "Validate the exact active target authorization.",
            AssessmentStage.PLAN: "Create the immutable governed website assessment plan.",
            AssessmentStage.APPROVAL: "Consume approval for the exact immutable assessment plan.",
            AssessmentStage.EXECUTION: (
                f"Run the approved {profile} website assessment through the restricted worker."
            ),
            AssessmentStage.EVIDENCE: "Normalize and hash bounded scanner evidence.",
            AssessmentStage.VERIFICATION: "Verify candidate findings independently from the model.",
            AssessmentStage.REVIEW: "Request governed independent human review.",
            AssessmentStage.REPORT: "Generate an evidence-backed assessment report.",
        }[stage]

    @staticmethod
    def _chat_stage(by_stage: dict[AssessmentStage, GraphNode]) -> str:
        if any(node.status == NodeStatus.FAILED for node in by_stage.values()):
            return "failed_safely"
        if any(node.status == NodeStatus.BLOCKED for node in by_stage.values()):
            return "blocked"
        if by_stage[AssessmentStage.REPORT].status == NodeStatus.COMPLETED:
            return "report_ready"
        if by_stage[AssessmentStage.APPROVAL].status == NodeStatus.WAITING_FOR_HUMAN_APPROVAL:
            return "waiting_for_confirmation"
        if by_stage[AssessmentStage.EXECUTION].status == NodeStatus.RUNNING:
            return "collecting_evidence"
        if by_stage[AssessmentStage.EVIDENCE].status == NodeStatus.RUNNING:
            return "normalizing_evidence"
        if by_stage[AssessmentStage.VERIFICATION].status == NodeStatus.RUNNING:
            return "verifying_evidence"
        if by_stage[AssessmentStage.REVIEW].status in {
            NodeStatus.RUNNING,
            NodeStatus.WAITING_FOR_HUMAN_APPROVAL,
        }:
            return "waiting_for_independent_review"
        if by_stage[AssessmentStage.APPROVAL].status == NodeStatus.CANCELLED:
            return "cancelled"
        if by_stage[AssessmentStage.EXECUTION].status == NodeStatus.CANCELLED:
            return "cancelled"
        return "queued_for_analysis"
