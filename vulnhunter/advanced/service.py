"""Build governed action manifests and a durable task graph for one assessment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import ActionManifest, ExecutionLimits
from vulnhunter.advanced.models import AssessmentProfile, AssessmentRequest
from vulnhunter.security_tools.catalog import SecurityToolCatalog
from vulnhunter.taskgraph.models import GraphNode, TaskGraph


class AdvancedAssessmentPlanner:
    def __init__(self, catalog: SecurityToolCatalog) -> None:
        self.catalog = catalog

    def build(
        self,
        request: AssessmentRequest,
    ) -> tuple[tuple[ActionManifest, ...], TaskGraph]:
        tool_ids = self._tool_sequence(request.profile)
        definitions = {item.tool_id: item for item in self.catalog.list()}
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        previous_node: str | None = None
        now = datetime.now(UTC)

        for index, tool_id in enumerate(tool_ids, start=1):
            definition = definitions[tool_id]
            manifest = ActionManifest(
                manifest_id=f"{request.assessment_id}-{index:02d}",
                campaign_id=request.campaign_id,
                requested_by=request.requested_by,
                role_id=self._role_for(tool_id),
                skill_id=self._skill_for(tool_id),
                action=f"security_tool.{tool_id}.run",
                action_class=definition.action_class,
                tool_id=tool_id,
                operation=request.profile.value,
                target_references=request.target_references,
                authorization_references=request.authorization_references,
                limits=ExecutionLimits(
                    timeout_seconds=min(request.timeout_seconds, 86_400),
                    maximum_requests=request.maximum_requests,
                    maximum_targets=len(request.target_references),
                ),
                approval_required=definition.approval_required,
                created_at=now,
                expires_at=now + timedelta(hours=2),
                purpose=f"Run {definition.display_name} within the authorised assessment.",
            )
            manifests.append(manifest)
            node_id = f"{request.assessment_id}-node-{index:02d}"
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    role_id=manifest.role_id,
                    skill_id=manifest.skill_id,
                    action_manifest_sha256=manifest.fingerprint(),
                    dependencies=(() if previous_node is None else (previous_node,)),
                    maximum_attempts=manifest.limits.maximum_attempts,
                )
            )
            previous_node = node_id

        graph = TaskGraph(
            graph_id=f"{request.assessment_id}-graph",
            campaign_id=request.campaign_id,
            run_id=request.run_id,
            nodes=tuple(nodes),
        )
        return tuple(manifests), graph

    @staticmethod
    def _tool_sequence(profile: AssessmentProfile) -> tuple[str, ...]:
        mapping = {
            AssessmentProfile.DEEP_DISCOVERY: ("amass", "nmap", "httpx", "testssl"),
            AssessmentProfile.ACTIVE_ASSESSMENT: (
                "nmap",
                "httpx",
                "testssl",
                "nuclei",
                "zap",
            ),
            AssessmentProfile.EXPLOITABILITY_VALIDATION: ("sqlmap", "metasploit"),
            AssessmentProfile.PRIVILEGED_ENVIRONMENT: ("nmap",),
            AssessmentProfile.ATTACK_PATH_SIMULATION: (
                "amass",
                "nmap",
                "httpx",
                "nuclei",
            ),
            AssessmentProfile.REMEDIATION_RETEST: (
                "httpx",
                "testssl",
                "nuclei",
                "trivy",
                "bearer",
            ),
        }
        return mapping[profile]

    @staticmethod
    def _role_for(tool_id: str) -> str:
        if tool_id in {"sqlmap", "metasploit"}:
            return "advanced-validation-specialist"
        return "scanner-evidence-specialist"

    @staticmethod
    def _skill_for(tool_id: str) -> str:
        if tool_id in {"sqlmap", "metasploit"}:
            return "controlled-exploitability-validation"
        if tool_id in {"trivy", "bearer", "bandit", "gitleaks", "osv-scanner"}:
            return "local-code-and-dependency-assessment"
        return "governed-security-tool-operation"
