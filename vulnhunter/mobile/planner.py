"""Build hash-bound multi-tool task graphs for one uploaded APK."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import ActionManifest, ExecutionLimits
from vulnhunter.mobile.models import (
    MobileAnalysisProfile,
    MobileAnalysisRequest,
    MobileArtifactRecord,
)
from vulnhunter.security_tools.catalog import SecurityToolCatalog
from vulnhunter.taskgraph.models import GraphNode, TaskGraph


class MobileAnalysisPlanner:
    def __init__(self, catalog: SecurityToolCatalog) -> None:
        self.catalog = catalog

    def build(
        self,
        request: MobileAnalysisRequest,
        artifact: MobileArtifactRecord,
    ) -> tuple[tuple[ActionManifest, ...], TaskGraph]:
        if request.artifact_id != artifact.artifact_id:
            raise ValueError("analysis request artifact_id does not match the ingested artifact")
        if request.artifact_sha256 != artifact.sha256:
            raise ValueError(
                "analysis request artifact digest does not match the ingested artifact"
            )
        if request.artifact_path.resolve() != artifact.stored_path.resolve():
            raise ValueError("analysis request artifact path does not match the ingested artifact")

        tool_ids = self._tool_sequence(request.profile, artifact)
        definitions = {item.tool_id: item for item in self.catalog.list()}
        manifests: list[ActionManifest] = []
        nodes: list[GraphNode] = []
        previous_node: str | None = None
        now = datetime.now(UTC)

        for index, tool_id in enumerate(tool_ids, start=1):
            definition = definitions[tool_id]
            role_id, skill_id = self._role_and_skill(tool_id)
            manifest = ActionManifest(
                manifest_id=f"{request.analysis_id}-{index:02d}",
                campaign_id=request.campaign_id,
                requested_by=request.requested_by,
                role_id=role_id,
                skill_id=skill_id,
                action=f"mobile-tool.{tool_id}.run",
                action_class=definition.action_class,
                tool_id=tool_id,
                operation=request.profile.value,
                target_references=(artifact.artifact_id, artifact.sha256),
                authorization_references=request.authorization_references,
                limits=ExecutionLimits(
                    timeout_seconds=request.timeout_seconds,
                    maximum_requests=1,
                    maximum_output_bytes=request.maximum_output_bytes,
                    maximum_targets=2,
                ),
                approval_required=definition.approval_required,
                created_at=now,
                expires_at=now + timedelta(hours=2),
                purpose=(
                    f"Run {definition.display_name} against the uploaded APK within the "
                    "declared mobile analysis profile."
                ),
            )
            manifests.append(manifest)
            node_id = f"{request.analysis_id}-node-{index:02d}"
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    role_id=role_id,
                    skill_id=skill_id,
                    action_manifest_sha256=manifest.fingerprint(),
                    dependencies=(() if previous_node is None else (previous_node,)),
                    maximum_attempts=manifest.limits.maximum_attempts,
                )
            )
            previous_node = node_id

        return tuple(manifests), TaskGraph(
            graph_id=f"{request.analysis_id}-graph",
            campaign_id=request.campaign_id,
            run_id=request.run_id,
            nodes=tuple(nodes),
        )

    @staticmethod
    def _tool_sequence(
        profile: MobileAnalysisProfile,
        artifact: MobileArtifactRecord,
    ) -> tuple[str, ...]:
        static = ("apksigner", "aapt2", "apkid", "apktool", "jadx", "androguard", "yara")
        native = ("radare2", "ghidra") if artifact.native_libraries else ()
        dynamic = ("mobsf", "adb", "frida")
        mapping = {
            MobileAnalysisProfile.STATIC: static,
            MobileAnalysisProfile.STATIC_AND_NATIVE: static + native,
            MobileAnalysisProfile.DYNAMIC: dynamic,
            MobileAnalysisProfile.FULL: static + native + dynamic,
            MobileAnalysisProfile.RETEST: ("apksigner", "aapt2", "apktool", "jadx", "mobsf"),
        }
        return mapping[profile]

    @staticmethod
    def _role_and_skill(tool_id: str) -> tuple[str, str]:
        if tool_id in {"adb", "frida", "mobsf"}:
            return "mobile-dynamic-analysis-specialist", "android-runtime-security-validation"
        if tool_id in {"radare2", "ghidra"}:
            return "mobile-application-security-analyst", "android-native-library-triage"
        return "mobile-application-security-analyst", "android-apk-static-analysis"
