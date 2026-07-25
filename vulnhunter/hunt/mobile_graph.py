"""Evidence graph projection for completed mobile hunt receipts."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.actions.models import sha256_json
from vulnhunter.hunt.mobile_runtime import MobileHuntExecutionReceipt
from vulnhunter.hunt.models import CandidateState
from vulnhunter.mobile.models import MobileArtifactRecord

_NODE_SAFE = re.compile(r"[^a-z0-9._-]+")


def _node_id(prefix: str, value: str) -> str:
    normalized = _NODE_SAFE.sub("-", value.casefold()).strip("-._") or "unknown"
    digest = hashlib.sha256(value.encode()).hexdigest()[:10]
    return f"{prefix}-{normalized[:72]}-{digest}"


class MobileEvidenceGraphNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    kind: str
    label: str
    state: str
    severity: str = "unknown"
    evidence_receipts: tuple[str, ...] = ()
    tool_ids: tuple[str, ...] = ()


class MobileEvidenceGraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str
    source: str
    target: str
    relation: str
    evidence_receipts: tuple[str, ...] = ()


class MobileEvidenceGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    graph_id: str
    artifact_id: str
    artifact_sha256: str
    nodes: tuple[MobileEvidenceGraphNode, ...]
    edges: tuple[MobileEvidenceGraphEdge, ...]
    verified_paths: int = Field(ge=0)
    evidence_required_paths: int = Field(ge=0)
    graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def build_mobile_evidence_graph(
    *,
    artifact: MobileArtifactRecord,
    hunt: MobileHuntExecutionReceipt,
) -> MobileEvidenceGraph:
    """Create only relationships directly supported by candidate receipts."""

    artifact_node = _node_id("artifact", artifact.artifact_id)
    nodes: list[MobileEvidenceGraphNode] = [
        MobileEvidenceGraphNode(
            node_id=artifact_node,
            kind="artifact",
            label=artifact.original_filename,
            state="verified",
            severity="info",
            evidence_receipts=(f"artifact:{artifact.sha256}",),
        )
    ]
    edges: list[MobileEvidenceGraphEdge] = []
    components: dict[str, str] = {}
    tool_receipts: dict[str, set[str]] = defaultdict(set)
    for candidate in hunt.candidates:
        for tool in candidate.tool_ids:
            tool_receipts[tool].update(candidate.evidence_receipts)

    for tool, receipts in sorted(tool_receipts.items()):
        tool_node = _node_id("tool", tool)
        nodes.append(
            MobileEvidenceGraphNode(
                node_id=tool_node,
                kind="tool",
                label=tool,
                state="completed",
                severity="info",
                evidence_receipts=tuple(sorted(receipts)),
                tool_ids=(tool,),
            )
        )
        edges.append(
            MobileEvidenceGraphEdge(
                edge_id=_node_id("edge", f"{artifact_node}:{tool_node}"),
                source=artifact_node,
                target=tool_node,
                relation="analysed_by",
                evidence_receipts=tuple(sorted(receipts)),
            )
        )

    for candidate in hunt.candidates:
        component_label = candidate.component or "Application surface"
        component_node = components.get(component_label)
        if component_node is None:
            component_node = _node_id("component", component_label)
            components[component_label] = component_node
            nodes.append(
                MobileEvidenceGraphNode(
                    node_id=component_node,
                    kind="component",
                    label=component_label,
                    state="observed",
                    severity="info",
                )
            )
            edges.append(
                MobileEvidenceGraphEdge(
                    edge_id=_node_id("edge", f"{artifact_node}:{component_node}"),
                    source=artifact_node,
                    target=component_node,
                    relation="contains_or_declares",
                )
            )
        candidate_node = _node_id("candidate", candidate.candidate_id)
        nodes.append(
            MobileEvidenceGraphNode(
                node_id=candidate_node,
                kind="candidate",
                label=candidate.title,
                state=candidate.state.value,
                severity=candidate.severity,
                evidence_receipts=candidate.evidence_receipts,
                tool_ids=candidate.tool_ids,
            )
        )
        edges.append(
            MobileEvidenceGraphEdge(
                edge_id=_node_id("edge", f"{component_node}:{candidate_node}"),
                source=component_node,
                target=candidate_node,
                relation="supports_candidate",
                evidence_receipts=candidate.evidence_receipts,
            )
        )
        for tool in candidate.tool_ids:
            tool_node = _node_id("tool", tool)
            edges.append(
                MobileEvidenceGraphEdge(
                    edge_id=_node_id("edge", f"{tool_node}:{candidate_node}"),
                    source=tool_node,
                    target=candidate_node,
                    relation="produced_evidence_for",
                    evidence_receipts=candidate.evidence_receipts,
                )
            )

    verified_paths = sum(item.state == CandidateState.VERIFIED for item in hunt.candidates)
    evidence_required_paths = sum(
        item.state == CandidateState.EVIDENCE_REQUIRED for item in hunt.candidates
    )
    unsigned = {
        "graph_id": _node_id("graph", f"{artifact.artifact_id}:{hunt.receipt_sha256}"),
        "artifact_id": artifact.artifact_id,
        "artifact_sha256": artifact.sha256,
        "nodes": [item.model_dump(mode="json") for item in nodes],
        "edges": [item.model_dump(mode="json") for item in edges],
        "verified_paths": verified_paths,
        "evidence_required_paths": evidence_required_paths,
    }
    return MobileEvidenceGraph(
        **unsigned,
        graph_sha256=sha256_json(unsigned),
    )


__all__ = [
    "MobileEvidenceGraph",
    "MobileEvidenceGraphEdge",
    "MobileEvidenceGraphNode",
    "build_mobile_evidence_graph",
]
