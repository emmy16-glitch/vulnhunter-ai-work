"""Integrity and authority policy for advisory web-hunter inputs and outputs."""

from __future__ import annotations

import hashlib

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.opensandbox_supply_chain import canonical_json_bytes
from vulnhunter.web_hunters.errors import WebHunterContractError
from vulnhunter.web_hunters.models import (
    HunterContext,
    HunterHypothesis,
    hypothesis_id_for,
    semantic_fingerprint,
    verification_intent_id_for,
)
from vulnhunter.web_perception.models import WebPerceptionResult


def build_hunter_context(result: WebPerceptionResult) -> HunterContext:
    """Re-verify perception evidence and graph integrity before any hunter sees them."""

    evidence_sha256 = hashlib.sha256(
        canonical_json_bytes(result.evidence.model_dump(mode="json"))
    ).hexdigest()
    if evidence_sha256 != result.evidence_sha256:
        raise WebHunterContractError("web perception evidence integrity check failed")

    graph_payload = {
        "schema_version": result.graph.schema_version,
        "target_url": result.graph.target_url,
        "nodes": [node.model_dump(mode="json") for node in result.graph.nodes],
        "edges": [edge.model_dump(mode="json") for edge in result.graph.edges],
    }
    graph_sha256 = sha256_json(graph_payload)
    if graph_sha256 != result.graph.graph_sha256:
        raise WebHunterContractError("application surface graph integrity check failed")
    if result.graph.target_url != result.target_url:
        raise WebHunterContractError("surface graph target does not match perception result")

    return HunterContext(
        target_url=result.target_url,
        perception_plan_sha256=result.plan_sha256,
        perception_evidence_sha256=result.evidence_sha256,
        graph_sha256=result.graph.graph_sha256,
        evidence=result.evidence,
        graph=result.graph,
    )


def validate_hypothesis(context: HunterContext, hypothesis: HunterHypothesis) -> None:
    """Reject fabricated evidence references or identities from any specialist."""

    if hypothesis.evidence.graph_sha256 != context.graph_sha256:
        raise WebHunterContractError("hunter hypothesis references a different graph")

    node_ids = {node.node_id for node in context.graph.nodes}
    edge_ids = {edge.edge_id for edge in context.graph.edges}
    if hypothesis.target_node_id not in node_ids:
        raise WebHunterContractError("hunter target node does not exist in the graph")
    if hypothesis.target_node_id not in hypothesis.evidence.node_ids:
        raise WebHunterContractError("hunter evidence must include its target node")
    if not set(hypothesis.evidence.node_ids).issubset(node_ids):
        raise WebHunterContractError("hunter evidence references an unknown graph node")
    if not set(hypothesis.evidence.edge_ids).issubset(edge_ids):
        raise WebHunterContractError("hunter evidence references an unknown graph edge")

    expected_fingerprint = semantic_fingerprint(
        hunter_id=hypothesis.hunter_id,
        vulnerability_class=hypothesis.vulnerability_class,
        target_node_id=hypothesis.target_node_id,
        strategy=hypothesis.verification_intent.strategy,
    )
    if hypothesis.semantic_fingerprint != expected_fingerprint:
        raise WebHunterContractError("hunter semantic fingerprint does not match its contents")

    expected_hypothesis_id = hypothesis_id_for(
        graph_sha256=context.graph_sha256,
        semantic_fingerprint_value=expected_fingerprint,
    )
    if hypothesis.hypothesis_id != expected_hypothesis_id:
        raise WebHunterContractError("hunter hypothesis ID does not match its graph identity")

    expected_intent_id = verification_intent_id_for(
        hypothesis_id=hypothesis.hypothesis_id,
        strategy=hypothesis.verification_intent.strategy,
        target_node_id=hypothesis.target_node_id,
    )
    if hypothesis.verification_intent.intent_id != expected_intent_id:
        raise WebHunterContractError("verification intent ID does not match the hypothesis")
