import hashlib

import pytest
from pydantic import ValidationError

from vulnhunter.context_broker import (
    ContextBroker,
    ContextBrokerError,
    ContextQuery,
    ContextSourceKind,
)
from vulnhunter.repository_graph import (
    GraphifyArtifact,
    GraphifyEdge,
    GraphifyNode,
    NativeRepositoryGraph,
)

REVISION = "a" * 40


def _graphify_artifact(tmp_path, *, revision=REVISION, nodes=None, edges=()):
    graph = tmp_path / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    return GraphifyArtifact(
        repository_root=str(tmp_path.resolve()),
        repository_revision=revision,
        graph_path=str(graph),
        graph_sha256=hashlib.sha256(b"{}").hexdigest(),
        graph_bytes=2,
        graphify_version="graphify 0.9.16",
        nodes=tuple(
            nodes
            or (GraphifyNode(node_id="node-1", label="authorize_target", source_file="service.py"),)
        ),
        edges=tuple(edges),
    )


def test_context_broker_routes_exact_files_graph_rules_and_auth(tmp_path):
    (tmp_path / "service.py").write_text(
        "def authorize_target():\n    return True\n", encoding="utf-8"
    )
    graph = NativeRepositoryGraph(tmp_path).build()
    broker = ContextBroker(
        tmp_path,
        graph=graph,
        rules=("Authorization must fail closed.",),
        contradictions=("Legacy note says authorization may be optional; this is invalid.",),
    )
    bundle = broker.build(
        ContextQuery(
            query_id="query-01",
            text="authorization target",
            authorization_references=("authorization-01",),
        )
    )
    assert "service.py" in bundle.relevant_files
    assert any(item.source_kind == ContextSourceKind.FILE_EXCERPT for item in bundle.items)
    assert any(item.source_kind == ContextSourceKind.GRAPH_NODE for item in bundle.items)
    assert bundle.authorization_references == ("authorization-01",)


def test_context_broker_fails_closed_for_unconfigured_embeddings(tmp_path):
    (tmp_path / "a.py").write_text("value = 1", encoding="utf-8")
    broker = ContextBroker(tmp_path)
    with pytest.raises(ContextBrokerError, match="no approved retriever"):
        broker.build(
            ContextQuery(query_id="query-02", text="value", allow_embedding_retrieval=True)
        )


def test_context_broker_uses_bounded_graphify_subgraph_with_provenance(tmp_path):
    (tmp_path / "service.py").write_text("def authorize_target(): return True", encoding="utf-8")
    nodes = tuple(
        GraphifyNode(node_id=f"node-{index}", label=f"authorize_{index}", source_file="service.py")
        for index in range(5)
    )
    edges = tuple(
        GraphifyEdge(source_id=f"node-{index}", target_id=f"node-{index + 1}", relation="calls")
        for index in range(4)
    )
    artifact = _graphify_artifact(tmp_path, nodes=nodes, edges=edges)
    bundle = ContextBroker(
        tmp_path,
        graphify_artifact=artifact,
        current_repository_revision=REVISION,
    ).build(
        ContextQuery(
            query_id="query-graphify",
            text="authorize",
            maximum_graph_nodes=2,
            maximum_graph_edges=1,
        )
    )
    assert bundle.graph_status == "current"
    assert len(bundle.selected_graph_nodes) == 2
    assert len(bundle.selected_graph_edges) <= 1
    assert any(item.metadata.get("graph_sha256") == artifact.graph_sha256 for item in bundle.items)


def test_context_broker_rejects_cross_repository_graph(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    artifact = _graphify_artifact(other)
    with pytest.raises(ContextBrokerError, match="another repository"):
        ContextBroker(tmp_path, graphify_artifact=artifact)


def test_context_broker_rejects_stale_graph_and_uses_deterministic_fallback(tmp_path):
    (tmp_path / "service.py").write_text("def authorize_target(): return True", encoding="utf-8")
    artifact = _graphify_artifact(tmp_path, revision="b" * 40)
    bundle = ContextBroker(
        tmp_path,
        graphify_artifact=artifact,
        current_repository_revision=REVISION,
    ).build(ContextQuery(query_id="query-stale", text="authorize target"))
    assert bundle.graph_status == "stale"
    assert "revision" in bundle.graph_fallback_reason
    assert not bundle.selected_graph_nodes
    assert any(item.source_kind == ContextSourceKind.FILE_EXCERPT for item in bundle.items)


def test_context_broker_unavailable_graph_does_not_crash_or_fabricate(tmp_path):
    (tmp_path / "service.py").write_text("policy_value = 1", encoding="utf-8")
    bundle = ContextBroker(tmp_path).build(
        ContextQuery(query_id="query-fallback", text="policy value")
    )
    assert bundle.graph_status == "unavailable"
    assert bundle.selected_graph_nodes == ()
    assert "bounded file search" in bundle.graph_fallback_reason


def test_context_broker_enforces_file_and_bundle_byte_limits(tmp_path):
    for index in range(10):
        (tmp_path / f"file_{index}.py").write_text("policy = 'bounded'\n" * 20, encoding="utf-8")
    bundle = ContextBroker(tmp_path).build(
        ContextQuery(
            query_id="query-limits",
            text="policy bounded",
            maximum_scanned_files=2,
            maximum_scanned_bytes=1_024,
            maximum_bundle_bytes=1_024,
            maximum_excerpt_characters=200,
        )
    )
    assert bundle.content_bytes <= 1_024
    assert len(bundle.relevant_files) <= 2
    assert bundle.truncated is True


def test_context_broker_excludes_secret_files_and_rejects_secret_selection(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=do-not-disclose", encoding="utf-8")
    (tmp_path / "service.py").write_text("TOKEN_POLICY = 'redact'", encoding="utf-8")
    bundle = ContextBroker(tmp_path).build(
        ContextQuery(query_id="query-secret", text="token policy")
    )
    assert ".env" not in bundle.relevant_files
    assert all("do-not-disclose" not in item.content for item in bundle.items)
    with pytest.raises(ValidationError):
        ContextQuery(query_id="query-secret-path", text="token", allowed_paths=(".env",))
