"""Deterministic application-surface graph construction."""

from __future__ import annotations

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_perception.models import (
    ApplicationSurfaceGraph,
    PerceivedPage,
    SurfaceEdge,
    SurfaceEdgeKind,
    SurfaceNode,
    SurfaceNodeKind,
)


def _node_id(kind: SurfaceNodeKind, url: str, method: str | None, detail: str | None) -> str:
    return sha256_json(
        {
            "kind": kind.value,
            "url": url,
            "method": method,
            "detail_sha256": detail,
        }
    )


def _edge_id(kind: SurfaceEdgeKind, source: str, target: str) -> str:
    return sha256_json({"kind": kind.value, "source": source, "target": target})


def build_surface_graph(
    target_url: str,
    pages: tuple[PerceivedPage, ...],
) -> ApplicationSurfaceGraph:
    """Build a stable graph without storing DOM text, headers, bodies, or form values."""

    nodes_by_id: dict[str, SurfaceNode] = {}
    edges_by_id: dict[str, SurfaceEdge] = {}

    def add_node(
        kind: SurfaceNodeKind,
        url: str,
        *,
        method: str | None = None,
        detail_sha256: str | None = None,
    ) -> str:
        node_id = _node_id(kind, url, method, detail_sha256)
        nodes_by_id.setdefault(
            node_id,
            SurfaceNode(
                node_id=node_id,
                kind=kind,
                url=url,
                method=method,
                detail_sha256=detail_sha256,
            ),
        )
        return node_id

    def add_edge(kind: SurfaceEdgeKind, source: str, target: str) -> None:
        edge_id = _edge_id(kind, source, target)
        edges_by_id.setdefault(
            edge_id,
            SurfaceEdge(
                edge_id=edge_id,
                kind=kind,
                source_node_id=source,
                target_node_id=target,
            ),
        )

    page_nodes: dict[str, str] = {}
    for page in pages:
        page_nodes[page.url] = add_node(
            SurfaceNodeKind.PAGE,
            page.url,
            detail_sha256=page.dom_structure_sha256,
        )

    for page in pages:
        source = page_nodes[page.url]

        for link in page.links:
            target = page_nodes.get(link)
            if target is None:
                target = add_node(SurfaceNodeKind.PAGE, link)
            add_edge(SurfaceEdgeKind.LINKS_TO, source, target)

        for request in page.requests:
            target = add_node(
                SurfaceNodeKind.ENDPOINT,
                request.url,
                method=request.method,
            )
            add_edge(SurfaceEdgeKind.REQUESTS, source, target)

        for form in page.forms:
            form_node = add_node(
                SurfaceNodeKind.FORM,
                form.action_url,
                method=form.method,
                detail_sha256=form.form_sha256,
            )
            endpoint_node = add_node(
                SurfaceNodeKind.ENDPOINT,
                form.action_url,
                method=form.method,
            )
            add_edge(SurfaceEdgeKind.SUBMITS_TO, source, form_node)
            add_edge(SurfaceEdgeKind.SUBMITS_TO, form_node, endpoint_node)

        for script in page.scripts:
            target = add_node(SurfaceNodeKind.SCRIPT, script)
            add_edge(SurfaceEdgeKind.LOADS_SCRIPT, source, target)

    nodes = tuple(sorted(nodes_by_id.values(), key=lambda item: item.node_id))
    edges = tuple(sorted(edges_by_id.values(), key=lambda item: item.edge_id))
    graph_payload = {
        "schema_version": 1,
        "target_url": target_url,
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "edges": [edge.model_dump(mode="json") for edge in edges],
    }
    return ApplicationSurfaceGraph(
        **graph_payload,
        graph_sha256=sha256_json(graph_payload),
    )
