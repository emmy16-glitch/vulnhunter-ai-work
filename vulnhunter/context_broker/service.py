"""Exact-search and graph-backed bounded context routing."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Iterable
from pathlib import Path

from vulnhunter.context_broker.models import (
    ContextBundle,
    ContextConfidence,
    ContextFreshness,
    ContextItem,
    ContextQuery,
    ContextSourceKind,
)
from vulnhunter.repository_graph import GraphifyArtifact, RepositoryGraphSnapshot
from vulnhunter.security import redact_text

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{1,127}")
_EXCLUDED = frozenset(
    {
        ".git",
        ".venv",
        ".vulnhunter-install-backups",
        "__pycache__",
        "artifacts",
        "build",
        "coverage",
        "dist",
        "graphify-out",
        "htmlcov",
        "node_modules",
        "var",
        "venv",
    }
)
_SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3", ".log")
_SOURCE_SUFFIXES = {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".html", ".css", ".js"}


class ContextBrokerError(RuntimeError):
    pass


class ContextBroker:
    """Return the smallest policy-bounded repository context for one task."""

    def __init__(
        self,
        repository_root: Path,
        *,
        graph: RepositoryGraphSnapshot | None = None,
        graphify_artifact: GraphifyArtifact | None = None,
        current_repository_revision: str | None = None,
        task_history_provider: Callable[[str], Iterable[dict[str, object]]] | None = None,
        rules: tuple[str, ...] = (),
        contradictions: tuple[str, ...] = (),
        embedding_retriever: Callable[[ContextQuery], Iterable[ContextItem]] | None = None,
    ) -> None:
        self.repository_root = repository_root.expanduser().resolve(strict=True)
        if not self.repository_root.is_dir() or repository_root.expanduser().is_symlink():
            raise ContextBrokerError("repository root must be a non-symlinked directory")
        if graph is not None and Path(graph.repository_root).resolve() != self.repository_root:
            raise ContextBrokerError("native graph belongs to another repository")
        if (
            graphify_artifact is not None
            and Path(graphify_artifact.repository_root).resolve() != self.repository_root
        ):
            raise ContextBrokerError("Graphify artifact belongs to another repository")
        self.graph = graph
        self.graphify_artifact = graphify_artifact
        self.current_repository_revision = current_repository_revision
        self.task_history_provider = task_history_provider
        self.rules = rules
        self.contradictions = contradictions
        self.embedding_retriever = embedding_retriever

    def build(self, query: ContextQuery) -> ContextBundle:
        terms = tuple(dict.fromkeys(token.lower() for token in _TOKEN.findall(query.text)))
        if not terms:
            raise ContextBrokerError("query does not contain searchable terms")
        items: list[ContextItem] = []
        scanned_files = 0
        scanned_bytes = 0
        scan_truncated = False

        for path in self._candidate_files(query.allowed_paths):
            if scanned_files >= query.maximum_scanned_files:
                scan_truncated = True
                break
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > query.maximum_scanned_bytes - scanned_bytes:
                scan_truncated = True
                continue
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            scanned_files += 1
            scanned_bytes += len(raw)
            lower = text.lower()
            score = sum(lower.count(term) for term in terms)
            if score == 0:
                continue
            relative = path.relative_to(self.repository_root).as_posix()
            excerpt, line_start, line_end = self._excerpt(
                text, terms, query.maximum_excerpt_characters
            )
            excerpt = redact_text(excerpt)
            if not excerpt.strip():
                continue
            items.append(
                ContextItem(
                    source_kind=ContextSourceKind.FILE_EXCERPT,
                    source_id=f"file:{relative}",
                    path=relative,
                    line_start=line_start,
                    line_end=line_end,
                    content=excerpt,
                    confidence=ContextConfidence.VERIFIED,
                    freshness=ContextFreshness.CURRENT,
                    source_sha256=hashlib.sha256(raw).hexdigest(),
                    metadata={"keyword_score": score},
                )
            )

        graph_status, fallback_reason, selected_nodes, selected_edges = self._add_graph_items(
            query, terms, items
        )
        self._add_task_history(query, items)
        self._add_policy_context(query, terms, items)

        if query.allow_embedding_retrieval:
            if self.embedding_retriever is None:
                raise ContextBrokerError(
                    "embedding retrieval was requested but no approved retriever exists"
                )
            for item in self.embedding_retriever(query):
                if item.source_kind != ContextSourceKind.EMBEDDING:
                    raise ContextBrokerError("embedding retriever returned an invalid source kind")
                items.append(item)

        rank = {
            ContextConfidence.VERIFIED: 0,
            ContextConfidence.EXTRACTED: 1,
            ContextConfidence.INFERRED: 2,
            ContextConfidence.AMBIGUOUS: 3,
        }
        items.sort(key=lambda item: (rank[item.confidence], item.path or "", item.source_id))
        selected: list[ContextItem] = []
        content_bytes = 0
        truncated = scan_truncated
        for item in items:
            item_bytes = len(item.content.encode("utf-8"))
            if (
                len(selected) >= query.maximum_items
                or content_bytes + item_bytes > query.maximum_bundle_bytes
            ):
                truncated = True
                continue
            selected.append(item)
            content_bytes += item_bytes

        relevant_files = tuple(
            dict.fromkeys(item.path for item in selected if item.path is not None)
        )[: query.maximum_items]
        relevant_symbols = tuple(
            str(item.metadata["symbol"]) for item in selected if "symbol" in item.metadata
        )[: query.maximum_graph_nodes]
        repository_state = self.graph.repository_state_sha256 if self.graph else None
        if self.graphify_artifact is not None and graph_status == "current":
            repository_state = self.graphify_artifact.graph_sha256
        return ContextBundle(
            query_id=query.query_id,
            items=tuple(selected),
            relevant_files=relevant_files,
            relevant_symbols=tuple(dict.fromkeys(relevant_symbols)),
            contradictions=tuple(
                item.content
                for item in selected
                if item.source_kind == ContextSourceKind.CONTRADICTION
            ),
            task_specific_rules=tuple(
                item.content for item in selected if item.source_kind == ContextSourceKind.RULE
            ),
            authorization_references=query.authorization_references,
            repository_state_sha256=repository_state,
            graph_status=graph_status,
            graph_fallback_reason=fallback_reason,
            selected_graph_nodes=tuple(selected_nodes),
            selected_graph_edges=tuple(selected_edges),
            content_bytes=content_bytes,
            truncated=truncated,
        )

    def _add_graph_items(
        self,
        query: ContextQuery,
        terms: tuple[str, ...],
        items: list[ContextItem],
    ) -> tuple[str, str | None, list[str], list[str]]:
        selected_nodes: list[str] = []
        selected_edges: list[str] = []
        if not query.include_graph:
            return "disabled_by_query", "Graph context was disabled by the bounded query.", [], []

        artifact = self.graphify_artifact
        if artifact is not None:
            if (
                self.current_repository_revision is not None
                and artifact.repository_revision != self.current_repository_revision
            ):
                status = "stale"
                reason = "Graphify artifact revision does not match the current repository."
            else:
                matching = sorted(
                    (
                        node
                        for node in artifact.nodes
                        if any(
                            term in node.label.lower() or term in (node.source_file or "").lower()
                            for term in terms
                        )
                    ),
                    key=lambda node: node.node_id,
                )[: query.maximum_graph_nodes]
                selected_id_set = {node.node_id for node in matching}
                for node in matching:
                    selected_nodes.append(node.node_id)
                    items.append(
                        ContextItem(
                            source_kind=ContextSourceKind.GRAPH_NODE,
                            source_id=f"graphify:{node.node_id}",
                            path=node.source_file,
                            content=(
                                f"{node.label} ({node.source_location or 'location unavailable'})"
                            ),
                            confidence=ContextConfidence(node.confidence.value),
                            freshness=ContextFreshness.CURRENT,
                            metadata={
                                "symbol": node.label,
                                "graph_sha256": artifact.graph_sha256,
                                "repository_revision": artifact.repository_revision,
                            },
                        )
                    )
                matching_edges = sorted(
                    (
                        edge
                        for edge in artifact.edges
                        if edge.source_id in selected_id_set and edge.target_id in selected_id_set
                    ),
                    key=lambda edge: (edge.source_id, edge.relation, edge.target_id),
                )[: query.maximum_graph_edges]
                for edge in matching_edges:
                    edge_id = f"{edge.source_id}->{edge.target_id}:{edge.relation}"
                    selected_edges.append(edge_id)
                    items.append(
                        ContextItem(
                            source_kind=ContextSourceKind.GRAPH_EDGE,
                            source_id=f"graphify-edge:{edge_id}",
                            content=edge_id,
                            confidence=ContextConfidence(edge.confidence.value),
                            freshness=ContextFreshness.CURRENT,
                            metadata={"graph_sha256": artifact.graph_sha256},
                        )
                    )
                return "current", None, selected_nodes, selected_edges
        else:
            status = "unavailable"
            reason = "No validated Graphify artifact was supplied."

        if self.graph is not None:
            matching_nodes = sorted(
                (
                    node
                    for node in self.graph.nodes
                    if any(term in node.name.lower() or term in node.path.lower() for term in terms)
                ),
                key=lambda node: node.node_id,
            )[: query.maximum_graph_nodes]
            selected_id_set = {node.node_id for node in matching_nodes}
            for node in matching_nodes:
                selected_nodes.append(node.node_id)
                items.append(
                    ContextItem(
                        source_kind=ContextSourceKind.GRAPH_NODE,
                        source_id=node.node_id,
                        path=node.path,
                        line_start=node.line_start,
                        line_end=node.line_end,
                        content=f"{node.kind.value}: {node.name}",
                        confidence=ContextConfidence.EXTRACTED,
                        freshness=ContextFreshness.CURRENT,
                        source_sha256=node.source_sha256,
                        metadata={"symbol": node.name, "native_graph": True},
                    )
                )
            matching_edges = sorted(
                (
                    edge
                    for edge in self.graph.edges
                    if edge.source_id in selected_id_set and edge.target_id in selected_id_set
                ),
                key=lambda edge: (edge.source_id, edge.kind, edge.target_id),
            )[: query.maximum_graph_edges]
            for edge in matching_edges:
                edge_id = f"{edge.source_id}->{edge.target_id}:{edge.kind.value}"
                selected_edges.append(edge_id)
                items.append(
                    ContextItem(
                        source_kind=ContextSourceKind.GRAPH_EDGE,
                        source_id=edge_id,
                        path=edge.provenance_path,
                        line_start=edge.provenance_line,
                        content=f"{edge_id}; {edge.evidence}",
                        confidence=ContextConfidence(edge.confidence.value),
                        freshness=ContextFreshness.CURRENT,
                        metadata={"native_graph": True},
                    )
                )
            return "deterministic_fallback", reason, selected_nodes, selected_edges
        return status, reason + " Deterministic bounded file search was used.", [], []

    def _add_task_history(self, query: ContextQuery, items: list[ContextItem]) -> None:
        if not query.include_task_history or self.task_history_provider is None:
            return
        for index, record in enumerate(self.task_history_provider(query.text)):
            content = redact_text(str(record))[: query.maximum_excerpt_characters]
            if content:
                items.append(
                    ContextItem(
                        source_kind=ContextSourceKind.TASK_HISTORY,
                        source_id=f"task-history:{index}",
                        content=content,
                        confidence=ContextConfidence.EXTRACTED,
                        freshness=ContextFreshness.UNKNOWN,
                    )
                )

    def _add_policy_context(
        self, query: ContextQuery, terms: tuple[str, ...], items: list[ContextItem]
    ) -> None:
        for index, rule in enumerate(self.rules):
            if any(term in rule.lower() for term in terms):
                items.append(
                    ContextItem(
                        source_kind=ContextSourceKind.RULE,
                        source_id=f"rule:{index}",
                        content=rule,
                        confidence=ContextConfidence.VERIFIED,
                        freshness=ContextFreshness.CURRENT,
                    )
                )
        for index, contradiction in enumerate(self.contradictions):
            if any(term in contradiction.lower() for term in terms):
                items.append(
                    ContextItem(
                        source_kind=ContextSourceKind.CONTRADICTION,
                        source_id=f"contradiction:{index}",
                        content=contradiction,
                        confidence=ContextConfidence.VERIFIED,
                        freshness=ContextFreshness.CURRENT,
                    )
                )
        for reference in query.authorization_references:
            items.append(
                ContextItem(
                    source_kind=ContextSourceKind.AUTHORIZATION,
                    source_id=f"authorization:{reference}",
                    content=f"Bound authorization reference: {reference}",
                    confidence=ContextConfidence.VERIFIED,
                    freshness=ContextFreshness.UNKNOWN,
                )
            )

    def _candidate_files(self, allowed_paths: tuple[str, ...]) -> Iterable[Path]:
        allowed = tuple(path.strip("/") for path in allowed_paths)
        for directory, directory_names, file_names in os.walk(
            self.repository_root, topdown=True, followlinks=False
        ):
            directory_names[:] = sorted(
                name
                for name in directory_names
                if name not in _EXCLUDED and not (Path(directory) / name).is_symlink()
            )
            for name in sorted(file_names):
                path = Path(directory) / name
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.suffix.lower() not in _SOURCE_SUFFIXES
                ):
                    continue
                relative = path.relative_to(self.repository_root).as_posix()
                if self._secret_path(relative):
                    continue
                if allowed and not any(
                    relative == prefix or relative.startswith(f"{prefix}/") for prefix in allowed
                ):
                    continue
                try:
                    path.resolve(strict=True).relative_to(self.repository_root)
                except (OSError, ValueError):
                    continue
                yield path

    @staticmethod
    def _secret_path(relative: str) -> bool:
        parts = relative.replace("\\", "/").split("/")
        name = parts[-1].lower()
        return (
            any(part in _EXCLUDED for part in parts)
            or name == ".env"
            or name.startswith(".env.")
            or name == "agent.db"
            or name.endswith(_SECRET_SUFFIXES)
        )

    @staticmethod
    def _excerpt(text: str, terms: tuple[str, ...], maximum: int) -> tuple[str, int, int]:
        lines = text.splitlines()
        match_index = 0
        for index, line in enumerate(lines):
            if any(term in line.lower() for term in terms):
                match_index = index
                break
        start = max(0, match_index - 3)
        end = min(len(lines), match_index + 5)
        excerpt = "\n".join(lines[start:end])[:maximum]
        return excerpt, start + 1, end
