"""Static-first native repository graph indexing and bounded queries."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.repository_graph.models import (
    GraphEdgeKind,
    GraphNodeKind,
    RelationshipConfidence,
    RepositoryFileState,
    RepositoryGraphEdge,
    RepositoryGraphNode,
    RepositoryGraphSnapshot,
)

_EXCLUDED_COMPONENTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        "coverage",
        ".pytest_cache",
        ".ruff_cache",
    }
)
_MD_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class RepositoryGraphError(RuntimeError):
    pass


class NativeRepositoryGraph:
    def __init__(self, root: Path, *, maximum_file_bytes: int = 2_000_000) -> None:
        self.root = root.expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise RepositoryGraphError("repository root must be a directory")
        self.maximum_file_bytes = maximum_file_bytes

    def build(self, previous: RepositoryGraphSnapshot | None = None) -> RepositoryGraphSnapshot:
        states: list[RepositoryFileState] = []
        nodes: list[RepositoryGraphNode] = []
        edges: list[RepositoryGraphEdge] = []
        symbol_index: dict[str, list[str]] = {}
        pending_calls: list[tuple[str, str, str, int]] = []

        candidates = tuple(self._candidate_files())
        for path in candidates:
            relative = path.relative_to(self.root).as_posix()
            try:
                stat_before = path.stat()
                if stat_before.st_size > self.maximum_file_bytes:
                    continue
                raw = path.read_bytes()
                stat_after = path.stat()
            except (OSError, PermissionError):
                continue
            if stat_before.st_ino != stat_after.st_ino or stat_before.st_size != stat_after.st_size:
                continue
            digest = hashlib.sha256(raw).hexdigest()
            states.append(RepositoryFileState(path=relative, sha256=digest, size_bytes=len(raw)))
            if path.suffix == ".py":
                self._index_python(relative, raw, digest, nodes, edges, symbol_index, pending_calls)
            elif path.suffix.lower() in {".md", ".rst", ".txt"}:
                self._index_document(relative, raw, digest, nodes, edges)

        node_ids = {node.node_id for node in nodes}
        for source_id, called_name, provenance_path, line in pending_calls:
            targets = symbol_index.get(called_name, [])
            confidence = (
                RelationshipConfidence.EXTRACTED
                if len(targets) == 1
                else RelationshipConfidence.AMBIGUOUS
            )
            for target_id in targets[:20]:
                if source_id in node_ids and target_id in node_ids:
                    edges.append(
                        RepositoryGraphEdge(
                            source_id=source_id,
                            target_id=target_id,
                            kind=GraphEdgeKind.CALLS,
                            confidence=confidence,
                            provenance_path=provenance_path,
                            provenance_line=line,
                            evidence=f"AST call expression references {called_name}",
                        )
                    )

        self._add_test_mappings(nodes, edges)
        states_tuple = tuple(sorted(states, key=lambda item: item.path))
        previous_map = {item.path: item.sha256 for item in previous.files} if previous else {}
        current_map = {item.path: item.sha256 for item in states_tuple}
        changed = tuple(
            sorted(path for path, digest in current_map.items() if previous_map.get(path) != digest)
        )
        removed = tuple(sorted(set(previous_map) - set(current_map)))
        state_sha = sha256_json([item.model_dump(mode="json") for item in states_tuple])
        return RepositoryGraphSnapshot(
            repository_root=str(self.root),
            repository_state_sha256=state_sha,
            nodes=tuple(sorted(nodes, key=lambda item: item.node_id)),
            edges=tuple(
                sorted(edges, key=lambda item: (item.source_id, item.kind, item.target_id))
            ),
            files=states_tuple,
            changed_files=changed,
            removed_files=removed,
        )

    def save(self, snapshot: RepositoryGraphSnapshot, path: Path) -> None:
        destination = path.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = snapshot.model_dump(mode="json")
        envelope = {"snapshot": data, "snapshot_sha256": sha256_json(data)}
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(
            json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        temporary.replace(destination)

    @staticmethod
    def load(path: Path) -> RepositoryGraphSnapshot:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            snapshot = envelope["snapshot"]
            expected = envelope["snapshot_sha256"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RepositoryGraphError("repository graph artifact is invalid") from exc
        if sha256_json(snapshot) != expected:
            raise RepositoryGraphError("repository graph artifact failed integrity verification")
        return RepositoryGraphSnapshot.model_validate(snapshot)

    @staticmethod
    def neighbors(
        snapshot: RepositoryGraphSnapshot,
        node_id: str,
        *,
        maximum_edges: int = 100,
    ) -> tuple[RepositoryGraphEdge, ...]:
        if maximum_edges < 1 or maximum_edges > 10_000:
            raise ValueError("maximum_edges must be between 1 and 10000")
        return tuple(
            edge
            for edge in snapshot.edges
            if edge.source_id == node_id or edge.target_id == node_id
        )[:maximum_edges]

    def _candidate_files(self) -> Iterable[Path]:
        for path in sorted(self.root.rglob("*")):
            if any(part in _EXCLUDED_COMPONENTS for part in path.relative_to(self.root).parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(self.root)
            except (OSError, ValueError):
                continue
            if path.suffix.lower() in {".py", ".md", ".rst", ".txt"}:
                yield path

    def _index_python(self, relative, raw, digest, nodes, edges, symbol_index, pending_calls):
        try:
            text = raw.decode("utf-8")
            tree = ast.parse(text, filename=relative)
        except (UnicodeDecodeError, SyntaxError):
            return
        file_id = self._node_id("file", relative)
        module_name = relative[:-3].replace("/", ".") if relative.endswith(".py") else relative
        module_id = self._node_id("module", module_name)
        nodes.extend(
            (
                RepositoryGraphNode(
                    node_id=file_id,
                    kind=GraphNodeKind.FILE,
                    name=relative,
                    path=relative,
                    source_sha256=digest,
                ),
                RepositoryGraphNode(
                    node_id=module_id,
                    kind=GraphNodeKind.MODULE,
                    name=module_name,
                    path=relative,
                    source_sha256=digest,
                ),
            )
        )
        edges.append(
            RepositoryGraphEdge(
                source_id=file_id,
                target_id=module_id,
                kind=GraphEdgeKind.DEFINES,
                confidence=RelationshipConfidence.EXTRACTED,
                provenance_path=relative,
                provenance_line=1,
                evidence="Python file defines module",
            )
        )
        parent_stack: list[str] = [module_id]

        class Visitor(ast.NodeVisitor):
            def visit_ClassDef(visitor_self, node: ast.ClassDef):
                node_id = self._node_id("class", f"{module_name}:{node.name}")
                nodes.append(
                    RepositoryGraphNode(
                        node_id=node_id,
                        kind=GraphNodeKind.CLASS,
                        name=node.name,
                        path=relative,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        source_sha256=digest,
                    )
                )
                symbol_index.setdefault(node.name, []).append(node_id)
                edges.append(
                    self._defines_edge(
                        parent_stack[-1], node_id, relative, node.lineno, "AST class definition"
                    )
                )
                parent_stack.append(node_id)
                visitor_self.generic_visit(node)
                parent_stack.pop()

            def visit_FunctionDef(visitor_self, node: ast.FunctionDef):
                kind = (
                    GraphNodeKind.METHOD
                    if parent_stack[-1].startswith("class:")
                    else (
                        GraphNodeKind.TEST
                        if node.name.startswith("test_")
                        else GraphNodeKind.FUNCTION
                    )
                )
                node_id = self._node_id(kind.value, f"{module_name}:{node.name}:{node.lineno}")
                nodes.append(
                    RepositoryGraphNode(
                        node_id=node_id,
                        kind=kind,
                        name=node.name,
                        path=relative,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        source_sha256=digest,
                    )
                )
                symbol_index.setdefault(node.name, []).append(node_id)
                edges.append(
                    self._defines_edge(
                        parent_stack[-1], node_id, relative, node.lineno, "AST function definition"
                    )
                )
                parent_stack.append(node_id)
                visitor_self.generic_visit(node)
                parent_stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Import(visitor_self, node: ast.Import):
                for alias in node.names:
                    target = self._node_id("module", alias.name)
                    edges.append(
                        self._import_edge(module_id, target, relative, node.lineno, alias.name)
                    )
                visitor_self.generic_visit(node)

            def visit_ImportFrom(visitor_self, node: ast.ImportFrom):
                if node.module:
                    target = self._node_id("module", node.module)
                    edges.append(
                        self._import_edge(module_id, target, relative, node.lineno, node.module)
                    )
                visitor_self.generic_visit(node)

            def visit_Call(visitor_self, node: ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name:
                    pending_calls.append((parent_stack[-1], name, relative, node.lineno))
                visitor_self.generic_visit(node)

        Visitor().visit(tree)

    def _index_document(self, relative, raw, digest, nodes, edges):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        document_id = self._node_id("document", relative)
        nodes.append(
            RepositoryGraphNode(
                node_id=document_id,
                kind=GraphNodeKind.DOCUMENT,
                name=relative,
                path=relative,
                source_sha256=digest,
            )
        )
        for line_number, line in enumerate(text.splitlines(), start=1):
            for target in _MD_LINK.findall(line):
                if "://" in target or target.startswith("#"):
                    continue
                clean = target.split("#", 1)[0]
                if not clean:
                    continue
                target_path = (Path(relative).parent / clean).as_posix()
                edges.append(
                    RepositoryGraphEdge(
                        source_id=document_id,
                        target_id=self._node_id("document", target_path),
                        kind=GraphEdgeKind.LINKS,
                        confidence=RelationshipConfidence.EXTRACTED,
                        provenance_path=relative,
                        provenance_line=line_number,
                        evidence=f"Markdown link to {clean}",
                    )
                )

    @staticmethod
    def _add_test_mappings(nodes, edges):
        source_nodes = [
            node
            for node in nodes
            if node.kind in {GraphNodeKind.FILE, GraphNodeKind.MODULE}
            and not node.path.startswith("tests/")
        ]
        test_nodes = [node for node in nodes if node.kind == GraphNodeKind.TEST]
        for test_node in test_nodes:
            normalized = test_node.path.rsplit("/", 1)[-1].removeprefix("test_").removesuffix(".py")
            matches = [
                node
                for node in source_nodes
                if normalized and normalized in node.path.rsplit("/", 1)[-1]
            ]
            for source in matches[:10]:
                edges.append(
                    RepositoryGraphEdge(
                        source_id=test_node.node_id,
                        target_id=source.node_id,
                        kind=GraphEdgeKind.TESTS,
                        confidence=RelationshipConfidence.INFERRED,
                        provenance_path=test_node.path,
                        provenance_line=test_node.line_start,
                        evidence="Test filename heuristically maps to source filename",
                    )
                )

    @staticmethod
    def _node_id(kind: str, value: str) -> str:
        clean = re.sub(r"[^a-z0-9._:/#-]+", "-", value.lower()).strip("-")
        return f"{kind}:{clean}"[:512]

    @staticmethod
    def _defines_edge(source, target, path, line, evidence):
        return RepositoryGraphEdge(
            source_id=source,
            target_id=target,
            kind=GraphEdgeKind.DEFINES,
            confidence=RelationshipConfidence.EXTRACTED,
            provenance_path=path,
            provenance_line=line,
            evidence=evidence,
        )

    @staticmethod
    def _import_edge(source, target, path, line, imported):
        return RepositoryGraphEdge(
            source_id=source,
            target_id=target,
            kind=GraphEdgeKind.IMPORTS,
            confidence=RelationshipConfidence.EXTRACTED,
            provenance_path=path,
            provenance_line=line,
            evidence=f"AST import of {imported}",
        )
