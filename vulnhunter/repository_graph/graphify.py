"""Restricted, provenance-bound Graphify adapter.

Graphify is advisory repository intelligence. It never receives authority to
approve, change scope, execute scanners, publish findings, or start hooks/MCP.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from vulnhunter.repository_graph.models import (
    GraphifyArtifact,
    GraphifyEdge,
    GraphifyNode,
    RelationshipConfidence,
)

_ALLOWED_OPERATIONS = frozenset({"build", "query", "explain", "path", "status"})
_FORBIDDEN_ARGUMENTS = frozenset(
    {
        "--mcp",
        "--watch",
        "--global",
        "hook",
        "install",
        "serve",
        "watch",
    }
)
_IGNORED_COMPONENTS = frozenset(
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
    }
)
_SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3", ".log")


class GraphifyAdapterError(RuntimeError):
    """Fail-closed Graphify planning, execution, or artifact error."""

    def __init__(self, message: str, *, code: str = "graphify_denied") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GraphifyCommand:
    operation: str
    argv: tuple[str, ...]
    repository_root: Path
    output_file: Path
    repository_revision: str
    graphify_version: str
    timeout_seconds: int
    maximum_output_bytes: int
    maximum_nodes: int
    maximum_edges: int
    planned_at: datetime


class GraphifyAdapter:
    """Allowlisted wrapper around an explicitly configured Graphify CLI.

    Normal application startup never builds a graph. Execution is disabled by
    default and additionally requires an injected authorizer for the exact plan.
    """

    def __init__(
        self,
        *,
        repository_roots: tuple[Path, ...],
        output_root: Path,
        command_templates: dict[str, tuple[str, ...]] | None = None,
        executable: str | Path = "/mnt/vulnhunter-data/tools/uv/tool-bin/graphify",
        execution_enabled: bool = False,
        authorizer: Callable[[GraphifyCommand], bool] | None = None,
        revision_resolver: Callable[[Path], str] | None = None,
    ) -> None:
        self.repository_roots = tuple(self._approved_root(path) for path in repository_roots)
        self.output_root = self._prepare_output_root(output_root)
        self.command_templates = command_templates or {}
        self.executable = self._resolve_executable(executable)
        self.execution_enabled = execution_enabled
        self.authorizer = authorizer
        self.revision_resolver = revision_resolver or self._git_revision
        if execution_enabled and authorizer is None:
            raise GraphifyAdapterError(
                "Graphify execution requires a pre-execution authorizer",
                code="authorization_missing",
            )
        for operation, template in self.command_templates.items():
            self._validate_template(operation, template)

    def readiness(self) -> dict[str, object]:
        graph = self.output_root / "graph.json"
        report = self.output_root / "GRAPH_REPORT.md"
        return {
            "installed": self.executable is not None,
            "configured_operations": tuple(sorted(self.command_templates)),
            "execution_enabled": self.execution_enabled,
            "graph_present": graph.is_file() and not graph.is_symlink(),
            "report_present": report.is_file() and not report.is_symlink(),
            "hooks_enabled": False,
            "mcp_enabled": False,
            "status": "CODE_READY_DISABLED" if self.executable else "NOT_READY",
        }

    def plan(
        self,
        operation: str,
        *,
        repository_root: Path,
        output_file: Path,
        timeout_seconds: int = 900,
        maximum_output_bytes: int = 20_000_000,
        maximum_nodes: int = 10_000,
        maximum_edges: int = 50_000,
    ) -> GraphifyCommand:
        if self.executable is None:
            raise GraphifyAdapterError("Graphify is not installed", code="not_installed")
        template = self.command_templates.get(operation)
        if operation not in _ALLOWED_OPERATIONS or template is None:
            raise GraphifyAdapterError(
                "Graphify operation is not allowlisted or configured",
                code="operation_denied",
            )
        self._validate_limits(timeout_seconds, maximum_output_bytes, maximum_nodes, maximum_edges)
        root = self._approved_root(repository_root)
        if root not in self.repository_roots:
            raise GraphifyAdapterError(
                "repository root is not authorized for Graphify",
                code="repository_denied",
            )
        destination = self._approved_output(output_file)
        replacements = {"{repo}": str(root), "{output}": str(destination)}
        argv = [str(self.executable)]
        for template_value in template:
            value = template_value
            for marker, replacement in replacements.items():
                value = value.replace(marker, replacement)
            if "{" in value or "}" in value:
                raise GraphifyAdapterError("Graphify command contains an unknown placeholder")
            argv.append(value)
        self._validate_argv(tuple(argv))
        return GraphifyCommand(
            operation=operation,
            argv=tuple(argv),
            repository_root=root,
            output_file=destination,
            repository_revision=self.revision_resolver(root),
            graphify_version=self._version(),
            timeout_seconds=timeout_seconds,
            maximum_output_bytes=maximum_output_bytes,
            maximum_nodes=maximum_nodes,
            maximum_edges=maximum_edges,
            planned_at=datetime.now(UTC),
        )

    def execute(self, command: GraphifyCommand) -> GraphifyArtifact:
        if not self.execution_enabled:
            raise GraphifyAdapterError("Graphify execution is disabled", code="disabled")
        if self.authorizer is None or not self.authorizer(command):
            raise GraphifyAdapterError(
                "Graphify authorization failed closed", code="authorization_denied"
            )
        if self.executable is None or command.argv[0] != str(self.executable):
            raise GraphifyAdapterError("Graphify plan executable binding is invalid")
        if command.repository_root not in self.repository_roots:
            raise GraphifyAdapterError("Graphify plan repository binding is invalid")
        if self.revision_resolver(command.repository_root) != command.repository_revision:
            raise GraphifyAdapterError(
                "repository revision changed after Graphify planning", code="stale_plan"
            )
        self._approved_output(command.output_file)
        self._validate_argv(command.argv)
        command.output_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        lock_path = self.output_root / ".vulnhunter-graphify.lock"
        with lock_path.open("a+b") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise GraphifyAdapterError(
                    "another Graphify operation is already running", code="busy"
                ) from exc
            return self._execute_locked(command)

    def load_artifact(
        self,
        graph_file: Path,
        *,
        repository_root: Path,
        maximum_graph_bytes: int = 20_000_000,
        maximum_nodes: int = 10_000,
        maximum_edges: int = 50_000,
        graphify_version: str | None = None,
        require_report: bool = True,
    ) -> GraphifyArtifact:
        root = self._approved_root(repository_root)
        if root not in self.repository_roots:
            raise GraphifyAdapterError("repository root is not authorized for Graphify")
        graph = self._approved_output(graph_file)
        raw, digest = self._read_regular_bounded(graph, maximum_graph_bytes)
        if require_report:
            report = graph.parent / "GRAPH_REPORT.md"
            report_raw, _ = self._read_regular_bounded(report, maximum_graph_bytes)
            if not report_raw.strip():
                raise GraphifyAdapterError("Graphify report is empty", code="malformed_graph")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GraphifyAdapterError(
                "Graphify artifact is not valid JSON", code="malformed_graph"
            ) from exc
        if not isinstance(payload, dict):
            raise GraphifyAdapterError(
                "Graphify artifact must be a JSON object", code="malformed_graph"
            )
        revision = payload.get("built_at_commit")
        current_revision = self.revision_resolver(root)
        if not isinstance(revision, str) or revision != current_revision:
            raise GraphifyAdapterError(
                "Graphify artifact is stale for the repository revision", code="stale_graph"
            )
        if self._repository_has_newer_sources(root, graph):
            raise GraphifyAdapterError(
                "Graphify artifact predates repository source changes", code="stale_graph"
            )
        raw_nodes = payload.get("nodes")
        raw_edges = payload.get("links", payload.get("edges"))
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise GraphifyAdapterError(
                "Graphify artifact has no valid node and edge lists", code="malformed_graph"
            )
        if len(raw_nodes) > maximum_nodes or len(raw_edges) > maximum_edges:
            raise GraphifyAdapterError(
                "Graphify artifact exceeds structural limits", code="oversized_graph"
            )
        nodes = self._validated_nodes(raw_nodes)
        edges = self._validated_edges(raw_edges, {node.node_id for node in nodes})
        return GraphifyArtifact(
            repository_root=str(root),
            repository_revision=revision,
            graph_path=str(graph),
            graph_sha256=digest,
            graph_bytes=len(raw),
            graphify_version=graphify_version or self._version(),
            nodes=nodes,
            edges=edges,
        )

    def _execute_locked(self, command: GraphifyCommand) -> GraphifyArtifact:
        runtime_home = self.output_root / ".runtime-home"
        runtime_home.mkdir(mode=0o700, exist_ok=True)
        environment = {
            "HOME": str(runtime_home),
            "LANG": "C.UTF-8",
            "PATH": f"{self.executable.parent}:/usr/bin:/bin",
            "PYTHONFAULTHANDLER": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "TOKENIZERS_PARALLELISM": "false",
        }
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    command.argv,
                    cwd=command.repository_root,
                    env=environment,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=command.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise GraphifyAdapterError("Graphify command timed out", code="timeout") from exc
            output_bytes = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
        if output_bytes > command.maximum_output_bytes:
            raise GraphifyAdapterError(
                "Graphify process output exceeded the configured limit",
                code="output_limit",
            )
        if completed.returncode == 132:
            raise GraphifyAdapterError(
                "Graphify terminated with SIGILL (exit 132)",
                code="runtime_incompatible",
            )
        if completed.returncode != 0:
            raise GraphifyAdapterError("Graphify command failed", code="command_failed")
        artifact = self.load_artifact(
            command.output_file,
            repository_root=command.repository_root,
            maximum_graph_bytes=command.maximum_output_bytes,
            maximum_nodes=command.maximum_nodes,
            maximum_edges=command.maximum_edges,
            graphify_version=command.graphify_version,
        )
        self._write_provenance(command, artifact)
        return artifact

    def _write_provenance(self, command: GraphifyCommand, artifact: GraphifyArtifact) -> None:
        path = command.output_file.parent / "vulnhunter-graphify-provenance.json"
        self._approved_output(path)
        if path.is_symlink():
            raise GraphifyAdapterError("Graphify provenance path may not be a symlink")
        data = {
            "schema_version": "1.0",
            "advisory_only": True,
            "hooks_enabled": False,
            "mcp_enabled": False,
            "operation": command.operation,
            "argv": list(command.argv),
            "repository_root": str(command.repository_root),
            "repository_revision": command.repository_revision,
            "graphify_version": command.graphify_version,
            "graph_sha256": artifact.graph_sha256,
            "graph_bytes": artifact.graph_bytes,
            "node_count": len(artifact.nodes),
            "edge_count": len(artifact.edges),
            "planned_at": command.planned_at.isoformat(),
            "accepted_at": datetime.now(UTC).isoformat(),
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)

    @staticmethod
    def _validate_limits(
        timeout_seconds: int,
        maximum_output_bytes: int,
        maximum_nodes: int,
        maximum_edges: int,
    ) -> None:
        if not 1 <= timeout_seconds <= 1_800:
            raise GraphifyAdapterError("Graphify timeout is outside the approved range")
        if not 1_024 <= maximum_output_bytes <= 50_000_000:
            raise GraphifyAdapterError("Graphify byte limit is outside the approved range")
        if not 1 <= maximum_nodes <= 100_000 or not 1 <= maximum_edges <= 500_000:
            raise GraphifyAdapterError("Graphify structural limits are outside the approved range")

    @staticmethod
    def _validate_template(operation: str, template: tuple[str, ...]) -> None:
        if operation not in _ALLOWED_OPERATIONS or not template:
            raise GraphifyAdapterError("Graphify command template is not approved")
        GraphifyAdapter._validate_argv(("graphify", *template))

    @staticmethod
    def _validate_argv(argv: tuple[str, ...]) -> None:
        lowered = {value.lower() for value in argv[1:]}
        if lowered & _FORBIDDEN_ARGUMENTS:
            raise GraphifyAdapterError(
                "Graphify hooks, MCP, watch, install, and global operations are forbidden",
                code="operation_denied",
            )

    @staticmethod
    def _approved_root(path: Path) -> Path:
        expanded = path.expanduser()
        if expanded.is_symlink():
            raise GraphifyAdapterError("Graphify repository root may not be a symlink")
        try:
            root = expanded.resolve(strict=True)
        except OSError as exc:
            raise GraphifyAdapterError("Graphify repository root is unavailable") from exc
        if not root.is_dir():
            raise GraphifyAdapterError("Graphify repository root must be a directory")
        return root

    @staticmethod
    def _prepare_output_root(path: Path) -> Path:
        expanded = path.expanduser()
        if expanded.exists() and expanded.is_symlink():
            raise GraphifyAdapterError("Graphify output root may not be a symlink")
        expanded.mkdir(parents=True, exist_ok=True, mode=0o700)
        return expanded.resolve(strict=True)

    def _approved_output(self, path: Path) -> Path:
        expanded = path.expanduser()
        if expanded.exists() and expanded.is_symlink():
            raise GraphifyAdapterError("Graphify output may not be a symlink", code="symlink")
        destination = expanded.resolve()
        try:
            destination.relative_to(self.output_root)
        except ValueError as exc:
            raise GraphifyAdapterError("Graphify output is outside the approved root") from exc
        return destination

    @staticmethod
    def _resolve_executable(value: str | Path) -> Path | None:
        requested = Path(value)
        if requested.is_absolute() and requested.exists():
            candidate = str(requested)
        else:
            candidate = shutil.which(requested.name if requested.is_absolute() else str(requested))
        if candidate is None:
            return None
        try:
            resolved = Path(candidate).resolve(strict=True)
        except OSError:
            return None
        return resolved if resolved.is_file() and os.access(resolved, os.X_OK) else None

    def _version(self) -> str:
        if self.executable is None:
            raise GraphifyAdapterError("Graphify is not installed", code="not_installed")
        try:
            completed = subprocess.run(
                (str(self.executable), "--version"),
                env={"HOME": str(self.output_root), "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GraphifyAdapterError("Graphify version probe timed out") from exc
        if completed.returncode == 132:
            raise GraphifyAdapterError(
                "Graphify version probe terminated with SIGILL", code="runtime_incompatible"
            )
        if completed.returncode != 0 or len(completed.stdout) + len(completed.stderr) > 4_096:
            raise GraphifyAdapterError("Graphify version probe failed")
        value = completed.stdout.decode("utf-8", errors="replace").strip()
        if not value:
            raise GraphifyAdapterError("Graphify version probe returned no version")
        return value[:128]

    @staticmethod
    def _git_revision(root: Path) -> str:
        git = shutil.which("git")
        if git is None:
            raise GraphifyAdapterError("Git is unavailable for repository binding")
        completed = subprocess.run(
            (str(Path(git).resolve()), "-C", str(root), "rev-parse", "HEAD"),
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        revision = completed.stdout.decode("ascii", errors="ignore").strip()
        if completed.returncode != 0 or len(revision) not in {40, 64}:
            raise GraphifyAdapterError("repository revision could not be verified")
        return revision

    @staticmethod
    def _read_regular_bounded(path: Path, maximum_bytes: int) -> tuple[bytes, str]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise GraphifyAdapterError("Graphify artifact is missing or unsafe") from exc
        data = bytearray()
        digest = hashlib.sha256()
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > maximum_bytes:
                raise GraphifyAdapterError(
                    "Graphify artifact exceeds the configured limit", code="oversized_graph"
                )
            while True:
                chunk = os.read(descriptor, min(1_048_576, maximum_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                digest.update(chunk)
                if len(data) > maximum_bytes:
                    raise GraphifyAdapterError(
                        "Graphify artifact exceeds the configured limit", code="oversized_graph"
                    )
        finally:
            os.close(descriptor)
        return bytes(data), digest.hexdigest()

    @classmethod
    def _repository_has_newer_sources(cls, root: Path, graph: Path) -> bool:
        """Conservatively reject a graph older than any indexable source file.

        Graphify records Git HEAD, but an uncommitted working tree can change while
        HEAD remains constant. The mtime check prevents such a graph from being
        presented as current. A rebuilt graph naturally becomes newer than its
        inputs.
        """

        graph_mtime = graph.stat().st_mtime_ns
        indexed_suffixes = {
            ".c",
            ".cc",
            ".cpp",
            ".cs",
            ".css",
            ".go",
            ".h",
            ".hpp",
            ".html",
            ".java",
            ".js",
            ".jsx",
            ".json",
            ".kt",
            ".kts",
            ".mjs",
            ".php",
            ".py",
            ".rb",
            ".rs",
            ".scala",
            ".sh",
            ".sql",
            ".swift",
            ".ts",
            ".tsx",
            ".vue",
        }
        for candidate in root.rglob("*"):
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            if any(part in _IGNORED_COMPONENTS for part in relative.parts):
                continue
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.suffix.lower() not in indexed_suffixes:
                continue
            try:
                if candidate.stat().st_mtime_ns > graph_mtime:
                    return True
            except OSError:
                return True
        return False

    @classmethod
    def _validated_nodes(cls, raw_nodes: list[object]) -> tuple[GraphifyNode, ...]:
        nodes: list[GraphifyNode] = []
        seen: set[str] = set()
        for raw in raw_nodes:
            if not isinstance(raw, dict):
                raise GraphifyAdapterError("Graphify node is malformed", code="malformed_graph")
            node_id = raw.get("id")
            label = raw.get("label")
            source_file = raw.get("source_file")
            if not isinstance(node_id, str) or not isinstance(label, str):
                raise GraphifyAdapterError("Graphify node identity is malformed")
            if node_id in seen:
                raise GraphifyAdapterError("Graphify node identities are not unique")
            seen.add(node_id)
            if source_file is not None:
                if not isinstance(source_file, str) or not cls._safe_source_path(source_file):
                    raise GraphifyAdapterError(
                        "Graphify node references an ignored or secret path",
                        code="path_denied",
                    )
            nodes.append(
                GraphifyNode(
                    node_id=node_id,
                    label=label,
                    source_file=source_file,
                    source_location=(
                        str(raw["source_location"]) if raw.get("source_location") else None
                    ),
                    confidence=cls._confidence(raw.get("confidence")),
                )
            )
        return tuple(nodes)

    @classmethod
    def _validated_edges(
        cls, raw_edges: list[object], node_ids: set[str]
    ) -> tuple[GraphifyEdge, ...]:
        edges: list[GraphifyEdge] = []
        for raw in raw_edges:
            if not isinstance(raw, dict):
                raise GraphifyAdapterError("Graphify edge is malformed", code="malformed_graph")
            source = raw.get("source")
            target = raw.get("target")
            relation = raw.get("relation", raw.get("type", "references"))
            if (
                not isinstance(source, str)
                or not isinstance(target, str)
                or not isinstance(relation, str)
                or source not in node_ids
                or target not in node_ids
            ):
                raise GraphifyAdapterError("Graphify edge identity is malformed")
            edges.append(
                GraphifyEdge(
                    source_id=source,
                    target_id=target,
                    relation=relation,
                    confidence=cls._confidence(raw.get("confidence")),
                )
            )
        return tuple(edges)

    @staticmethod
    def _confidence(value: object) -> RelationshipConfidence:
        normalized = str(value or "extracted").lower()
        try:
            return RelationshipConfidence(normalized)
        except ValueError:
            return RelationshipConfidence.AMBIGUOUS

    @staticmethod
    def _safe_source_path(value: str) -> bool:
        path = PurePosixPath(value.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            return False
        if any(part in _IGNORED_COMPONENTS for part in path.parts):
            return False
        name = path.name.lower()
        if name == ".env" or name.startswith(".env.") or name == "agent.db":
            return False
        return not name.endswith(_SECRET_SUFFIXES)
