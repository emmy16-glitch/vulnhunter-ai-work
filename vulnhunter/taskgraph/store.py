"""Locked, atomic persistence with revision CAS and bounded worker leases."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.taskgraph.models import (
    TERMINAL_STATUSES,
    GraphNode,
    NodeStatus,
    TaskGraph,
    WorkerLease,
    utc_now,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - project targets Linux
    fcntl = None

_GRAPH_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class TaskGraphStoreError(RuntimeError):
    pass


class TaskGraphConflict(TaskGraphStoreError):
    pass


class TaskGraphLeaseError(TaskGraphStoreError):
    pass


class TaskGraphStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.root / ".taskgraph.lock"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._lock_path.touch(exist_ok=True)
        with self._lock_path.open("r+") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def save(self, graph: TaskGraph, *, expected_revision: int | None = None) -> Path:
        """Create a graph, or CAS-update an existing graph when expected_revision is supplied."""
        with self._locked():
            path = self._path(graph.graph_id)
            if path.exists():
                previous = self._load_unlocked(graph.graph_id)
                if expected_revision is None:
                    if graph == previous:
                        return path
                    raise TaskGraphConflict("existing graph updates require expected_revision")
                if previous.revision != expected_revision:
                    raise TaskGraphConflict(
                        f"task graph revision conflict: expected {expected_revision}, "
                        f"found {previous.revision}"
                    )
                try:
                    graph.validate_update_from(previous)
                except ValueError as exc:
                    raise TaskGraphStoreError(f"invalid task graph update: {exc}") from exc
            else:
                if expected_revision is not None:
                    raise TaskGraphConflict("cannot CAS-update a graph that does not exist")
                if graph.revision != 0:
                    raise TaskGraphStoreError("new task graphs must start at revision zero")
            self._write_graph_unlocked(graph)
            return path

    def load(self, graph_id: str) -> TaskGraph:
        with self._locked():
            return self._load_unlocked(graph_id)

    def ready_nodes(self, graph_id: str) -> tuple[GraphNode, ...]:
        graph = self.load(graph_id)
        by_id = {node.node_id: node for node in graph.nodes}
        return tuple(
            node
            for node in graph.nodes
            if node.status in {NodeStatus.PENDING, NodeStatus.READY}
            and all(by_id[item].status == NodeStatus.COMPLETED for item in node.dependencies)
        )

    def update_status(
        self,
        graph_id: str,
        *,
        node_id: str,
        status: NodeStatus,
        last_error: str | None = None,
        expected_revision: int | None = None,
        now: datetime | None = None,
    ) -> TaskGraph:
        timestamp = now or utc_now()
        with self._locked():
            graph = self._load_unlocked(graph_id)
            self._assert_expected_revision(graph, expected_revision)
            nodes: list[GraphNode] = []
            found = False
            for node in graph.nodes:
                if node.node_id != node_id:
                    nodes.append(node)
                    continue
                found = True
                if node.lease is not None and status != NodeStatus.RUNNING:
                    raise TaskGraphLeaseError(
                        "release the active lease before leaving running state"
                    )
                attempts = node.attempts + (
                    1 if status == NodeStatus.RUNNING and node.status != status else 0
                )
                candidate = node.model_copy(
                    update={
                        "status": status,
                        "attempts": attempts,
                        "last_error": last_error,
                        "updated_at": timestamp,
                    }
                )
                candidate = GraphNode.model_validate(candidate.model_dump())
                nodes.append(candidate)
            if not found:
                raise TaskGraphStoreError(f"unknown task node: {node_id}")
            updated = self._next_graph(graph, tuple(nodes), timestamp)
            self._write_graph_unlocked(updated)
            return updated

    def acquire_lease(
        self,
        graph_id: str,
        *,
        node_id: str,
        owner_id: str,
        ttl_seconds: int = 120,
        maximum_renewals: int = 100,
        expected_revision: int | None = None,
        now: datetime | None = None,
    ) -> tuple[TaskGraph, str]:
        if ttl_seconds < 5 or ttl_seconds > 86_400:
            raise TaskGraphLeaseError("lease TTL must be between 5 and 86400 seconds")
        timestamp = now or utc_now()
        raw_token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
        with self._locked():
            graph = self._load_unlocked(graph_id)
            self._assert_expected_revision(graph, expected_revision)
            nodes: list[GraphNode] = []
            found = False
            for node in graph.nodes:
                if node.node_id != node_id:
                    nodes.append(node)
                    continue
                found = True
                if node.status in TERMINAL_STATUSES:
                    raise TaskGraphLeaseError("terminal nodes cannot be leased")
                if node.status not in {NodeStatus.READY, NodeStatus.RUNNING}:
                    raise TaskGraphLeaseError("only ready or running nodes can be leased")
                if node.lease is not None and not node.lease.is_expired(now=timestamp):
                    raise TaskGraphLeaseError("task node already has an active lease")
                lease = WorkerLease(
                    owner_id=owner_id,
                    token_sha256=token_sha256,
                    acquired_at=timestamp,
                    heartbeat_at=timestamp,
                    expires_at=timestamp + timedelta(seconds=ttl_seconds),
                    maximum_renewals=maximum_renewals,
                )
                candidate = node.model_copy(
                    update={
                        "status": NodeStatus.RUNNING,
                        "attempts": node.attempts + (1 if node.status != NodeStatus.RUNNING else 0),
                        "lease": lease,
                        "updated_at": timestamp,
                    }
                )
                nodes.append(GraphNode.model_validate(candidate.model_dump()))
            if not found:
                raise TaskGraphStoreError(f"unknown task node: {node_id}")
            updated = self._next_graph(graph, tuple(nodes), timestamp)
            self._write_graph_unlocked(updated)
            return updated, raw_token

    def renew_lease(
        self,
        graph_id: str,
        *,
        node_id: str,
        owner_id: str,
        raw_token: str,
        ttl_seconds: int = 120,
        expected_revision: int | None = None,
        now: datetime | None = None,
    ) -> TaskGraph:
        if ttl_seconds < 5 or ttl_seconds > 86_400:
            raise TaskGraphLeaseError("lease TTL must be between 5 and 86400 seconds")
        timestamp = now or utc_now()
        token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
        with self._locked():
            graph = self._load_unlocked(graph_id)
            self._assert_expected_revision(graph, expected_revision)
            nodes = self._map_lease_node(
                graph,
                node_id=node_id,
                owner_id=owner_id,
                token_sha256=token_sha256,
                operation="renew",
                timestamp=timestamp,
                ttl_seconds=ttl_seconds,
            )
            updated = self._next_graph(graph, nodes, timestamp)
            self._write_graph_unlocked(updated)
            return updated

    def release_lease(
        self,
        graph_id: str,
        *,
        node_id: str,
        owner_id: str,
        raw_token: str,
        next_status: NodeStatus = NodeStatus.READY,
        expected_revision: int | None = None,
        now: datetime | None = None,
    ) -> TaskGraph:
        if next_status == NodeStatus.RUNNING:
            raise TaskGraphLeaseError("released nodes cannot remain running")
        timestamp = now or utc_now()
        token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
        with self._locked():
            graph = self._load_unlocked(graph_id)
            self._assert_expected_revision(graph, expected_revision)
            nodes: list[GraphNode] = []
            found = False
            for node in graph.nodes:
                if node.node_id != node_id:
                    nodes.append(node)
                    continue
                found = True
                self._validate_lease(node, owner_id, token_sha256, timestamp, allow_expired=False)
                candidate = node.model_copy(
                    update={"lease": None, "status": next_status, "updated_at": timestamp}
                )
                nodes.append(GraphNode.model_validate(candidate.model_dump()))
            if not found:
                raise TaskGraphStoreError(f"unknown task node: {node_id}")
            updated = self._next_graph(graph, tuple(nodes), timestamp)
            self._write_graph_unlocked(updated)
            return updated

    def recover_expired_leases(
        self,
        graph_id: str,
        *,
        expected_revision: int | None = None,
        now: datetime | None = None,
    ) -> TaskGraph:
        timestamp = now or utc_now()
        with self._locked():
            graph = self._load_unlocked(graph_id)
            self._assert_expected_revision(graph, expected_revision)
            changed = False
            nodes: list[GraphNode] = []
            for node in graph.nodes:
                if node.lease is None or not node.lease.is_expired(now=timestamp):
                    nodes.append(node)
                    continue
                changed = True
                candidate = node.model_copy(
                    update={
                        "lease": None,
                        "status": NodeStatus.READY,
                        "last_error": "worker lease expired; task recovered",
                        "updated_at": timestamp,
                    }
                )
                nodes.append(GraphNode.model_validate(candidate.model_dump()))
            if not changed:
                return graph
            updated = self._next_graph(graph, tuple(nodes), timestamp)
            self._write_graph_unlocked(updated)
            return updated

    def _map_lease_node(
        self,
        graph: TaskGraph,
        *,
        node_id: str,
        owner_id: str,
        token_sha256: str,
        operation: str,
        timestamp: datetime,
        ttl_seconds: int,
    ) -> tuple[GraphNode, ...]:
        nodes: list[GraphNode] = []
        found = False
        for node in graph.nodes:
            if node.node_id != node_id:
                nodes.append(node)
                continue
            found = True
            lease = self._validate_lease(node, owner_id, token_sha256, timestamp)
            if operation != "renew":
                raise TaskGraphLeaseError("unsupported lease operation")
            if lease.renewal_count >= lease.maximum_renewals:
                raise TaskGraphLeaseError("lease renewal limit exceeded")
            renewed = lease.model_copy(
                update={
                    "heartbeat_at": timestamp,
                    "expires_at": timestamp + timedelta(seconds=ttl_seconds),
                    "renewal_count": lease.renewal_count + 1,
                }
            )
            candidate = node.model_copy(update={"lease": renewed, "updated_at": timestamp})
            nodes.append(GraphNode.model_validate(candidate.model_dump()))
        if not found:
            raise TaskGraphStoreError(f"unknown task node: {node_id}")
        return tuple(nodes)

    @staticmethod
    def _validate_lease(
        node: GraphNode,
        owner_id: str,
        token_sha256: str,
        timestamp: datetime,
        *,
        allow_expired: bool = False,
    ) -> WorkerLease:
        lease = node.lease
        if lease is None:
            raise TaskGraphLeaseError("task node does not have a lease")
        if lease.owner_id != owner_id or lease.token_sha256 != token_sha256:
            raise TaskGraphLeaseError("worker lease identity or token does not match")
        if lease.is_expired(now=timestamp) and not allow_expired:
            raise TaskGraphLeaseError("worker lease has expired")
        return lease

    @staticmethod
    def _assert_expected_revision(graph: TaskGraph, expected: int | None) -> None:
        if expected is not None and graph.revision != expected:
            raise TaskGraphConflict(
                f"task graph revision conflict: expected {expected}, found {graph.revision}"
            )

    @staticmethod
    def _next_graph(
        graph: TaskGraph, nodes: tuple[GraphNode, ...], timestamp: datetime
    ) -> TaskGraph:
        candidate = graph.model_copy(
            update={"nodes": nodes, "revision": graph.revision + 1, "updated_at": timestamp}
        )
        candidate = TaskGraph.model_validate(candidate.model_dump())
        try:
            candidate.validate_update_from(graph)
        except ValueError as exc:
            raise TaskGraphStoreError(f"invalid task graph update: {exc}") from exc
        return candidate

    def _path(self, graph_id: str) -> Path:
        if _GRAPH_ID.fullmatch(graph_id) is None:
            raise TaskGraphStoreError("task graph identifier is malformed")
        directory = self.root / graph_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "graph-envelope.json"

    def _load_unlocked(self, graph_id: str) -> TaskGraph:
        path = self._path(graph_id)
        if path.is_file():
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                graph_data = envelope["graph"]
                expected = envelope["graph_sha256"]
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise TaskGraphStoreError("task graph envelope is invalid") from exc
            actual = sha256_json(graph_data)
            if actual != expected:
                raise TaskGraphStoreError("task graph failed integrity verification")
            try:
                return TaskGraph.model_validate(graph_data)
            except ValidationError as exc:
                raise TaskGraphStoreError("task graph is invalid") from exc

        # One-time compatibility path for the previous graph.json + digest format.
        directory = self.root / graph_id
        legacy = directory / "graph.json"
        digest = directory / "graph.sha256"
        if not legacy.is_file() or not digest.is_file():
            raise TaskGraphStoreError(f"task graph does not exist: {graph_id}")
        data = legacy.read_text(encoding="utf-8")
        expected = digest.read_text(encoding="utf-8").strip()
        if hashlib.sha256(data.encode()).hexdigest() != expected:
            raise TaskGraphStoreError("task graph failed integrity verification")
        try:
            graph = TaskGraph.model_validate_json(data)
        except ValidationError as exc:
            raise TaskGraphStoreError("task graph is invalid") from exc
        self._write_graph_unlocked(graph)
        return graph

    def _write_graph_unlocked(self, graph: TaskGraph) -> None:
        path = self._path(graph.graph_id)
        graph_data = graph.model_dump(mode="json")
        envelope = {
            "schema_version": "1.0",
            "graph": graph_data,
            "graph_sha256": sha256_json(graph_data),
        }
        data = json.dumps(envelope, sort_keys=True, indent=2) + "\n"
        self._atomic_write(path, data)

    @staticmethod
    def _atomic_write(path: Path, data: str) -> None:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
