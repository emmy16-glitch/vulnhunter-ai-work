import pytest

from vulnhunter.taskgraph import GraphNode, NodeStatus, TaskGraph, TaskGraphStore
from vulnhunter.taskgraph.store import TaskGraphStoreError


def test_taskgraph_enforces_dependencies_and_terminal_states(tmp_path):
    graph = TaskGraph(
        graph_id="graph-01",
        campaign_id="campaign-01",
        run_id="run-01",
        nodes=(
            GraphNode(
                node_id="discover",
                role_id="scanner-evidence-specialist",
                skill_id="governed-security-tool-operation",
                action_manifest_sha256="a" * 64,
            ),
            GraphNode(
                node_id="verify",
                role_id="independent-security-verifier",
                skill_id="independent-security-verification",
                action_manifest_sha256="b" * 64,
                dependencies=("discover",),
            ),
        ),
    )
    store = TaskGraphStore(tmp_path)
    store.save(graph)
    assert [node.node_id for node in store.ready_nodes("graph-01")] == ["discover"]

    store.update_status("graph-01", node_id="discover", status=NodeStatus.RUNNING)
    store.update_status("graph-01", node_id="discover", status=NodeStatus.COMPLETED)
    assert [node.node_id for node in store.ready_nodes("graph-01")] == ["verify"]

    with pytest.raises(ValueError, match="cycle"):
        TaskGraph(
            graph_id="graph-cycle",
            campaign_id="campaign-01",
            run_id="run-01",
            nodes=(
                GraphNode(
                    node_id="a-node",
                    role_id="orchestrator",
                    skill_id="bounded-task-routing",
                    action_manifest_sha256="a" * 64,
                    dependencies=("b-node",),
                ),
                GraphNode(
                    node_id="b-node",
                    role_id="orchestrator",
                    skill_id="bounded-task-routing",
                    action_manifest_sha256="b" * 64,
                    dependencies=("a-node",),
                ),
            ),
        )


def test_task_graph_store_rejects_path_traversal_identifier(tmp_path):
    store = TaskGraphStore(tmp_path / "graphs")
    with pytest.raises(TaskGraphStoreError, match="malformed"):
        store.load("../../outside")


def test_task_graph_revision_cas_and_immutable_bindings(tmp_path):
    graph = TaskGraph(
        graph_id="graph-cas",
        campaign_id="campaign-01",
        run_id="run-01",
        nodes=(
            GraphNode(
                node_id="discover",
                role_id="scanner-evidence-specialist",
                skill_id="governed-security-tool-operation",
                action_manifest_sha256="a" * 64,
            ),
        ),
    )
    store = TaskGraphStore(tmp_path)
    store.save(graph)
    updated = store.update_status(
        "graph-cas",
        node_id="discover",
        status=NodeStatus.RUNNING,
        expected_revision=0,
    )
    assert updated.revision == 1

    from vulnhunter.taskgraph import TaskGraphConflict

    with pytest.raises(TaskGraphConflict, match="revision conflict"):
        store.update_status(
            "graph-cas",
            node_id="discover",
            status=NodeStatus.COMPLETED,
            expected_revision=0,
        )

    changed = updated.nodes[0].model_copy(update={"role_id": "orchestrator"})
    forged = updated.model_copy(
        update={"nodes": (changed,), "revision": 2, "updated_at": updated.updated_at}
    )
    with pytest.raises(ValueError, match="immutable"):
        forged.validate_update_from(updated)


def test_task_graph_worker_leases_are_bounded_and_recoverable(tmp_path):
    from datetime import UTC, datetime, timedelta

    from vulnhunter.taskgraph import TaskGraphLeaseError

    now = datetime(2026, 7, 15, 10, 0, tzinfo=UTC)
    graph = TaskGraph(
        graph_id="graph-lease",
        campaign_id="campaign-01",
        run_id="run-01",
        created_at=now,
        updated_at=now,
        nodes=(
            GraphNode(
                node_id="discover",
                role_id="scanner-evidence-specialist",
                skill_id="governed-security-tool-operation",
                action_manifest_sha256="a" * 64,
                status=NodeStatus.READY,
                updated_at=now,
            ),
        ),
    )
    store = TaskGraphStore(tmp_path)
    store.save(graph)
    leased, token = store.acquire_lease(
        "graph-lease",
        node_id="discover",
        owner_id="worker-01",
        ttl_seconds=30,
        expected_revision=0,
        now=now,
    )
    assert leased.revision == 1
    assert leased.nodes[0].lease is not None
    assert leased.nodes[0].lease.owner_id == "worker-01"

    with pytest.raises(TaskGraphLeaseError, match="active lease"):
        store.acquire_lease(
            "graph-lease",
            node_id="discover",
            owner_id="worker-02",
            ttl_seconds=30,
            expected_revision=1,
            now=now + timedelta(seconds=1),
        )

    renewed = store.renew_lease(
        "graph-lease",
        node_id="discover",
        owner_id="worker-01",
        raw_token=token,
        ttl_seconds=30,
        expected_revision=1,
        now=now + timedelta(seconds=5),
    )
    assert renewed.revision == 2
    assert renewed.nodes[0].lease.renewal_count == 1

    recovered = store.recover_expired_leases(
        "graph-lease",
        expected_revision=2,
        now=now + timedelta(seconds=40),
    )
    assert recovered.revision == 3
    assert recovered.nodes[0].lease is None
    assert recovered.nodes[0].status == NodeStatus.READY
