import json
import subprocess
from unittest.mock import patch

import pytest

from vulnhunter.repository_graph import (
    GraphEdgeKind,
    GraphifyAdapter,
    GraphifyAdapterError,
    NativeRepositoryGraph,
)

REVISION = "a" * 40


def _adapter(tmp_path, **kwargs):
    executable = tmp_path / "graphify"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    output = tmp_path / "out"
    adapter = GraphifyAdapter(
        repository_roots=(repo,),
        output_root=output,
        executable=executable,
        revision_resolver=lambda _root: REVISION,
        **kwargs,
    )
    return adapter, repo, output


def _write_graph(
    output,
    *,
    revision=REVISION,
    source_file="vulnhunter/service.py",
    extra_nodes=(),
):
    output.mkdir(exist_ok=True)
    nodes = [
        {
            "id": "service",
            "label": "Service",
            "source_file": source_file,
            "source_location": "L1",
            "confidence": "EXTRACTED",
        },
        *extra_nodes,
    ]
    graph = output / "graph.json"
    graph.write_text(
        json.dumps(
            {
                "built_at_commit": revision,
                "nodes": nodes,
                "links": [],
                "directed": False,
                "multigraph": False,
                "graph": {},
            }
        ),
        encoding="utf-8",
    )
    (output / "GRAPH_REPORT.md").write_text("# Controlled report\n", encoding="utf-8")
    return graph


def test_native_repository_graph_indexes_symbols_calls_and_changes(tmp_path):
    (tmp_path / "app.py").write_text(
        "def helper():\n    return 1\n\ndef run():\n    return helper()\n",
        encoding="utf-8",
    )
    (tmp_path / "test_app.py").write_text("def test_run():\n    assert True\n", encoding="utf-8")
    service = NativeRepositoryGraph(tmp_path)
    first = service.build()
    assert any(node.name == "helper" for node in first.nodes)
    assert any(edge.kind == GraphEdgeKind.CALLS for edge in first.edges)
    assert set(first.changed_files) == {"app.py", "test_app.py"}

    (tmp_path / "app.py").write_text("def helper():\n    return 2\n", encoding="utf-8")
    second = service.build(first)
    assert second.changed_files == ("app.py",)
    assert second.repository_state_sha256 != first.repository_state_sha256


def test_native_repository_graph_skips_external_symlink(tmp_path):
    external = tmp_path.parent / "outside-secret.py"
    external.write_text("SECRET = 'do-not-read'", encoding="utf-8")
    (tmp_path / "escape.py").symlink_to(external)
    snapshot = NativeRepositoryGraph(tmp_path).build()
    assert not any(item.path == "escape.py" for item in snapshot.files)


def test_graphify_adapter_is_truthfully_disabled_and_allowlisted(tmp_path, monkeypatch):
    executable = tmp_path / "graphify"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "out"
    adapter = GraphifyAdapter(
        repository_roots=(repo,),
        output_root=output,
        executable=executable,
    )
    assert adapter.readiness()["installed"] is True
    with pytest.raises(GraphifyAdapterError, match="not allowlisted"):
        adapter.plan("build", repository_root=repo, output_file=output / "graph.json")


def test_graphify_validates_current_bounded_artifact(tmp_path):
    adapter, repo, output = _adapter(tmp_path)
    graph = _write_graph(output)
    artifact = adapter.load_artifact(
        graph,
        repository_root=repo,
        graphify_version="graphify 0.9.16",
    )
    assert artifact.repository_revision == REVISION
    assert artifact.graph_bytes > 0
    assert [node.node_id for node in artifact.nodes] == ["service"]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("{", "not valid JSON"),
        (json.dumps({"built_at_commit": REVISION}), "node and edge lists"),
    ],
)
def test_graphify_rejects_malformed_json(tmp_path, payload, message):
    adapter, repo, output = _adapter(tmp_path)
    graph = _write_graph(output)
    graph.write_text(payload, encoding="utf-8")
    with pytest.raises(GraphifyAdapterError, match=message):
        adapter.load_artifact(graph, repository_root=repo, graphify_version="0.9.16")


def test_graphify_rejects_oversized_and_stale_graphs(tmp_path):
    adapter, repo, output = _adapter(tmp_path)
    graph = _write_graph(output)
    with pytest.raises(GraphifyAdapterError) as oversized:
        adapter.load_artifact(
            graph,
            repository_root=repo,
            maximum_graph_bytes=10,
            graphify_version="0.9.16",
        )
    assert oversized.value.code == "oversized_graph"

    _write_graph(output, revision="b" * 40)
    with pytest.raises(GraphifyAdapterError) as stale:
        adapter.load_artifact(graph, repository_root=repo, graphify_version="0.9.16")
    assert stale.value.code == "stale_graph"


def test_graphify_rejects_symlink_graph_and_repository_escape(tmp_path):
    adapter, repo, output = _adapter(tmp_path)
    actual = _write_graph(output)
    linked = output / "linked.json"
    linked.symlink_to(actual)
    with pytest.raises(GraphifyAdapterError) as symlinked:
        adapter.load_artifact(linked, repository_root=repo, graphify_version="0.9.16")
    assert symlinked.value.code == "symlink"

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(GraphifyAdapterError, match="not authorized"):
        adapter.load_artifact(actual, repository_root=outside, graphify_version="0.9.16")


@pytest.mark.parametrize(
    "source_file",
    [".env", "var/private.py", "secrets/signing.key", "graphify-out/cache.py"],
)
def test_graphify_rejects_ignored_and_secret_paths(tmp_path, source_file):
    adapter, repo, output = _adapter(tmp_path)
    graph = _write_graph(output, source_file=source_file)
    with pytest.raises(GraphifyAdapterError) as denied:
        adapter.load_artifact(graph, repository_root=repo, graphify_version="0.9.16")
    assert denied.value.code == "path_denied"


@pytest.mark.parametrize("forbidden", [("hook", "install"), ("--mcp",), ("watch", ".")])
def test_graphify_rejects_hook_mcp_and_watch_templates(tmp_path, forbidden):
    with pytest.raises(GraphifyAdapterError) as denied:
        _adapter(tmp_path, command_templates={"build": forbidden})
    assert denied.value.code == "operation_denied"


def test_graphify_subprocess_is_shell_free_and_exit_132_is_classified(tmp_path, monkeypatch):
    adapter, repo, output = _adapter(
        tmp_path,
        command_templates={"build": ("{repo}", "--code-only", "--max-workers", "1")},
        execution_enabled=True,
        authorizer=lambda _command: True,
    )
    monkeypatch.setattr(adapter, "_version", lambda: "graphify 0.9.16")
    command = adapter.plan("build", repository_root=repo, output_file=output / "graph.json")
    with patch("vulnhunter.repository_graph.graphify.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(command.argv, 132)
        with pytest.raises(GraphifyAdapterError) as incompatible:
            adapter.execute(command)
    assert incompatible.value.code == "runtime_incompatible"
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["stdin"] is subprocess.DEVNULL
    assert run.call_args.kwargs["timeout"] == command.timeout_seconds


def test_graphify_timeout_fails_closed(tmp_path, monkeypatch):
    adapter, repo, output = _adapter(
        tmp_path,
        command_templates={"build": ("{repo}", "--code-only", "--max-workers", "1")},
        execution_enabled=True,
        authorizer=lambda _command: True,
    )
    monkeypatch.setattr(adapter, "_version", lambda: "graphify 0.9.16")
    command = adapter.plan("build", repository_root=repo, output_file=output / "graph.json")
    with patch(
        "vulnhunter.repository_graph.graphify.subprocess.run",
        side_effect=subprocess.TimeoutExpired(command.argv, command.timeout_seconds),
    ):
        with pytest.raises(GraphifyAdapterError) as timed_out:
            adapter.execute(command)
    assert timed_out.value.code == "timeout"
