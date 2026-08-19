from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.agent_activity.hierarchy import build_activity_tree
from vulnhunter.agent_activity.read_models import event_to_public_dict
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore


def _event(sequence: int, event_type: str, summary: str, **extra: object) -> dict[str, object]:
    return {
        "event_id": f"evt-{sequence}",
        "sequence": sequence,
        "event_type": event_type,
        "summary": summary,
        "source": "runtime",
        "timestamp": f"2026-08-19T10:00:{sequence:02d}+00:00",
        **extra,
    }


def test_tree_groups_only_persisted_events_and_exposes_safe_statuses() -> None:
    tree = build_activity_tree(
        [
            _event(1, "planning_started", "Preparing the bounded plan."),
            _event(2, "tool_execution_started", "The approved tool was queued.", tool_id="nuclei"),
            _event(
                3,
                "tool_execution_completed",
                "The persisted tool receipt was accepted.",
                tool_id="nuclei",
            ),
            _event(4, "evaluation_started", "Correlating persisted evidence."),
            _event(5, "run_blocked", "The next governed step is blocked."),
        ],
        task_id="assessment-123",
        run_state="blocked",
        last_sequence=5,
    )

    assert tree["task_id"] == "assessment-123"
    assert tree["status"] == "blocked"
    assert tree["last_sequence"] == 5
    nodes = tree["nodes"]
    assert isinstance(nodes, list)
    assert [node["label"] for node in nodes] == [
        "Planning",
        "Tool execution",
        "Evidence correlation and candidate validation",
        "Completion and blockers",
    ]
    tool_stage = nodes[1]
    assert tool_stage["status"] == "completed"
    children = tool_stage["children"]
    assert [child["status"] for child in children] == ["running", "completed"]
    assert children[0]["tool_id"] == "nuclei"
    assert all("provider" not in child for node in nodes for child in node["children"])


def test_empty_tree_does_not_fabricate_planning_or_tool_steps() -> None:
    tree = build_activity_tree([], task_id="conversation-123", run_state="created")

    assert tree["status"] == "queued"
    assert tree["nodes"] == []


def test_persisted_repository_inspection_events_reload_into_the_activity_tree(tmp_path) -> None:
    service = AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity"))
    timestamp = datetime(2026, 8, 19, 10, 0, tzinfo=UTC)
    service.record_transition(
        run_id="assessment-persisted",
        timestamp=timestamp,
        event_type="repository_inspection_started",
        summary="Verifying the configured repository and scanner compatibility manifests.",
        run_state="checking_policy",
        source="policy",
        execution_state="not_started",
        metadata={"api_key": "must-not-be-exposed", "inspection": "compatibility_manifests"},
    )
    service.record_transition(
        run_id="assessment-persisted",
        timestamp=timestamp + timedelta(seconds=1),
        event_type="repository_inspection_completed",
        summary="The configured repository and scanner compatibility manifests were verified.",
        run_state="checking_policy",
        source="policy",
        execution_state="succeeded",
        metadata={"inspection": "compatibility_manifests"},
    )

    events = service.feed("assessment-persisted").events
    tree = build_activity_tree(
        [event_to_public_dict(event) for event in events],
        task_id="assessment-persisted",
        run_state="checking_policy",
        last_sequence=events[-1].sequence,
    )

    assert tree["nodes"][0]["label"] == "Repository and file inspection"
    assert tree["nodes"][0]["status"] == "completed"
    assert tree["nodes"][0]["total_count"] == 2
    assert all("api_key" not in str(node) for node in tree["nodes"])


def test_same_task_identity_survives_provider_failover_event_sequence() -> None:
    events = [
        _event(1, "planning_started", "Preparing one VulnHunter response."),
        _event(2, "planning_started", "Continuing the same response after a transport retry."),
        _event(3, "planning_started", "The response request is still provider-neutral."),
    ]
    tree = build_activity_tree(events, task_id="thread-task-123", run_state="running")

    assert tree["task_id"] == "thread-task-123"
    planning = tree["nodes"][0]
    assert planning["activity_id"] == "thread-task-123:stage:planning"
    assert [child["parent_activity_id"] for child in planning["children"]] == [
        "thread-task-123:stage:planning",
        "thread-task-123:stage:planning",
        "thread-task-123:stage:planning",
    ]
