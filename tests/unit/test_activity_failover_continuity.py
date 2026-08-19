from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.agent_activity.hierarchy import build_activity_tree
from vulnhunter.agent_activity.read_models import event_to_public_dict
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.web import ai_failover, conversation_service


def _router_call() -> tuple[str | None, str, str]:
    return conversation_service._remote_advisory(
        "Prepare a safe summary for this assessment.",
        available_profiles=("passive",),
        conversation_context=(),
        memory_summary="",
        tool_context="",
        reasoning_effort="high",
        provider_preference="groq",
    )


def test_groq_gemini_ollama_switch_keeps_one_activity_identity_and_cursor(monkeypatch, tmp_path):
    ai_failover.install()
    calls = {"groq": 0, "gemini": 0, "ollama": 0}

    def groq(*_args, **_kwargs):
        calls["groq"] += 1
        if calls["groq"] == 1:
            return '{"message":"first response","recommended_profile":null,"model":"hidden"}', "ok"
        return None, "Groq unavailable"

    def gemini(*_args, **_kwargs):
        calls["gemini"] += 1
        if calls["gemini"] == 1:
            return (
                '{"message":"fallback response","recommended_profile":null,"model":"hidden"}',
                "ok",
            )
        return None, "Gemini unavailable"

    def ollama(*_args, **_kwargs):
        calls["ollama"] += 1
        return (
            '{"message":"local fallback response","recommended_profile":null,"model":"hidden"}',
            "ok",
        )

    monkeypatch.setattr(conversation_service, "_groq_advisory", groq)
    monkeypatch.setattr(ai_failover, "_gemini_advisory", gemini)
    monkeypatch.setattr(ai_failover, "_ollama_advisory", ollama)

    activity = AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity"))
    task_id = "conversation-task-failover-1"
    started = datetime(2026, 8, 19, 10, 0, tzinfo=UTC)
    trees = []
    sequences = []
    for offset, expected_message in enumerate(
        ("first response", "fallback response", "local fallback response")
    ):
        advisory, detail, provider = _router_call()
        assert expected_message in str(advisory)
        assert detail == "AI reasoning completed."
        assert provider == "auto"

        activity.record_transition(
            run_id=task_id,
            timestamp=started + timedelta(seconds=offset),
            event_type="planning_started",
            summary="Preparing a provider-neutral VulnHunter response.",
            run_state="planning",
            source="planner",
            execution_state="not_started",
            metadata={"task_id": task_id},
        )
        events = activity.feed(task_id).events
        public_events = [event_to_public_dict(event) for event in events]
        tree = build_activity_tree(
            public_events,
            task_id=task_id,
            run_state="running",
            last_sequence=events[-1].sequence,
        )
        trees.append(tree)
        sequences.append(events[-1].sequence)

    assert calls == {"groq": 3, "gemini": 2, "ollama": 1}
    assert sequences == [1, 2, 3]
    assert {tree["task_id"] for tree in trees} == {task_id}
    assert [tree["last_sequence"] for tree in trees] == sequences
    assert all(tree["nodes"][0]["label"] == "Planning" for tree in trees)
    assert all("groq" not in str(tree).casefold() for tree in trees)
    assert all("gemini" not in str(tree).casefold() for tree in trees)
    assert all("ollama" not in str(tree).casefold() for tree in trees)


def test_all_provider_failures_leave_task_cursor_and_tree_unchanged(monkeypatch, tmp_path):
    ai_failover.install()
    monkeypatch.setattr(
        conversation_service,
        "_groq_advisory",
        lambda *_args, **_kwargs: (None, "Groq unavailable"),
    )
    monkeypatch.setattr(
        ai_failover,
        "_gemini_advisory",
        lambda *_args, **_kwargs: (None, "Gemini unavailable"),
    )
    monkeypatch.setattr(
        ai_failover,
        "_ollama_advisory",
        lambda *_args, **_kwargs: (None, "Ollama unavailable"),
    )

    activity = AgentActivityService(AppendOnlyActivityStore(tmp_path / "activity"))
    task_id = "conversation-task-failover-blocked"
    timestamp = datetime(2026, 8, 19, 10, 0, tzinfo=UTC)
    activity.record_transition(
        run_id=task_id,
        timestamp=timestamp,
        event_type="planning_started",
        summary="Preparing a provider-neutral VulnHunter response.",
        run_state="planning",
        source="planner",
        execution_state="not_started",
        metadata={"task_id": task_id},
    )
    before_events = activity.feed(task_id).events
    before_tree = build_activity_tree(
        [event_to_public_dict(event) for event in before_events],
        task_id=task_id,
        run_state="running",
        last_sequence=before_events[-1].sequence,
    )

    advisory, detail, provider = _router_call()

    assert advisory is None
    assert detail == "AI reasoning is temporarily unavailable."
    assert provider == "auto"
    after_events = activity.feed(task_id).events
    after_tree = build_activity_tree(
        [event_to_public_dict(event) for event in after_events],
        task_id=task_id,
        run_state="running",
        last_sequence=after_events[-1].sequence,
    )
    assert [event.sequence for event in after_events] == [1]
    assert after_tree == before_tree
