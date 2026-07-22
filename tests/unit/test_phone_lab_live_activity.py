from types import SimpleNamespace

from vulnhunter.web.stream_views import _active_summary


def test_active_summary_explains_queued_and_evaluating_states_without_private_reasoning():
    queued = SimpleNamespace(
        workflow_state="queued",
        current_state="running",
        execution_blocking_reason=None,
    )
    evaluating = SimpleNamespace(
        workflow_state="evaluating",
        current_state="running",
        execution_blocking_reason=None,
    )

    assert "queued" in _active_summary(queued).lower()
    assert "verified" in _active_summary(evaluating).lower()
