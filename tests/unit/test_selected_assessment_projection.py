from copy import deepcopy

import pytest

from vulnhunter.web.selected_assessment_projection import (
    assert_selected_assessment_invariants,
    canonical_execution_state,
    replace_selected_assessment,
    selected_assessment_projection,
)


def _projection(
    *,
    assessment_id: str = "assessment-1",
    kind: str = "apk",
    revision: int = 1,
    state: str = "running",
) -> dict[str, object]:
    surfaces = {
        name: assessment_id
        for name in (
            "chat",
            "activity",
            "inspector",
            "history",
            "findings",
            "evidence",
            "graph",
            "reports",
        )
    }
    result_identity = {
        name: assessment_id
        for name in (
            "findings",
            "evidence",
            "graph",
            "reports",
        )
    }
    terminal = state in {"blocked", "failed", "gated", "rejected", "completed", "cancelled"}
    assessment_health = "in_progress"
    if state == "completed":
        assessment_health = "completed"
    elif state == "cancelled":
        assessment_health = "cancelled"
    elif state in {"blocked", "failed", "gated", "rejected"}:
        assessment_health = "attention_required"
    return {
        "assessment_id": assessment_id,
        "assessment_kind": kind,
        "graph_id": f"graph-{assessment_id}",
        "selected": True,
        "projection_revision": revision,
        "surface_identity": surfaces,
        "result_identity": result_identity,
        "task_card": {
            "assessment_id": assessment_id,
            "activity_timeline_id": f"activity-{assessment_id}",
            "state": state,
            "terminal": terminal,
            "progress": {
                "measurement": "stage",
                "completed": 4 if terminal else 2,
                "total": 4,
                "stage": state,
            },
        },
        "execution": {"state": state},
        "health": {
            "assessment": assessment_health,
            "worker": "active" if not terminal else "available",
            "provider": "not_evaluated",
        },
    }


@pytest.mark.parametrize("kind", ["apk", "website", "source_hunt"])
def test_selected_projection_accepts_every_supported_workflow(kind: str):
    projection = selected_assessment_projection(_projection(kind=kind))
    assert projection is not None
    assert projection["assessment_kind"] == kind
    assert projection["projection_contract"] == "selected-assessment/v1"


@pytest.mark.parametrize(
    ("workflow_state", "canonical"),
    [
        ("created", "prepared"),
        ("pending", "prepared"),
        ("executing", "running"),
        ("evaluating", "running"),
        ("execution_blocked", "blocked"),
        ("readiness_blocked", "blocked"),
        ("unavailable", "blocked"),
        ("timed_out", "failed"),
        ("denied", "rejected"),
    ],
)
def test_workflow_state_aliases_converge_before_browser_projection(
    workflow_state: str,
    canonical: str,
):
    assert canonical_execution_state(workflow_state) == canonical


def test_unknown_workflow_state_fails_closed():
    with pytest.raises(ValueError, match="supported execution state"):
        canonical_execution_state("almost-finished")


def test_selected_projection_returns_a_defensive_snapshot():
    original = _projection()
    projected = selected_assessment_projection(original)
    assert projected is not None
    projected["execution"]["state"] = "completed"
    assert original["execution"] == {"state": "running"}


def test_replacement_never_merges_two_assessments():
    current = _projection(assessment_id="old-assessment", revision=8)
    incoming = _projection(assessment_id="new-assessment", kind="website", revision=1)
    replacement = replace_selected_assessment(current, incoming)
    assert replacement is not None
    assert replacement["assessment_id"] == "new-assessment"
    assert replacement["assessment_kind"] == "website"
    assert "old-assessment" not in repr(replacement)


def test_newer_same_assessment_projection_replaces_current_state():
    current = _projection(revision=3, state="running")
    incoming = _projection(revision=4, state="completed")
    replacement = replace_selected_assessment(current, incoming)
    assert replacement is not None
    assert replacement["projection_revision"] == 4
    assert replacement["execution"] == {"state": "completed"}


def test_delayed_same_assessment_projection_cannot_roll_back_state():
    current = _projection(revision=4, state="completed")
    delayed = _projection(revision=3, state="running")
    replacement = replace_selected_assessment(current, delayed)
    assert replacement is not None
    assert replacement["projection_revision"] == 4
    assert replacement["execution"] == {"state": "completed"}


def test_idempotent_same_revision_replay_preserves_current_snapshot():
    current = _projection(revision=4, state="completed")
    replay = deepcopy(current)
    replacement = replace_selected_assessment(current, replay)
    assert replacement is not None
    assert replacement == selected_assessment_projection(current)
    assert replacement is not current


def test_conflicting_same_revision_is_rejected():
    current = _projection(revision=4, state="running")
    conflicting = _projection(revision=4, state="completed")
    with pytest.raises(ValueError, match="same selected-assessment revision"):
        replace_selected_assessment(current, conflicting)


def test_missing_server_projection_clears_local_selection():
    assert replace_selected_assessment(_projection(), None) is None


def test_cross_surface_identity_is_rejected():
    projection = _projection()
    projection["surface_identity"]["reports"] = "another-assessment"
    with pytest.raises(ValueError, match="Every browser surface"):
        assert_selected_assessment_invariants(projection)


@pytest.mark.parametrize("surface", ["findings", "evidence", "graph", "reports"])
def test_cross_assessment_result_identity_is_rejected(surface: str):
    projection = _projection()
    projection["result_identity"][surface] = "another-assessment"
    with pytest.raises(ValueError, match="Every result projection"):
        assert_selected_assessment_invariants(projection)


def test_missing_result_identity_is_rejected():
    projection = _projection()
    projection.pop("result_identity")
    with pytest.raises(ValueError, match="Every result projection"):
        assert_selected_assessment_invariants(projection)


def test_task_card_identity_is_rejected():
    projection = _projection()
    projection["task_card"]["assessment_id"] = "another-assessment"
    with pytest.raises(ValueError, match="persisted task card"):
        assert_selected_assessment_invariants(projection)


def test_task_card_state_must_match_execution_state():
    projection = _projection(state="running")
    projection["task_card"]["state"] = "completed"
    with pytest.raises(ValueError, match="task card must agree"):
        assert_selected_assessment_invariants(projection)


def test_task_card_terminal_flag_must_match_execution_state():
    projection = _projection(state="completed")
    projection["task_card"]["terminal"] = False
    with pytest.raises(ValueError, match="terminal flag"):
        assert_selected_assessment_invariants(projection)


def test_assessment_health_must_match_execution_state():
    projection = _projection(state="failed")
    projection["health"]["assessment"] = "completed"
    with pytest.raises(ValueError, match="Assessment health"):
        assert_selected_assessment_invariants(projection)


def test_health_dimensions_cannot_collapse_into_one_generic_state():
    projection = _projection()
    projection["health"] = {"assessment": "failed"}
    with pytest.raises(ValueError, match="must remain separate"):
        assert_selected_assessment_invariants(projection)


@pytest.mark.parametrize("state", [None, "", "unknown", "finished"])
def test_execution_state_must_be_supported(state: object):
    projection = _projection()
    projection["execution"]["state"] = state
    projection["task_card"]["state"] = state
    with pytest.raises(ValueError, match="supported execution state"):
        assert_selected_assessment_invariants(projection)


@pytest.mark.parametrize("revision", [None, -1, True, "4"])
def test_projection_revision_must_be_a_non_negative_integer(revision: object):
    projection = _projection()
    projection["projection_revision"] = revision
    with pytest.raises(ValueError, match="non-negative projection revision"):
        assert_selected_assessment_invariants(projection)


def test_unknown_workflow_is_rejected():
    projection = deepcopy(_projection())
    projection["assessment_kind"] = "generic"
    with pytest.raises(ValueError, match="unsupported assessment kind"):
        selected_assessment_projection(projection)
