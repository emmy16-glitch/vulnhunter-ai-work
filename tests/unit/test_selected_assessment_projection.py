from copy import deepcopy

import pytest

from vulnhunter.web.selected_assessment_projection import (
    assert_selected_assessment_invariants,
    replace_selected_assessment,
    selected_assessment_projection,
)


def _projection(*, assessment_id: str = "assessment-1", kind: str = "apk") -> dict[str, object]:
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
    return {
        "assessment_id": assessment_id,
        "assessment_kind": kind,
        "graph_id": f"graph-{assessment_id}",
        "selected": True,
        "surface_identity": surfaces,
        "task_card": {"assessment_id": assessment_id},
        "execution": {"state": "running"},
        "health": {
            "assessment": "in_progress",
            "worker": "active",
            "provider": "not_evaluated",
        },
    }


@pytest.mark.parametrize("kind", ["apk", "website", "source_hunt"])
def test_selected_projection_accepts_every_supported_workflow(kind: str):
    projection = selected_assessment_projection(_projection(kind=kind))
    assert projection is not None
    assert projection["assessment_kind"] == kind
    assert projection["projection_contract"] == "selected-assessment/v1"


def test_selected_projection_returns_a_defensive_snapshot():
    original = _projection()
    projected = selected_assessment_projection(original)
    assert projected is not None
    projected["execution"]["state"] = "completed"
    assert original["execution"] == {"state": "running"}


def test_replacement_never_merges_two_assessments():
    current = _projection(assessment_id="old-assessment")
    incoming = _projection(assessment_id="new-assessment", kind="website")
    replacement = replace_selected_assessment(current, incoming)
    assert replacement is not None
    assert replacement["assessment_id"] == "new-assessment"
    assert replacement["assessment_kind"] == "website"
    assert "old-assessment" not in repr(replacement)


def test_missing_server_projection_clears_local_selection():
    assert replace_selected_assessment(_projection(), None) is None


def test_cross_surface_identity_fails_closed():
    projection = _projection()
    projection["surface_identity"]["reports"] = "another-assessment"
    with pytest.raises(ValueError, match="Every browser surface"):
        assert_selected_assessment_invariants(projection)


def test_task_card_identity_fails_closed():
    projection = _projection()
    projection["task_card"] = {"assessment_id": "another-assessment"}
    with pytest.raises(ValueError, match="persisted task card"):
        assert_selected_assessment_invariants(projection)


def test_health_dimensions_cannot_collapse_into_one_generic_state():
    projection = _projection()
    projection["health"] = {"assessment": "failed"}
    with pytest.raises(ValueError, match="must remain separate"):
        assert_selected_assessment_invariants(projection)


def test_unknown_workflow_fails_closed():
    projection = deepcopy(_projection())
    projection["assessment_kind"] = "generic"
    with pytest.raises(ValueError, match="unsupported assessment kind"):
        selected_assessment_projection(projection)
