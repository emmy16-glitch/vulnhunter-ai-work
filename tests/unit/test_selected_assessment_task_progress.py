import pytest

from vulnhunter.web.selected_assessment_projection import (
    assert_selected_assessment_invariants,
)


def _projection(progress: dict[str, object]) -> dict[str, object]:
    assessment_id = "assessment-progress"
    return {
        "assessment_id": assessment_id,
        "assessment_kind": "apk",
        "graph_id": "graph-progress",
        "selected": True,
        "projection_revision": 4,
        "surface_identity": {
            surface: assessment_id
            for surface in (
                "activity",
                "chat",
                "evidence",
                "findings",
                "graph",
                "history",
                "inspector",
                "reports",
            )
        },
        "result_identity": {
            surface: assessment_id for surface in ("evidence", "findings", "graph", "reports")
        },
        "task_card": {
            "assessment_id": assessment_id,
            "activity_timeline_id": "activity-progress",
            "state": "running",
            "terminal": False,
            "progress": progress,
        },
        "execution": {"state": "running"},
        "health": {
            "assessment": "in_progress",
            "provider": "not_evaluated",
            "worker": "active",
        },
    }


@pytest.mark.parametrize(
    "progress",
    [
        {"measurement": "none"},
        {"measurement": "bytes", "completed": 512, "total": 1024},
        {
            "measurement": "stage",
            "completed": 2,
            "total": 5,
            "stage": "static-analysis",
        },
    ],
)
def test_canonical_measured_progress_is_accepted(progress: dict[str, object]):
    assert_selected_assessment_invariants(_projection(progress))


def test_task_card_requires_one_persisted_activity_timeline():
    projection = _projection({"measurement": "none"})
    projection["task_card"].pop("activity_timeline_id")
    with pytest.raises(ValueError, match="durable activity timeline"):
        assert_selected_assessment_invariants(projection)


@pytest.mark.parametrize("field", ["percent", "percentage"])
def test_fabricated_percentage_progress_is_rejected(field: str):
    progress = {"measurement": "bytes", "completed": 1, "total": 2, field: 50}
    with pytest.raises(ValueError, match="fabricated percentage"):
        assert_selected_assessment_invariants(_projection(progress))


@pytest.mark.parametrize(
    "progress",
    [
        {"measurement": "bytes", "completed": -1, "total": 10},
        {"measurement": "bytes", "completed": 11, "total": 10},
        {"measurement": "bytes", "completed": 0, "total": 0},
        {"measurement": "bytes", "completed": True, "total": 10},
        {"measurement": "stage", "completed": 1, "total": 2},
        {
            "measurement": "stage",
            "completed": 1,
            "total": 2,
            "stage": "",
        },
    ],
)
def test_invalid_or_unmeasured_claims_are_rejected(progress: dict[str, object]):
    with pytest.raises(ValueError):
        assert_selected_assessment_invariants(_projection(progress))


def test_unmeasured_progress_cannot_claim_completion():
    progress = {"measurement": "none", "completed": 0, "total": 1}
    with pytest.raises(ValueError, match="cannot claim"):
        assert_selected_assessment_invariants(_projection(progress))


def test_progress_rejects_noncanonical_extra_fields():
    progress = {
        "measurement": "stage",
        "completed": 1,
        "total": 3,
        "stage": "queued",
        "estimated_seconds": 30,
    }
    with pytest.raises(ValueError, match="canonical measured fields"):
        assert_selected_assessment_invariants(_projection(progress))
