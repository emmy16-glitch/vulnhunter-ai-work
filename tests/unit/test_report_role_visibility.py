from __future__ import annotations

from types import SimpleNamespace

from vulnhunter.web import report_views


def _record(plan_id: str, *assigned_ids: str):
    first = assigned_ids[0] if assigned_ids else "unassigned-owner"
    second = assigned_ids[1] if len(assigned_ids) > 1 else "second-reviewer"
    plan = SimpleNamespace(
        plan_id=plan_id,
        accountable_owner_id=first,
        assignments=SimpleNamespace(
            operator_ids=(first,),
            primary_reviewer_ids=(first, second),
            adjudicator_id="adjudicator-a",
            dataset_quality_auditor_id="auditor-a",
            test_verifier_id="verifier-a",
            release_authority_id="release-a",
            emergency_stop_owner_id="stop-a",
        ),
    )
    return SimpleNamespace(plan=plan, plan_id=plan_id)


def _actor(role: str, identity_id: str):
    return SimpleNamespace(
        product_roles=(role,),
        governance_identity=SimpleNamespace(reviewer_id=identity_id),
    )


def test_reviewer_report_visibility_is_assignment_scoped(monkeypatch) -> None:
    assigned = _record("assigned-plan", "reviewer-a")
    unrelated = _record("unrelated-plan", "reviewer-b")
    monkeypatch.setattr(report_views, "list_pilot_plan_records", lambda: (assigned, unrelated))

    visible = report_views._visible_records(_actor("reviewer", "reviewer-a"))

    assert visible == (assigned,)


def test_full_report_role_sees_all_records(monkeypatch) -> None:
    records = (_record("plan-one", "reviewer-a"), _record("plan-two", "reviewer-b"))
    monkeypatch.setattr(report_views, "list_pilot_plan_records", lambda: records)

    visible = report_views._visible_records(_actor("security-auditor", "auditor-a"))

    assert visible == records


def test_public_summary_role_does_not_receive_unreleased_pilot_reports(monkeypatch) -> None:
    monkeypatch.setattr(
        report_views,
        "list_pilot_plan_records",
        lambda: (_record("private-plan", "reviewer-a"),),
    )

    visible = report_views._visible_records(_actor("read-only-observer", "observer-a"))

    assert visible == ()
