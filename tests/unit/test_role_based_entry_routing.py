from vulnhunter.web.dashboard_dispatch_views import entry_route_for_roles


def test_adjudicator_enters_the_adjudication_queue_before_review_work():
    assert entry_route_for_roles(("reviewer", "adjudicator")) == "web-adjudication-queue"


def test_reviewer_enters_the_assigned_review_queue():
    assert entry_route_for_roles(("reviewer",)) == "web-review-queue"


def test_campaign_roles_enter_governed_campaign_work():
    assert entry_route_for_roles(("campaign-operator",)) == "web-campaign-list"
    assert entry_route_for_roles(("campaign-approver",)) == "web-campaign-list"


def test_specialist_and_observer_entries_are_task_specific():
    assert entry_route_for_roles(("model-analyst",)) == "web-model-list"
    assert entry_route_for_roles(("read-only-observer",)) == "web-status"


def test_auditor_and_unknown_roles_keep_the_operational_dashboard_fallback():
    assert entry_route_for_roles(("security-auditor",)) is None
    assert entry_route_for_roles(()) is None
    assert entry_route_for_roles(("unknown-role",)) is None
