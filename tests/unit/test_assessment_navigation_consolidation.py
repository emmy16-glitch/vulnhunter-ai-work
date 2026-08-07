from pathlib import Path

INSPECTOR = Path("vulnhunter/web/templates/web/_mobile_analysis_inspector.html")
ROUTE = Path("vulnhunter/web/static/web/conversation-mobile-inspector-route.js")


def _inspector() -> str:
    return INSPECTOR.read_text(encoding="utf-8")


def _route() -> str:
    return ROUTE.read_text(encoding="utf-8")


def test_mobile_workspace_has_one_four_destination_primary_navigation() -> None:
    template = _inspector()
    nav = template.split('<nav class="vh-mobile-workspace-nav"', 1)[1].split("</nav>", 1)[0]

    assert nav.count("data-mobile-nav-destination=") == 4
    assert 'data-mobile-nav-destination="chat"' in nav
    assert 'data-mobile-nav-destination="activity"' in nav
    assert 'data-mobile-nav-destination="findings"' in nav
    assert 'data-mobile-nav-destination="more"' in nav
    assert ">Chat</button>" in nav
    assert ">Activity</button>" in nav
    assert ">Findings</button>" in nav
    assert ">More</button>" in nav
    assert "Graph" not in nav
    assert "Assessment</button>" not in nav


def test_inspector_separates_summary_activity_findings_evidence_and_report() -> None:
    template = _inspector()
    tabs = template.split('<div class="vh-analysis-tabs"', 1)[1].split("</div>", 1)[0]

    assert 'data-inspector-tab="overview"' in tabs
    assert 'data-inspector-tab="activity"' in tabs
    assert 'data-inspector-tab="findings"' in tabs
    assert 'data-inspector-tab="artifacts"' in tabs
    assert 'data-inspector-tab="reports"' in tabs
    assert 'data-inspector-tab="graph"' not in tabs
    assert 'data-inspector-panel="activity"' in template
    assert 'data-inspector-events' in template.split('data-inspector-panel="activity"', 1)[1]


def test_graph_is_contextual_evidence_not_a_primary_destination() -> None:
    template = _inspector()
    evidence = template.split('data-inspector-panel="artifacts"', 1)[1].split("</section>", 2)
    evidence_text = "</section>".join(evidence)

    assert 'data-inspector-graph-section' in evidence_text
    assert "Evidence relationships" in evidence_text
    assert 'data-inspector-graph' in evidence_text
    assert 'data-inspector-tab="graph"' not in template
    assert 'data-mobile-nav-destination="graph"' not in template


def test_mobile_specialist_routes_remain_assessment_scoped_and_back_aware() -> None:
    route = _route()

    assert 'const routeKeys = ["assessment", "inspector"]' in route
    assert 'url.searchParams.set("assessment", assessmentId)' in route
    assert 'url.searchParams.set("inspector", tab)' in route
    assert 'data-mobile-specialist-tab' in route
    assert 'if (!allowedTabs.has(tab) || !selectedAssessmentId) return;' in route
    assert 'window.addEventListener("popstate"' in route
    assert 'activateNavigation(destinationForTab(current.tab))' in route


def test_mobile_route_maps_contextual_tabs_to_one_active_primary_destination() -> None:
    route = _route()

    assert 'if (tab === "activity") return "activity";' in route
    assert 'if (tab === "findings") return "findings";' in route
    assert 'return "more";' in route
    assert 'item.classList.toggle("is-active", selected)' in route
    assert 'item.setAttribute("aria-current", selected ? "page" : "false")' in route
