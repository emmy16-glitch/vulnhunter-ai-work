from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
TEMPLATES = ROOT / "vulnhunter" / "web" / "templates" / "web"
SCRIPT = STATIC / "conversation-mobile-inspector.js"
ROUTE = STATIC / "conversation-mobile-inspector-route.js"
STORE = STATIC / "workspace-state.js"
TEMPLATE = TEMPLATES / "_mobile_analysis_inspector.html"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_inspector_requires_the_authoritative_selected_assessment():
    script = _text(SCRIPT)
    assert "state.projection" in script
    assert "state.taskCard" in script
    assert "taskCard?.assessment_id === selectedAssessmentId()" in script
    assert "window.vhSelectedAssessmentStore" in script
    assert 'document.addEventListener("vh:selected-assessment-store-ready"' in script
    assert 'document.addEventListener("vh:mobile-projection"' not in script
    assert 'document.addEventListener("vh:mobile-reset"' not in script
    assert "if (!hasAuthoritativeAssessment())" in script


def test_selected_assessment_store_announces_readiness_after_interface_is_defined():
    store = _text(STORE)
    interface = store.index('Object.defineProperty(window, "vhSelectedAssessmentStore"')
    ready = store.index('new CustomEvent("vh:selected-assessment-store-ready"')
    assert interface < ready
    assert "detail: store" in store
    assert '"vh:mobile-projection"' not in store
    assert '"vh:mobile-reset"' not in store


def test_inspector_replaces_and_clears_complete_selected_assessment_snapshots():
    script = _text(SCRIPT)
    for token in (
        "state.projection = snapshot?.assessment_projection || null",
        "state.taskCard = snapshot?.task_card || null",
        "state.plan = snapshot?.mobile_plan || null",
        "state.execution = snapshot?.mobile_execution || state.plan?.execution || null",
        "state.attachment = state.plan?.artifact || null",
        "applySelectedAssessment(store.getSnapshot())",
        "state.unsubscribeSelectedAssessment = store.subscribe(applySelectedAssessment)",
    ):
        assert token in script
    assert "if (!snapshot)" in script
    assert "hideInspector({ restoreFocus: false })" in script


def test_inspector_never_invents_prepared_progress():
    script = _text(SCRIPT)
    assert "state.plan\n          ? 8" not in script
    assert "state.plan ? 8" not in script
    assert 'progressValue.textContent = measured ? `${completed} of ${total}` : "—"' in script
    assert "persisted stages complete" in script
    assert '"Progress unavailable"' in script


def test_mobile_inspector_has_four_primary_destinations_and_contextual_specialist_tabs():
    template = _text(TEMPLATE)
    assert template.count('data-mobile-workspace-view="chat"') == 1
    assert template.count('data-mobile-workspace-view="analysis"') == 1
    assert template.count("data-mobile-nav-destination=") == 4
    for destination in ("chat", "activity", "findings", "more"):
        assert f'data-mobile-nav-destination="{destination}"' in template
    for tab in ("overview", "activity", "findings", "artifacts", "reports"):
        assert f'data-inspector-tab="{tab}"' in template
    assert 'data-inspector-tab="graph"' not in template
    assert "Evidence relationships" in template


def test_mobile_sheet_supports_focus_escape_and_android_back_semantics():
    script = _text(SCRIPT)
    for token in (
        'window.history.pushState({ vhAssessmentSheet: true }, "")',
        'window.addEventListener("popstate"',
        'event.key === "Escape"',
        'event.key !== "Tab"',
        "state.returnFocus",
        "close?.focus()",
        'inspector.setAttribute("aria-modal", "true")',
        'inspector.removeAttribute("aria-modal")',
    ):
        assert token in script


def test_mobile_inspector_route_is_assessment_scoped_and_restorable():
    route = _text(ROUTE)
    template = _text(TEMPLATE)
    assert "conversation-mobile-inspector-route.js" in template
    for token in (
        'url.searchParams.set("assessment", assessmentId)',
        'url.searchParams.set("inspector", tab)',
        "current.assessmentId !== selectedAssessmentId",
        "!allowedTabs.has(current.tab)",
        "analysisButton?.click()",
        'window.addEventListener("popstate"',
        'window.addEventListener("resize"',
        "store.subscribe(applySelectedAssessment)",
        "applySelectedAssessment(store.getSnapshot())",
    ):
        assert token in route
    assert 'url.searchParams.set("assessment", current.assessmentId)' not in route
    assert "writeRoute();" in route


def test_inspector_tabs_have_keyboard_roving_focus():
    script = _text(SCRIPT)
    template = _text(TEMPLATE)
    for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
        assert key in script
    assert "tab.tabIndex = selected ? 0 : -1" in script
    assert template.count('tabindex="-1"') == 4


def test_assessment_empty_states_are_compact_ordinary_language_statuses():
    template = _text(TEMPLATE)
    for copy in (
        "Select an assessment to view its analysis status.",
        "Select an assessment to view reviewed findings.",
        "Select an assessment to view saved evidence.",
        "No meaningful evidence relationships are available for this assessment.",
        "The report appears here only when this selected assessment has a persisted "
        "evidence-backed report receipt.",
    ):
        assert copy in template
    assert template.count('role="status"') == 5
    assert template.count('aria-live="polite"') == 4
    assert "until a real worker observation has been persisted and judged" not in template
    assert "The graph is created only from real target" not in template


def test_assessment_inspector_uses_task_language_before_system_language():
    template = _text(TEMPLATE)
    assert 'data-contract-name="Assessment Inspector"' in template
    for copy in (
        "Assessment details",
        "Assessment ID",
        "Select an assessment to see its scope.",
        "Analysis progress",
        "Saved analysis state",
        "Activity",
        "Saved events",
        "Analysis status",
        "Saved execution state",
    ):
        assert copy in template
    for implementation_copy in (
        ">Assessment Inspector<",
        "Persisted worker state only",
        "Signed or persisted receipts",
        "Separate from assessment and provider health",
        "No evidence receipts yet.",
        "No evidence relationships yet.",
    ):
        assert implementation_copy not in template
