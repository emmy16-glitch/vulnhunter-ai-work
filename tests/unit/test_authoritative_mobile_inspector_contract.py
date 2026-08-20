from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
TEMPLATES = ROOT / "vulnhunter" / "web" / "templates" / "web"
SCRIPT = STATIC / "conversation-mobile-inspector.js"
OPEN_ADAPTER = STATIC / "conversation-inspector-open.js"
STORE = STATIC / "workspace-state.js"
BRIDGE = STATIC / "conversation-mobile-bridge.js"
TEMPLATE = TEMPLATES / "_mobile_analysis_inspector.html"
CONVERSATION = TEMPLATES / "conversation.html"


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


def test_historical_mobile_plan_messages_are_projection_anchors():
    bridge = _text(BRIDGE)
    assert ".vh-chat-message.is-mobile_plan" in bridge
    assert 'document.querySelectorAll("[data-mobile-hunt-card]")' in bridge
    assert "replaceSelectedAssessment(payload)" in bridge
    assert 'const persistedSummary = card?.querySelector(".vh-persisted-mobile-plan")' in bridge
    assert "taskCard.state || projection?.execution?.state" in bridge


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


def test_mobile_inspector_is_contextual_and_has_no_duplicate_bottom_navigation():
    template = _text(TEMPLATE)
    conversation = _text(CONVERSATION)

    assert template.count("data-analysis-inspector-controller") == 1
    assert template.count('data-mobile-workspace-view="analysis"') == 1
    assert "data-mobile-nav-destination" not in template
    assert "vh-mobile-workspace-nav" not in template
    assert "data-analysis-inspector-open" in conversation
    for tab in (
        "overview",
        "activity",
        "findings",
        "components",
        "endpoints",
        "artifacts",
        "source-hunt",
        "reports",
    ):
        assert f'data-inspector-tab="{tab}"' in template
    assert "data-inspector-components-table" in template
    assert "data-inspector-endpoints-table" in template
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


def test_contextual_open_control_delegates_to_the_authoritative_inspector_controller():
    adapter = _text(OPEN_ADAPTER)
    template = _text(TEMPLATE)
    conversation = _text(CONVERSATION)

    assert "data-analysis-inspector-controller" in template
    assert "data-analysis-inspector-open" in conversation
    assert 'querySelector("[data-analysis-inspector-controller]")' in adapter
    assert 'event.target.closest?.("[data-analysis-inspector-open]")' in adapter
    assert "controller.click()" in adapter
    assert "restoreFocus" in adapter
    assert "conversation-mobile-inspector-route.js" not in template
    assert "conversation-mobile-inspector-route.js" not in conversation


def test_inspector_tabs_have_keyboard_roving_focus():
    script = _text(SCRIPT)
    template = _text(TEMPLATE)
    for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
        assert key in script
    assert "tab.tabIndex = selected ? 0 : -1" in script
    assert template.count('tabindex="-1"') == 8


def test_assessment_empty_states_are_compact_ordinary_language_statuses():
    template = _text(TEMPLATE)
    for copy in (
        "Select an assessment to view its execution status.",
        "Select an assessment to view persisted findings.",
        "Select an assessment to view saved evidence.",
        "No meaningful evidence relationships are available for this assessment.",
        "Format readiness is unavailable until the server provides the selected assessment "
        "report contract.",
    ):
        assert copy in template
    assert template.count('role="status"') == 6
    assert template.count('aria-live="polite"') == 5
    assert "until a real worker observation has been persisted and judged" not in template
    assert "The graph is created only from real target" not in template


def test_assessment_inspector_uses_task_language_before_system_language():
    template = _text(TEMPLATE)
    assert 'data-contract-name="Assessment Inspector"' in template
    for copy in (
        "Assessment details",
        "Assessment ID",
        "Select an assessment to see its scope.",
        "Saved assessment progress",
        "Task stages",
        "Persisted assessment state",
        "Activity",
        "Persisted events",
        "Execution status",
        "Backend-owned state",
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
