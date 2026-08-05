from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
TEMPLATES = ROOT / "vulnhunter" / "web" / "templates" / "web"
SCRIPT = STATIC / "conversation-mobile-inspector.js"
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


def test_mobile_inspector_has_one_consolidated_entry_and_internal_specialist_tabs():
    template = _text(TEMPLATE)
    assert template.count('data-mobile-workspace-view="chat"') == 1
    assert template.count('data-mobile-workspace-view="analysis"') == 1
    assert 'data-mobile-workspace-view="findings"' not in template
    assert 'data-mobile-workspace-view="graph"' not in template
    for tab in ("overview", "findings", "artifacts", "graph"):
        assert f'data-inspector-tab="{tab}"' in template


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


def test_inspector_tabs_have_keyboard_roving_focus():
    script = _text(SCRIPT)
    template = _text(TEMPLATE)
    for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
        assert key in script
    assert "tab.tabIndex = selected ? 0 : -1" in script
    assert template.count('tabindex="-1"') == 3


def test_assessment_empty_states_are_compact_ordinary_language_statuses():
    template = _text(TEMPLATE)
    for copy in (
        "Select an assessment to view its analysis status.",
        "Select an assessment to view reviewed findings.",
        "Select an assessment to view saved evidence.",
        "Select an assessment to view evidence links.",
    ):
        assert copy in template
    assert template.count('role="status"') == 4
    assert template.count('aria-live="polite"') == 3
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
