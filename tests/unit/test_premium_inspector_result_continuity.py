from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter/web/static/web"
TEMPLATES = ROOT / "vulnhunter/web/templates/web"
CONTINUITY = STATIC / "conversation-inspector-continuity.js"
INSPECTOR = STATIC / "conversation-mobile-inspector.js"
INSPECTOR_TEMPLATE = TEMPLATES / "_mobile_analysis_inspector.html"
CONVERSATION = TEMPLATES / "conversation.html"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dynamic_workspace_inspector_openers_are_wired_to_the_existing_inspector() -> None:
    javascript = _text(CONTINUITY)
    conversation = _text(CONVERSATION)

    assert "[data-analysis-inspector-open]" in conversation
    assert 'event.target.closest("[data-analysis-inspector-open]")' in javascript
    assert 'workspace.querySelector(\'[data-mobile-workspace-view="analysis"]\')' in javascript
    assert "analysisButton.click()" in javascript
    assert "if (!selectedAssessmentId()) return false" in javascript


def test_contextual_opening_selects_only_existing_specialist_tabs() -> None:
    javascript = _text(CONTINUITY)

    for mapping in (
        'finding: "findings"',
        'evidence: "artifacts"',
        'report: "reports"',
        'activity: "activity"',
    ):
        assert mapping in javascript
    assert 'document.addEventListener("vh:open-assessment-inspector"' in javascript
    assert "const resolveTab" in javascript
    assert 'return tabs.has(canonical) ? canonical : "overview"' in javascript
    assert "window.queueMicrotask(() => tabs.get(target)?.click())" in javascript


def test_inspector_open_close_preserves_conversation_reading_position_and_focus() -> None:
    javascript = _text(CONTINUITY)

    assert "feedScrollTop: null" in javascript
    assert "readingState.feedScrollTop = feed.scrollTop" in javascript
    assert "readingState.returnFocus" in javascript
    assert "feed.scrollTop = scrollTop" in javascript
    assert "returnFocus.focus({ preventScroll: true })" in javascript
    assert "const hiddenObserver = new MutationObserver" in javascript
    assert 'attributeFilter: ["hidden"]' in javascript
    assert "if (inspector.hidden) restoreReadingPosition()" in javascript


def test_continuity_layer_reads_selected_assessment_without_becoming_a_state_owner() -> None:
    javascript = _text(CONTINUITY)

    assert "window.vhSelectedAssessmentStore?.getSnapshot?.()" in javascript
    assert "assessment_projection?.assessment_id" in javascript
    for forbidden in (
        "window.vhSelectedAssessmentStore =",
        "assessmentState =",
        "workerState =",
        "providerState =",
        "progressPercent =",
    ):
        assert forbidden not in javascript


def test_inspector_continuity_loads_after_route_and_existing_inspector_ownership() -> None:
    template = _text(INSPECTOR_TEMPLATE)
    inspector = _text(INSPECTOR)

    assert template.count("conversation-mobile-inspector-route.js") == 1
    assert template.count("conversation-inspector-continuity.js") == 1
    assert template.index("conversation-mobile-inspector-route.js") < template.index(
        "conversation-inspector-continuity.js"
    )
    assert "const showInspector" in inspector
    assert "const hideInspector" in inspector
    assert "const setTab" in inspector
