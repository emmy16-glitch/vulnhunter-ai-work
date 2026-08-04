from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
TEMPLATES = ROOT / "vulnhunter" / "web" / "templates" / "web"
SCRIPT = STATIC / "conversation-mobile-inspector.js"
TEMPLATE = TEMPLATES / "_mobile_analysis_inspector.html"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_inspector_requires_the_authoritative_selected_assessment():
    script = _text(SCRIPT)
    assert "state.projection" in script
    assert "state.taskCard" in script
    assert "taskCard?.assessment_id === selectedAssessmentId()" in script
    assert 'document.addEventListener("vh:mobile-projection"' in script
    assert "if (!hasAuthoritativeAssessment())" in script


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
        "No worker is assigned yet.",
        "No reviewed findings yet.",
        "No evidence receipts yet.",
        "No evidence relationships yet.",
    ):
        assert copy in template
    assert template.count('role="status"') == 4
    assert template.count('aria-live="polite"') == 3
    assert "until a real worker observation has been persisted and judged" not in template
    assert "The graph is created only from real target" not in template
