from __future__ import annotations

from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "vulnhunter"
    / "web"
    / "static"
    / "web"
    / "conversation-mobile-inspector-route.js"
)


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_mobile_inspector_open_and_tab_changes_create_back_history() -> None:
    script = _script()
    for token in (
        'const routeStateKey = "vhMobileInspector";',
        'const method = mode === "push" ? "pushState" : "replaceState";',
        'writeRoute(next, { mode: "push" });',
        "window.history.back();",
        'window.addEventListener("popstate"',
    ):
        assert token in script


def test_mobile_inspector_history_is_assessment_scoped_and_idempotent() -> None:
    script = _script()
    for token in (
        "url.href === window.location.href",
        "current.assessmentId === next.assessmentId",
        "current.tab === next.tab",
        "current.assessmentId !== selectedAssessmentId",
        "!allowedTabs.has(current.tab)",
    ):
        assert token in script


def test_mobile_inspector_invalid_or_cleared_routes_restore_chat() -> None:
    script = _script()
    for token in (
        "showChatWithoutPublishing();",
        "if (!current.assessmentId && !current.tab)",
        "if (!selectedAssessmentId && (current.assessmentId || current.tab))",
        "if (!isMobile())",
    ):
        assert token in script
    assert "restoringRoute = true;\n    chatButton?.click();\n    restoringRoute = false;" in script
