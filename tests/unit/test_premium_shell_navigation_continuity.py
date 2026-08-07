from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTERACTION = ROOT / "vulnhunter" / "web" / "static" / "web" / "premium-interaction.js"
CSS = ROOT / "vulnhunter" / "web" / "static" / "web" / "premium-interaction.css"
BASE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "base.html"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_shell_navigation_acknowledges_without_intercepting_or_mutating_history() -> None:
    javascript = _text(INTERACTION)

    assert 'document.addEventListener("click"' in javascript
    assert "acknowledgeShellNavigation(link" in javascript
    assert (
        "event.preventDefault()"
        not in javascript.split('document.addEventListener("click"', maxsplit=1)[1].split(
            'window.addEventListener("pageshow"', maxsplit=1
        )[0]
    )
    assert (
        "window.history.pushState"
        not in javascript.split("const currentLocationKey", maxsplit=1)[1]
    )
    assert 'link.setAttribute("data-shell-navigation-pending", "true")' in javascript
    assert 'link.setAttribute("aria-busy", "true")' in javascript


def test_shell_navigation_keeps_server_owned_active_route_truth() -> None:
    javascript = _text(INTERACTION)

    shell = javascript.split("const currentLocationKey", maxsplit=1)[1]
    assert "aria-current" not in shell
    assert 'classList.add("is-active")' not in shell
    assert "history.pushState" not in shell
    assert "history.replaceState" not in shell


def test_successful_keyboard_navigation_restores_focus_to_main_content() -> None:
    javascript = _text(INTERACTION)
    base = _text(BASE)

    assert 'const shellNavigationStorageKey = "vh:shell-navigation"' in javascript
    assert 'window.addEventListener("pageshow", restoreShellNavigation)' in javascript
    assert "navigation.destination !== currentLocationKey()" in javascript
    assert 'navigation.input !== "keyboard"' in javascript
    assert 'document.querySelector("#main-content")' in javascript
    assert "main.focus({ preventScroll: true })" in javascript
    assert '<main id="main-content" class="vh-main" tabindex="-1">' in base


def test_shell_navigation_storage_failure_is_non_blocking() -> None:
    javascript = _text(INTERACTION)

    assert "Navigation remains functional when session storage is unavailable." in javascript
    assert (
        "Immediate visual acknowledgement still works without persisted continuity." in javascript
    )
    assert "window.sessionStorage.setItem" in javascript
    assert "window.sessionStorage.removeItem" in javascript


def test_pending_navigation_feedback_is_local_and_reduced_motion_safe() -> None:
    css = _text(CSS)

    assert '[data-shell-navigation-pending="true"]' in css
    assert "--vh-motion-duration-instant" in css
    assert 'html[data-shell-navigation="pending"]' in css
    assert "opacity: var(--vh-motion-opacity-muted)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "--vh-motion-duration-instant: 1ms" in css
    assert (
        "opacity: 0"
        not in css.split('html[data-shell-navigation="pending"]', maxsplit=1)[1].split(
            ".vh-motion-enter", maxsplit=1
        )[0]
    )


def test_shell_navigation_does_not_own_assessment_or_progress_state() -> None:
    javascript = _text(INTERACTION).split("const currentLocationKey", maxsplit=1)[1]

    for forbidden in (
        "assessmentState",
        "assessment_state",
        "workerState",
        "worker_state",
        "providerState",
        "provider_state",
        "progressPercent",
        "progress_percent",
    ):
        assert forbidden not in javascript
