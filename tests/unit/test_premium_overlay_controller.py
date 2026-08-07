from pathlib import Path

APP = Path("vulnhunter/web/static/web/app.js")
CSS = Path("vulnhunter/web/static/web/premium-interaction.css")
INTERACTION = Path("vulnhunter/web/static/web/premium-interaction.js")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_shared_controller_owns_dialog_open_close_and_history() -> None:
    javascript = _text(INTERACTION)

    assert "const overlayStack = []" in javascript
    assert "const overlayConfigs = new WeakMap()" in javascript
    assert "dialog.showModal()" in javascript
    assert "window.history.pushState" in javascript
    assert 'window.addEventListener("popstate"' in javascript
    assert 'dialog.addEventListener("cancel"' in javascript
    assert 'dialog.addEventListener("close"' in javascript
    assert "restoreFocus(config)" in javascript
    assert 'document.body?.classList.toggle("vh-overlay-open", open)' in javascript
    assert 'new CustomEvent("vh:overlay-open"' in javascript
    assert 'new CustomEvent("vh:overlay-close"' in javascript


def test_shell_command_and_approval_dialogs_use_shared_controller() -> None:
    app = _text(APP)

    assert "window.VulnHunterInteraction?.overlays" in app
    assert "overlays.open(commandDialog" in app
    assert "overlays.open(approvalDialog" in app
    assert "overlays.close(approvalDialog)" in app
    assert 'backdropClose: true' in app
    assert 'backdropClose: false' in app
    assert 'window.addEventListener("vh:interaction-ready"' in app
    assert ".showModal()" not in app


def test_overlay_presentation_uses_shared_motion_and_reduced_motion() -> None:
    css = _text(CSS)

    assert ".vh-overlay-open" in css
    assert "overscroll-behavior: contain" in css
    assert ":where(dialog[open])" in css
    assert ":where(dialog)::backdrop" in css
    assert "animation: vh-overlay-enter var(--vh-motion-duration-deliberate)" in css
    assert "@keyframes vh-overlay-enter" in css
    assert "@keyframes vh-overlay-backdrop-enter" in css

    reduced_motion = css.split("@media (prefers-reduced-motion: reduce)", maxsplit=1)[1]
    assert ":where(dialog[open])" in reduced_motion
    assert ":where(dialog)::backdrop" in reduced_motion
    assert "animation: none" in reduced_motion


def test_controller_does_not_create_assessment_or_worker_state() -> None:
    javascript = _text(INTERACTION)

    for forbidden in (
        "assessment_state",
        "assessmentState",
        "worker_state",
        "workerState",
        "provider_state",
        "providerState",
        "progress_percent",
        "progressPercent",
    ):
        assert forbidden not in javascript
