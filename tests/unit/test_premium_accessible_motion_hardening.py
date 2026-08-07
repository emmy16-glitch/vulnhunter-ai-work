from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSS = ROOT / "vulnhunter/web/static/web/premium-interaction.css"


def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def test_inspector_transitions_use_shared_semantic_timing() -> None:
    css = _css()

    assert ".vh-analysis-progress::after" in css
    assert "transition-duration: var(--vh-motion-duration-standard)" in css
    assert "transition-timing-function: var(--vh-motion-easing-standard)" in css
    assert ".vh-analysis-inspector" in css
    assert "transition-timing-function: var(--vh-motion-easing-enter)" in css


def test_reduced_motion_collapses_transitions_as_well_as_animation() -> None:
    css = _css()
    reduced = css.split("@media (prefers-reduced-motion: reduce)", maxsplit=1)[1]

    assert "animation-duration: 1ms !important" in reduced
    assert "animation-iteration-count: 1 !important" in reduced
    assert "transition-duration: 1ms !important" in reduced
    assert "scroll-behavior: auto !important" in reduced


def test_narrow_and_zoomed_inspector_content_reflows_without_ellipsis() -> None:
    css = _css()

    assert "@media (max-width: 900px)" in css
    assert ".vh-analysis-progress-row p" in css
    assert ".vh-analysis-artifact dd" in css
    assert "overflow-wrap: anywhere" in css
    assert "text-overflow: clip" in css
    assert "white-space: normal" in css


def test_forced_colors_preserves_focus_and_overlay_boundaries() -> None:
    css = _css()

    forced = css.split("@media (forced-colors: active)", maxsplit=1)[1]
    assert "outline: 2px solid CanvasText !important" in forced
    assert "outline-offset: 3px" in forced
    assert ":where(dialog[open])" in forced
    assert ".vh-analysis-inspector" in forced
