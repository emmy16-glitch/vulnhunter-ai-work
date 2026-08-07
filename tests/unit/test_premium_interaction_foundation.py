from pathlib import Path

BASE = Path("vulnhunter/web/templates/web/base.html")
CSS = Path("vulnhunter/web/static/web/premium-interaction.css")
JS = Path("vulnhunter/web/static/web/premium-interaction.js")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_shared_interaction_assets_are_loaded_by_the_product_shell() -> None:
    base = _text(BASE)

    css_asset = "web/premium-interaction.css"
    js_asset = "web/premium-interaction.js"
    assert css_asset in base
    assert js_asset in base
    assert base.index(css_asset) > base.index("web/background-uploads.css")
    assert base.index(css_asset) < base.index("{% block extra_styles %}")
    assert base.index(js_asset) < base.index("{% block extra_scripts %}")


def test_motion_tokens_have_one_shared_semantic_vocabulary() -> None:
    css = _text(CSS)

    for token in (
        "--vh-motion-duration-instant",
        "--vh-motion-duration-fast",
        "--vh-motion-duration-standard",
        "--vh-motion-duration-deliberate",
        "--vh-motion-duration-large",
        "--vh-motion-easing-standard",
        "--vh-motion-easing-enter",
        "--vh-motion-easing-exit",
        "--vh-motion-easing-emphasized",
        "--vh-motion-distance-xs",
        "--vh-motion-distance-sm",
        "--vh-motion-distance-md",
        "--vh-motion-distance-lg",
        "--vh-motion-scale-press",
        "--vh-motion-scale-enter",
        "--vh-motion-opacity-muted",
        "--vh-motion-opacity-disabled",
    ):
        assert token in css

    assert "transition-duration: var(--vh-motion-duration-fast)" in css
    assert "animation: vh-motion-enter var(--vh-motion-duration-standard)" in css
    assert "animation: vh-motion-exit var(--vh-motion-duration-fast)" in css


def test_shared_primitive_states_preserve_truthful_authoritative_state() -> None:
    css = _text(CSS)

    assert "--vh-interaction-target-min: 44px" in css
    assert "min-height: var(--vh-interaction-target-min)" in css
    assert '[aria-busy="true"]' in css
    assert '[aria-disabled="true"]' in css
    for state in (
        "disabled",
        "unavailable",
        "locked",
        "loading",
        "selected",
        "active",
        "success",
        "warning",
        "failure",
    ):
        assert f'[data-interaction-state="{state}"]' in css

    assert "pointer-events: none" in css
    assert "cursor: progress" in css
    assert "cursor: not-allowed" in css


def test_reduced_motion_is_a_complete_semantic_alternative() -> None:
    css = _text(CSS)
    javascript = _text(JS)

    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "--vh-motion-duration-standard: 1ms" in css
    assert "--vh-motion-distance-lg: 0px" in css
    assert "--vh-motion-scale-press: 1" in css
    assert "scroll-behavior: auto" in css
    assert "animation-iteration-count: 1" in css
    assert "transition: none" not in css

    assert 'matchMedia("(prefers-reduced-motion: reduce)")' in javascript
    assert "root.dataset.motion = motion" in javascript
    assert "vh:motion-preference-change" in javascript
    assert 'query.addEventListener("change", applyMotionPreference)' in javascript
