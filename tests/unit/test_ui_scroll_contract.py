from __future__ import annotations

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_global_ui_scroll_contract_is_present() -> None:
    css = (REPOSITORY_ROOT / "vulnhunter/web/static/web/ui-audit.css").read_text(
        encoding="utf-8"
    )

    assert "overflow-y: scroll" in css
    assert "scrollbar-gutter: stable" in css
    assert ".vh-main-shell" in css
    assert "min-height: 100dvh" in css
    assert ".vh-nav" in css
    assert "scrollbar-width: thin" in css


def test_browser_audit_checks_vertical_scrolling_and_duplicate_navigation() -> None:
    audit = (REPOSITORY_ROOT / ".playwright-validate.cjs").read_text(encoding="utf-8")

    required_checks = (
        "pageCanScrollVertically",
        "rootOverflowY",
        "sidebarCanScroll",
        "duplicateNavigation",
        "emptyLinks",
        "brokenAnchors",
    )
    for check in required_checks:
        assert check in audit
