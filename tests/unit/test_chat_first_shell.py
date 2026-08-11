"""Chat-first application shell (Batch 2) structural and classification tests."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"
BASE = WEB / "templates" / "web" / "base.html"
CHAT_SHELL_CSS = WEB / "static" / "web" / "chat-shell.css"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_base_shell_preserves_mobile_drawer_hooks() -> None:
    """The shared shell keeps the repository-owned drawer contract intact."""
    base = _text(BASE)
    for marker in (
        'class="vh-sidebar vh-chat-shell"',
        "[data-sidebar]",
        'data-nav-toggle aria-expanded="false"',
        "[data-nav-close]",
        'class="vh-sidebar-scrim"',
    ):
        assert marker in base, marker


def test_base_shell_is_chat_task_first_and_progressively_disclosed() -> None:
    """New assessment, Chats/Tasks, Manage and the user footer are the shell."""
    base = _text(BASE)
    assert "vh-new-assessment" in base
    assert "New assessment" in base
    assert "Chats / Tasks" in base
    assert "Task history" in base
    assert 'class="vh-manage"' in base
    # settings stays a distinct, non-primary shell entry
    assert 'aria-label="Settings"' in base
    # user + role footer
    assert "vh-shell-footer" in base
    assert "request.user.username" in base


def test_running_task_state_is_repository_backed() -> None:
    """The current-task row renders only real run state, never fake progress."""
    base = _text(BASE)
    assert "conversation.active_run.state" in base
    assert "conversation.active_run.detail_url" in base
    assert "conversation.active_run.terminal" in base
    for fake in ("36%", "percent", "fake progress", "Pause"):
        assert fake not in base


def test_chat_shell_navigation_buckets_items_by_product_ia() -> None:
    """Role-gated navigation is rearranged, not extended, by the shell."""
    from vulnhunter.web.templatetags.vh_navigation import chat_shell_navigation

    navigation = (
        {
            "label": "Assessment Workspace",
            "url_name": "web-dashboard",
            "active_routes": ("web-dashboard",),
        },
        {
            "label": "Authorizations",
            "url_name": "web-authorization-list",
            "active_routes": ("web-authorization-list",),
        },
        {
            "label": "Assessment History",
            "url_name": "web-scan-run-list",
            "active_routes": ("web-scan-run-list",),
        },
        {
            "label": "Findings",
            "url_name": "web-findings-overview",
            "active_routes": ("web-findings-overview",),
        },
        {
            "label": "Settings",
            "url_name": "web-settings-overview",
            "active_routes": ("web-settings-overview",),
        },
    )
    shell = chat_shell_navigation(navigation, "web-findings-overview")

    assert [str(i["label"]) for i in shell["primary"]] == ["Assessment Workspace"]
    assert [str(i["label"]) for i in shell["history"]] == ["Assessment History"]
    assert [str(i["label"]) for i in shell["settings"]] == ["Settings"]
    assert [str(i["label"]) for i in shell["manage"]] == ["Authorizations", "Findings"]
    assert shell["can_new_assessment"] is True
    # Deep view inside Manage expands it (progressive disclosure of the current area).
    assert shell["manage_active"] is True


def test_chat_shell_navigation_does_not_promote_every_backend_capability() -> None:
    from vulnhunter.web.templatetags.vh_navigation import chat_shell_navigation

    reviewer_navigation = (
        {
            "label": "Review Queue",
            "url_name": "web-review-queue",
            "active_routes": ("web-review-queue",),
        },
    )
    shell = chat_shell_navigation(reviewer_navigation, "web-review-queue")

    assert shell["can_new_assessment"] is False
    assert shell["history"] == ()
    assert shell["settings"] == ()
    # Only the specialist surface is surfaced, inside Manage.
    assert [str(i["label"]) for i in shell["manage"]] == ["Review Queue"]
    assert shell["manage_active"] is True


def test_chat_shell_css_respects_locked_contract() -> None:
    css = _text(CHAT_SHELL_CSS)
    for token in (
        "--vh-pink",
        "--vh-ink",
        "--vh-sidebar",
        "--vh-sidebar-surface",
        "--vh-shadow-panel",
        "--vh-radius-sm",
        "prefers-reduced-motion",
    ):
        assert token in css, token
    # No invented generic-blue/teal SaaS or gradient language.
    for forbidden in ("#4f8cff", "#38bdf8", "linear-gradient", "glow", "glassmorphism"):
        assert forbidden not in css, forbidden
    # Balanced braces.
    assert css.count("{") == css.count("}")


def test_chat_shell_navigation_keeps_route_permissions_authoritative() -> None:
    """The classifier never manufactures routes; it only moves existing items."""
    from vulnhunter.web.templatetags.vh_navigation import chat_shell_navigation

    navigation = (
        {
            "label": "Datasets",
            "url_name": "web-dataset-list",
            "active_routes": ("web-dataset-list",),
        },
    )
    shell = chat_shell_navigation(navigation, "")
    combined = (
        list(shell["primary"])
        + list(shell["history"])
        + list(shell["settings"])
        + list(shell["manage"])
    )
    assert [str(i["label"]) for i in combined] == ["Datasets"]
    assert all(i["url_name"] == "web-dataset-list" for i in combined)
