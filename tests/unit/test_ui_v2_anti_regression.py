from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "vulnhunter" / "web"
TEMPLATES = WEB / "templates" / "web"
STATIC = WEB / "static" / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_base_shell_does_not_restore_retired_global_ui_layers() -> None:
    base = _read(TEMPLATES / "base.html")
    app_js = _read(STATIC / "app.js")

    assert "product-wide.css" not in base
    assert "product-wide.css" not in app_js
    assert "ui-audit.css" not in base
    assert "unified-mobile.css" not in base
    assert "workspace.css" not in base
    assert "data-sidebar" in base
    assert "vh-chat-shell" in base
    assert "New assessment" in base
    assert "Chats / Tasks" in base
    assert "Task history" in base
    assert "Manage" in base


def test_conversation_is_task_first_not_dashboard_first() -> None:
    conversation = _read(TEMPLATES / "conversation.html")

    assert "data-run-stages" in conversation
    assert "data-run-tool-chips" in conversation
    assert "data-conversation-form" in conversation
    assert "data-history-panel" in conversation
    # The inspector is included as a contextual partial, not authored inline here.
    assert "data-analysis-inspector" not in conversation
    assert "vh-state-strip" not in conversation
    assert "vh-chat-actions" not in conversation
    assert "vh-mobile-workspace-nav" not in conversation
    assert "Remediation guidance" in conversation


def test_contextual_inspector_has_no_duplicate_mobile_bottom_navigation() -> None:
    inspector = _read(TEMPLATES / "_mobile_analysis_inspector.html")
    bridge = _read(STATIC / "conversation-mobile-bridge.js")

    assert "vh-mobile-workspace-nav" not in inspector
    assert "data-mobile-nav-destination" not in inspector
    assert "data-mobile-workspace-nav" not in bridge
    assert "Assessment details" in inspector
    assert "Technical and audit details" in inspector
    assert ">Summary<" in inspector
    assert ">Activity<" in inspector
    assert ">Findings " in inspector
    assert ">Evidence " in inspector
    assert ">Report " in inspector
    assert "Graph" not in inspector
    assert not (STATIC / "conversation-mobile-inspector-route.js").exists()


def test_conversation_search_and_export_live_in_overflow_not_header_toolbar() -> None:
    search_js = _read(STATIC / "conversation-search.js")
    export_js = _read(STATIC / "conversation-export.js")

    for script in (search_js, export_js):
        assert '.querySelector(".vh-task-menu-popover")' in script
        assert "vh-chat-actions" not in script

    assert "data-composer-tools-loader" in search_js
    assert "Search conversation" in search_js
    assert "Export conversation" in export_js


def test_primary_workspace_uses_readable_canonical_visual_system() -> None:
    tokens = _read(STATIC / "tokens.css")
    app = _read(STATIC / "app.css")
    conversation = _read(STATIC / "conversation.css")

    assert "system-ui" in tokens
    assert "--vh-canvas: #f5f2ec" in tokens
    assert "--vh-pink: #d99a9f" in tokens
    assert "--vh-sidebar: #10151b" in tokens
    assert "backdrop-filter" not in app
    assert "backdrop-filter" not in conversation
    assert "glassmorphism" not in conversation.lower()
    assert ".vh-message-copy" in conversation
    assert "font-size: 16px" in conversation
    assert "min-height: 44px" in conversation


def test_live_auxiliary_conversation_surfaces_use_the_same_visual_contract() -> None:
    stylesheet_names = (
        "conversation-composer-tools.css",
        "conversation-search.css",
        "conversation-export.css",
        "conversation-response-controls.css",
        "conversation-rich-content.css",
        "conversation-draft.css",
        "conversation-recent-prompts.css",
        "conversation-premium-continuity.css",
        "conversation-jump-latest.css",
        "conversation-upload.css",
        "background-uploads.css",
    )

    for name in stylesheet_names:
        stylesheet = _read(STATIC / name)
        assert "backdrop-filter" not in stylesheet, name
        assert "rgba(108, 124, 255" not in stylesheet, name
        assert "border-radius: 999px" not in stylesheet, name
        assert "var(--vh-" in stylesheet, name

    composer = _read(STATIC / "conversation-composer-tools.css")
    assert ".vh-provider-control" in composer
    assert "min-width: 112px" in composer
    assert "padding-bottom: max(8px, env(safe-area-inset-bottom))" in composer
    assert ".vh-composer-advanced[open]" in composer
    assert ".vh-composer-advanced[open] .vh-composer-advanced-body" in composer
    assert "position: static" in composer
    assert "flex: 1 0 100%" in composer


def test_mobile_workspace_is_one_column_and_drawer_driven() -> None:
    app = _read(STATIC / "app.css")
    conversation = _read(STATIC / "conversation.css")
    mobile_execution = _read(STATIC / "conversation-mobile-execution.css")

    assert "@media (max-width: 1023px)" in app
    assert ".vh-sidebar.is-open" in app
    assert "@media (max-width: 767px)" in conversation
    assert "grid-template-columns: minmax(0, 1fr)" in conversation
    assert "position: fixed" in conversation
    assert "@media (max-width: 720px)" in mobile_execution
    assert "env(safe-area-inset-bottom)" in mobile_execution


def test_source_hunt_is_focused_three_step_flow() -> None:
    source = _read(TEMPLATES / "source_hunt.html")
    source_css = _read(STATIC / "source-hunt.css")

    assert "Groq-only source analysis" in source
    assert "Three governed steps" in source
    assert "Exact repository snapshot" in source
    assert "Source-processing confirmation" in source
    assert "Queue exact snapshot and hunt" in source
    assert "Authority stays with VulnHunter" in source
    assert "backdrop-filter" not in source_css
    assert "vh-source-hunt-layout" in source_css


def test_specialist_indexes_do_not_use_primary_kpi_walls() -> None:
    paths = [
        "findings_overview.html",
        "agent_runs.html",
        "approvals.html",
        "review_queue.html",
        "adjudications_overview.html",
        "campaigns.html",
        "releases_overview.html",
        "datasets_overview.html",
        "models_overview.html",
        "audit_overview.html",
        "reports_overview.html",
        "settings_overview.html",
        "governance_overview.html",
        "authorizations_overview.html",
        "roles.html",
        "skills.html",
        "readiness.html",
    ]
    for name in paths:
        content = _read(TEMPLATES / name)
        assert "vh-summary-strip" not in content, name
        assert "vh-ops-metric-grid" not in content, name
        assert "vh-page-shell" in content, name


def test_ui_never_renders_hidden_chain_of_thought_contract() -> None:
    conversation = _read(TEMPLATES / "conversation.html").lower()
    conversation_js = _read(STATIC / "conversation.js").lower()

    forbidden = (
        "chain-of-thought",
        "private reasoning trace",
        "hidden reasoning tokens",
    )
    for phrase in forbidden:
        assert phrase not in conversation
        assert phrase not in conversation_js

    assert "working with the current assessment state" in conversation
