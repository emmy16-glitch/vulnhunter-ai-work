from pathlib import Path


def test_empty_mobile_composer_stays_compact_and_controls_keep_space():
    root = Path(__file__).resolve().parents[2]
    mobile_css = (root / "vulnhunter/web/static/web/conversation-mobile.css").read_text()

    assert ".vh-chat-input-shell textarea:placeholder-shown" in mobile_css
    assert "height: 44px !important" in mobile_css
    assert "flex: 1 1 auto" in mobile_css
    assert "min-width: 0" in mobile_css
    assert ".vh-reasoning-control select" in mobile_css
    assert "width: 6.5rem" in mobile_css
    assert "gap: .4rem" in mobile_css


def test_source_hunt_worker_is_started_only_after_live_groq_verification():
    root = Path(__file__).resolve().parents[2]
    launcher = (root / ".devcontainer/start-vulnhunter.sh").read_text()

    verify_index = launcher.index("vh_verify_groq")
    worker_index = launcher.index("vh_run_source_hunt_worker")
    ready_index = launcher.index('SOURCE_HUNT_STATE="exact-approval queue ready"')
    assert verify_index < worker_index < ready_index


def test_repeated_browser_lifecycle_uses_a_fresh_workspace_and_configured_evidence_path():
    root = Path(__file__).resolve().parents[2]
    script = (root / "tests/ui/conversation_e2e.cjs").read_text()

    assert 'locator(".vh-task-menu > summary")' in script
    assert 'locator("[data-thread-create]")' in script
    assert 'url.searchParams.has("thread")' in script
    assert 'locator("[data-run-card]").last()' in script
    assert "process.env.VULNHUNTER_UI_OUTPUT" in script
