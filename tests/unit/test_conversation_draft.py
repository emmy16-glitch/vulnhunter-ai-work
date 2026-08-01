from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-draft.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-draft.css"
BACKGROUND_UPLOAD_STYLES = ROOT / "vulnhunter/web/static/web/background-uploads.css"
RESPONSE_CONTROLS = ROOT / "vulnhunter/web/static/web/conversation-response-controls.js"


def test_draft_recovery_is_loaded_after_response_controls() -> None:
    controls = RESPONSE_CONTROLS.read_text(encoding="utf-8")

    assert "conversation-rich-content.js" in controls
    assert "conversation-draft.js" in controls
    assert controls.index("conversation-rich-content.js") < controls.index("conversation-draft.js")
    assert "script.dataset.conversationDraftLoader" in controls


def test_draft_uses_session_storage_and_thread_scoping_only() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "window.sessionStorage" in script
    assert "window.localStorage" not in script
    assert "initial.thread_id" in script
    assert "workspace.dataset.threadId" in script
    assert "window.location.pathname" in script
    assert "vulnhunter:conversation-draft" in script


def test_draft_never_persists_files_or_attachment_content() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "FileReader" not in script
    assert "arrayBuffer" not in script
    assert "data-conversation-file" not in script
    assert "attachment" not in script.lower()
    assert "maximumLength" in script
    assert "20000" in script


def test_draft_restores_stopped_and_failed_prompts_but_clears_success() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "body.stopped === true" in script
    assert 'restorePrompt("Prompt restored after stopping")' in script
    assert 'restorePrompt("Draft kept after the failed request")' in script
    assert 'restorePrompt("Draft kept after the connection error")' in script
    assert "storage.clear()" in script
    assert 'announce("Sent", "sent", 1000)' in script


def test_draft_status_uses_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-draft.css" in script
    assert ".vh-draft-status" in styles
    assert '[data-state="restored"]' in styles
    assert "@media (max-width: 640px)" in styles


def test_phone_upload_clearance_tracks_the_real_composer_height() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    upload_styles = BACKGROUND_UPLOAD_STYLES.read_text(encoding="utf-8")

    assert "new ResizeObserver(syncComposerClearance)" in script
    assert 'style.setProperty("--vh-phone-composer-clearance"' in script
    assert "window.visualViewport?.addEventListener" in script
    assert "var(--vh-phone-composer-clearance" in upload_styles
    assert "env(safe-area-inset-bottom)" in upload_styles
    assert "100dvh" in upload_styles
