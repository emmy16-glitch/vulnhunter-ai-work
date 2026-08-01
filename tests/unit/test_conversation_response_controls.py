from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-response-controls.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-response-controls.css"
UPLOAD_STYLES = ROOT / "vulnhunter/web/static/web/background-uploads.css"
RUNTIME = ROOT / "vulnhunter/web/static/web/conversation-runtime-compat.js"


def test_response_controls_are_loaded_after_provider_control() -> None:
    runtime = RUNTIME.read_text(encoding="utf-8")

    provider = runtime.index('loadScript("conversation-provider-control.js"')
    response = runtime.index('loadScript("conversation-response-controls.js"')
    assert provider < response
    assert "data-response-controls-loader" in runtime


def test_stop_waiting_aborts_only_the_active_message_request() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "new AbortController()" in script
    assert "requestUrl.pathname === messageUrl.pathname" in script
    assert 'controller.abort("user-stopped-waiting")' in script
    assert "The remote provider may already have received the request" in script
    assert 'JSON.stringify({ stopped: true })' in script
    assert "window.VulnHunterResponseControls" in script


def test_message_actions_support_copy_edit_and_retry() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'utilityButton("Copy"' in script
    assert 'utilityButton("Edit"' in script
    assert 'utilityButton("Retry"' in script
    assert "navigator.clipboard?.writeText" in script
    assert 'setInputValue(prompt, { submit: true })' in script
    assert "previousUserCopy" in script


def test_response_controls_use_self_hosted_csp_safe_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")
    upload_styles = UPLOAD_STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert ".style." not in script
    assert 'document.createElement("link")' in script
    assert "conversation-response-controls.css" in script
    assert ".vh-stop-response" in styles
    assert ".vh-message-utility-actions" in styles
    assert ".vh-clipboard-proxy" in styles
    assert "@media (max-width: 640px)" in styles
    assert ".vh-background-upload-dock[hidden] { display: none; }" in upload_styles
