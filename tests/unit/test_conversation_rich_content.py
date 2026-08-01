from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-rich-content.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-rich-content.css"
RESPONSE_CONTROLS = ROOT / "vulnhunter/web/static/web/conversation-response-controls.js"


def test_rich_content_is_loaded_after_response_controls() -> None:
    controls = RESPONSE_CONTROLS.read_text(encoding="utf-8")

    assert "conversation-rich-content.js" in controls
    assert "script.dataset.richContentLoader" in controls
    assert "conversation-rich-content.css" not in controls


def test_rich_content_builds_safe_dom_without_model_html() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "document.createElement" in script
    assert "document.createTextNode" in script
    assert ".textContent =" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "DOMParser" not in script
    assert "eval(" not in script


def test_rich_content_supports_expected_answer_blocks() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'wrapper.className = "vh-rich-code"' in script
    assert 'element.className = "vh-rich-heading"' in script
    assert 'list.className = "vh-rich-list"' in script
    assert 'quote.className = "vh-rich-quote"' in script
    assert 'code.className = "vh-rich-inline-code"' in script
    assert 'button.textContent = "Copy code"' in script


def test_rich_content_preserves_raw_answer_for_whole_message_copy() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    controls = RESPONSE_CONTROLS.read_text(encoding="utf-8")

    assert "copy.dataset.rawMessage = raw" in script
    assert "copy.dataset.richRendered === \"true\"" in script
    assert "messageCopy.dataset.rawMessage || messageCopy.textContent" in controls


def test_rich_content_uses_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-rich-content.css" in script
    assert ".vh-rich-code" in styles
    assert ".vh-rich-code-copy" in styles
    assert ".vh-rich-inline-code" in styles
    assert "@media (max-width: 640px)" in styles
