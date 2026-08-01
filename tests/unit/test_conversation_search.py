from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-search.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-search.css"
DRAFT = ROOT / "vulnhunter/web/static/web/conversation-draft.js"


def test_conversation_search_loads_after_draft_recovery() -> None:
    draft = DRAFT.read_text(encoding="utf-8")

    assert "conversation-search.js" in draft
    assert "script.dataset.conversationSearchLoader" in draft
    assert "conversation-search.css" not in draft


def test_conversation_search_uses_message_text_without_rewriting_content() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'feed.querySelectorAll(".vh-chat-message")' in script
    assert "message.textContent" in script
    assert 'message.classList.add("is-search-match")' in script
    assert 'message.classList.toggle("is-search-active"' in script
    assert "replaceChildren" not in script
    assert "insertAdjacentHTML" not in script
    assert "DOMParser" not in script


def test_conversation_search_supports_keyboard_and_result_navigation() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "event.ctrlKey || event.metaKey" in script
    assert 'event.key.toLocaleLowerCase() === "f"' in script
    assert 'event.key === "Enter"' in script
    assert 'event.key === "Escape"' in script
    assert "state.activeIndex + (event.shiftKey ? -1 : 1)" in script
    assert "Previous search result" in script
    assert "Next search result" in script


def test_conversation_search_uses_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-search.css" in script
    assert ".vh-conversation-search" in styles
    assert ".vh-chat-message.is-search-active" in styles
    assert "@media (max-width: 760px)" in styles
