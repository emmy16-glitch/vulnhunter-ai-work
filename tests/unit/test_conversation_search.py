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


def test_conversation_search_marks_only_searchable_workspace_text() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "function searchableBlocks()" in script
    assert 'mark.dataset.vhSearchMatch = "true"' in script
    assert 'match.classList.add("is-vh-search-active")' in script
    assert 'feed.querySelectorAll("mark[data-vh-search-match]")' in script
    assert "replaceWith(document.createTextNode" in script
    assert "insertAdjacentHTML" not in script
    assert "DOMParser" not in script


def test_conversation_search_supports_keyboard_open_escape_and_result_navigation() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "event.metaKey || event.ctrlKey" in script
    assert 'event.key.toLocaleLowerCase() === "f"' in script
    assert 'event.key === "Escape"' in script
    assert 'data-conversation-search-previous' in script
    assert 'data-conversation-search-next' in script
    assert "activate(activeIndex - 1)" in script
    assert "activate(activeIndex + 1)" in script
    assert "restoreMenuFocus" in script


def test_conversation_search_uses_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-search.css" in script
    assert ".vh-conversation-search-panel" in styles
    assert "mark[data-vh-search-match]" in styles
    assert ".is-vh-search-active" in styles
    assert "@media (max-width: 767px)" in styles
    assert "min-height: 44px" in styles
