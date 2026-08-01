from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-recent-prompts.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-recent-prompts.css"
COMPOSER = ROOT / "vulnhunter/web/static/web/conversation-composer-tools.js"


def test_recent_prompts_load_from_the_existing_composer_tools() -> None:
    composer = COMPOSER.read_text(encoding="utf-8")

    assert "conversation-recent-prompts.js" in composer
    assert "script.dataset.recentPromptsLoader" in composer
    assert "conversation-recent-prompts.css" not in composer


def test_recent_prompts_use_only_current_thread_user_messages() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'feed.querySelectorAll(".vh-chat-message.is-user")' in script
    assert ".reverse()" in script
    assert "const maximumPrompts = 5" in script
    assert "seen.has(normalized)" in script
    assert "seen.add(normalized)" in script
    assert "values.length >= maximumPrompts" in script
    assert "maximumValueLength = 4000" in script


def test_recent_prompts_appear_before_starter_prompts_on_phone() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "list.prepend(section)" in script
    assert 'title.textContent = "Recent prompts"' in script
    assert 'meta.textContent = index === 0 ? "Most recent"' in script


def test_recent_prompts_only_insert_text_and_never_persist_or_submit() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "button.dataset.promptValue = value" in script
    assert 'button.dataset.promptSearch = "recent previous history"' in script
    assert "requestSubmit" not in script
    assert ".submit(" not in script
    assert "fetch(" not in script
    assert "sessionStorage" not in script
    assert "localStorage" not in script
    assert "FileReader" not in script


def test_recent_prompts_update_when_conversation_messages_change() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "new MutationObserver(scheduleRender).observe(feed" in script
    assert "childList: true" in script
    assert "subtree: true" in script
    assert "characterData: true" in script
    assert "window.VulnHunterRecentPrompts" in script


def test_recent_prompts_use_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-recent-prompts.css" in script
    assert ".vh-composer-recent-prompts" in styles
    assert ".vh-composer-recent-option" in styles
    assert "@media (max-width: 640px)" in styles
