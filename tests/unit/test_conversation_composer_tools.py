from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-composer-tools.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-composer-tools.css"
SEARCH = ROOT / "vulnhunter/web/static/web/conversation-search.js"


def test_composer_tools_load_after_conversation_search() -> None:
    search = SEARCH.read_text(encoding="utf-8")

    assert "conversation-composer-tools.js" in search
    assert "script.dataset.composerToolsLoader" in search
    assert "conversation-composer-tools.css" not in search


def test_starter_prompts_only_insert_text_and_never_submit() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "Website assessment" in script
    assert "APK analysis" in script
    assert "Source review" in script
    assert "Explain findings" in script
    assert "Status and next step" in script
    assert "setInputValue" in script
    assert 'input.dispatchEvent(new Event("input"' in script
    assert "requestSubmit" not in script
    assert ".submit(" not in script
    assert 'type = "button"' in script


def test_composer_tools_expose_clear_and_character_count() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'clear.dataset.composerClear = "true"' in script
    assert 'counter.dataset.composerCounter = "true"' in script
    assert "maximumLength - length" in script
    assert 'counter.dataset.state = remaining <= 200 ? "warning" : "normal"' in script
    assert 'setInputValue("")' in script
    assert "input.maxLength" in script


def test_slash_commands_filter_and_insert_without_submitting() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'input.value.match(/^\\/([^\\n]*)$/)' in script
    assert "filterPrompts(query)" in script
    assert 'menu.dataset.openedBySlash = openedBySlash ? "true" : "false"' in script
    assert 'event.key === "Enter" && options.length' in script
    assert "event.stopImmediatePropagation()" in script
    assert "insertPrompt(options[0])" in script
    assert "if (query !== null) setInputValue(prompt)" in script
    assert "No starter prompt matches that command." in script


def test_composer_prompt_menu_closes_with_escape_from_any_focus_target() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'document.addEventListener("keydown"' in script
    assert 'event.key !== "Escape" || menu.hidden' in script
    assert 'closeMenu({ focusTrigger: true })' in script
    assert 'trigger.setAttribute("aria-expanded", "false")' in script


def test_composer_tools_use_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "conversation-composer-tools.css" in script
    assert ".vh-composer-tools" in styles
    assert ".vh-composer-prompt-menu" in styles
    assert ".vh-composer-counter" in styles
    assert ".vh-composer-prompt-empty" in styles
    assert "@media (max-width: 640px)" in styles
