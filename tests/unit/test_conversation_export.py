from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter/web/static/web/conversation-export.js"
STYLES = ROOT / "vulnhunter/web/static/web/conversation-export.css"
RECENT = ROOT / "vulnhunter/web/static/web/conversation-recent-prompts.js"


def test_conversation_export_loads_after_recent_prompt_reuse() -> None:
    recent = RECENT.read_text(encoding="utf-8")

    assert "conversation-export.js" in recent
    assert "script.dataset.conversationExportLoader" in recent
    assert "conversation-export.css" not in recent


def test_export_uses_only_visible_current_thread_message_content() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'feed.querySelectorAll(".vh-chat-message")' in script
    assert 'message.classList.contains("is-local-notice")' in script
    assert 'message.classList.contains("is-user")' in script
    assert 'message.classList.contains("is-assistant")' in script
    assert "copyElement.dataset.rawMessage || copyElement.textContent" in script
    assert "## ${role}" in script
    assert "_Exported from VulnHunter._" in script


def test_export_copies_or_downloads_markdown_without_network_or_storage() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "navigator.clipboard?.writeText" in script
    assert 'new Blob([buildMarkdown()], { type: "text/markdown;charset=utf-8" })' in script
    assert "URL.createObjectURL(blob)" in script
    assert "anchor.download = `${slug(threadTitle())}.md`" in script
    assert "URL.revokeObjectURL(url)" in script
    assert "fetch(" not in script
    assert "sessionStorage" not in script
    assert "localStorage" not in script


def test_export_uses_static_dom_and_self_hosted_responsive_styles() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    styles = STYLES.read_text(encoding="utf-8")

    assert 'document.createElement("style")' not in script
    assert 'document.createElement("link")' in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "conversation-export.css" in script
    assert ".vh-conversation-export" in styles
    assert ".vh-conversation-export-actions" in styles
    assert "@media (max-width: 760px)" in styles


def test_export_exposes_reusable_current_thread_api() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "window.VulnHunterConversationExport" in script
    assert "buildMarkdown" in script
    assert "copy: () => copyText(buildMarkdown())" in script
    assert "download: downloadMarkdown" in script
