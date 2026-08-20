from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_chat_first_workspace_protects_conversation_width_and_hides_duplicate_rail():
    styles = (
        ROOT / "vulnhunter/web/static/web/assessment-workspace.css"
    ).read_text(encoding="utf-8")
    template = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")

    assert 'data-chat-tasks-panel aria-label="Chats and tasks" hidden' in template
    assert ".vh-conversation-body .vh-chat-tasks-panel" in styles
    assert "display: none !important" in styles
    assert "@media (min-width: 768px) and (max-width: 1439px)" in styles
    assert "@media (min-width: 1440px)" in styles
    assert "grid-template-columns: minmax(620px, 1fr)" in styles
    assert "word-break: normal" in styles
    assert "overflow-wrap: break-word" in styles


def test_contextual_inspector_is_explicit_and_lifecycle_is_not_tool_coverage():
    template = (
        ROOT / "vulnhunter/web/templates/web/_mobile_analysis_inspector.html"
    ).read_text(encoding="utf-8")
    conversation = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")
    styles = (
        ROOT / "vulnhunter/web/static/web/assessment-workspace.css"
    ).read_text(encoding="utf-8")

    assert "Assessment lifecycle" in template
    assert "does not imply that every analysis capability completed successfully" in template
    assert "Analysis capabilities" in template
    assert "Persisted tool and policy state" in template
    assert "vh-chat-details-action" in conversation
    assert "conversation-inspector-open.js" in conversation
    assert ".vh-analysis-inspector[hidden]" in styles
    assert ".vh-chat-workspace.has-analysis-inspector" in styles


def test_starter_capabilities_are_progressive_and_not_permanent_task_panels():
    template = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")

    empty_start = template.index('class="vh-empty-workspace"')
    advanced = template.index('class="vh-inline-disclosure vh-empty-advanced-start"')
    public_consent = template.index('class="vh-public-consent-panel"')
    browser_intelligence = template.index('class="vh-browser-intelligence-panel"')
    main_close = template.index("</section>\n      </div>", browser_intelligence)

    assert empty_start < advanced < public_consent < browser_intelligence < main_close
    assert "Advanced setup" in template
    assert "Source Hunt" in template
    assert "vh-empty-recent" not in template


def test_conversation_context_is_human_readable_while_ids_remain_authoritative():
    script = (
        ROOT / "vulnhunter/web/static/web/conversation-mobile-context.js"
    ).read_text(encoding="utf-8")
    template = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")

    assert "assessmentId" in script
    assert "assessmentLabel" in script
    assert "contextState.ids" in script
    assert "ids: detail.selectedIds || []" in script
    assert 'projection.subject?.label || "Selected assessment"' in script
    assert "Assessment:" not in script
    assert "Reviewing the selected APK evidence" in script
    assert "Reasoning over the selected APK plan" not in script
    assert '<span class="vh-eyebrow">Context</span>' in template
    assert 'data-conversation-context-clear>Clear</button>' in template
