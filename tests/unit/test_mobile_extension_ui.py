from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_mobile_extension_controls_are_loaded_wired_and_phone_responsive():
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(
        encoding="utf-8"
    )
    script = (
        ROOT / "vulnhunter/web/static/web/conversation-mobile-deferred-tools.js"
    ).read_text(encoding="utf-8")
    stylesheet = (
        ROOT / "vulnhunter/web/static/web/conversation-mobile-deferred-tools.css"
    ).read_text(encoding="utf-8")

    assert "conversation-mobile-deferred-tools.css" in template
    assert "conversation-mobile-deferred-tools.js" in template
    assert "data-mobile-extension-approve-url" in template
    assert "web-conversation-mobile-extension-approve" in template
    assert "form.dataset.mobileExtensionApproveUrl" in script
    assert "fetch(approveUrl" in script
    assert "appendAssistantMessage(payload.message)" in script
    assert "vh:mobile-extension-status" in script
    assert "@media (max-width: 720px)" in stylesheet
    assert "min-height: 44px" in stylesheet
