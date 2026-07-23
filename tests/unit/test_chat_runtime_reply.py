def test_conversation_template_uses_a_csp_safe_runtime_guard() -> None:
    with open(
        "vulnhunter/web/templates/web/conversation.html",
        encoding="utf-8",
    ) as handle:
        template = handle.read()
    with open("vulnhunter/web/settings.py", encoding="utf-8") as handle:
        settings = handle.read()

    asset = "web/conversation-runtime-compat.js"
    assert asset in template
    assert template.index(asset) < template.index("data-conversation-workspace")
    assert "Object.defineProperty(String.prototype" not in template
    assert "\"script-src 'self'; \"" in settings


def test_commands_are_sent_to_the_authoritative_server_state() -> None:
    with open("vulnhunter/web/static/web/conversation.js", encoding="utf-8") as handle:
        script = handle.read()

    assert '" ".join(value.toLowerCase().split())' not in script
    assert "contextualReply" not in script
    assert "initial.message_url" in script
    assert "postForm(initial.message_url" in script
    assert "run.current_step" in script
    assert "next.final_message" in script
