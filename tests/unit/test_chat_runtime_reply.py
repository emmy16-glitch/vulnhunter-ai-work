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
    assert '"script-src \'self\'; "' in settings


def test_broken_normalizer_is_covered_by_the_external_guard() -> None:
    with open("vulnhunter/web/static/web/conversation.js", encoding="utf-8") as handle:
        script = handle.read()
    with open(
        "vulnhunter/web/static/web/conversation-runtime-compat.js",
        encoding="utf-8",
    ) as handle:
        compatibility = handle.read()

    assert '" ".join(value.toLowerCase().split())' in script
    assert 'Object.defineProperty(String.prototype, "join"' in compatibility
    assert "items.join(String(this))" in compatibility
