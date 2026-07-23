def test_conversation_template_repairs_the_runtime_join_crash() -> None:
    with open("vulnhunter/web/templates/web/conversation.html", encoding="utf-8") as handle:
        template = handle.read()

    assert "typeof String.prototype.join" in template
    assert "Array.isArray(items) ? items.join(String(this))" in template
    assert template.index("typeof String.prototype.join") < template.index(
        "data-conversation-workspace"
    )


def test_broken_normalizer_is_covered_by_the_compatibility_guard() -> None:
    with open("vulnhunter/web/static/web/conversation.js", encoding="utf-8") as handle:
        script = handle.read()
    with open("vulnhunter/web/templates/web/conversation.html", encoding="utf-8") as handle:
        template = handle.read()

    assert '" ".join(value.toLowerCase().split())' in script
    assert "Object.defineProperty(String.prototype, \"join\"" in template
