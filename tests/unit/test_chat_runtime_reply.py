from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_conversation_template_repairs_the_runtime_join_crash() -> None:
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(
        encoding="utf-8"
    )

    assert "typeof String.prototype.join" in template
    assert "Array.isArray(items) ? items.join(String(this))" in template
    assert template.index("typeof String.prototype.join") < template.index(
        "data-conversation-workspace"
    )


def test_broken_normalizer_is_covered_by_the_compatibility_guard() -> None:
    script = (ROOT / "vulnhunter/web/static/web/conversation.js").read_text(
        encoding="utf-8"
    )
    template = (ROOT / "vulnhunter/web/templates/web/conversation.html").read_text(
        encoding="utf-8"
    )

    assert '" ".join(value.toLowerCase().split())' in script
    assert "Object.defineProperty(String.prototype, \"join\"" in template
