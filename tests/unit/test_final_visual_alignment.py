from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "vulnhunter" / "web" / "templates" / "web"
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
BASE = TEMPLATES / "base.html"


def test_canonical_visual_owners_load_once_in_authority_order() -> None:
    base = BASE.read_text(encoding="utf-8")

    for owner in ("tokens.css", "app.css", "product.css", "chat-shell.css"):
        assert base.count(owner) == 1
    assert "workspace.css" not in base
    assert "workspace-polish.css" not in base
    assert "workspace-final-fixes.css" not in base
    assert base.index("tokens.css") < base.index("app.css")
    assert base.index("app.css") < base.index("product.css")
    assert base.index("product.css") < base.index("chat-shell.css")


def test_retired_dashboard_state_cards_are_not_restored_to_the_primary_workspace() -> None:
    conversation = (TEMPLATES / "conversation.html").read_text(encoding="utf-8")
    app = (STATIC / "app.css").read_text(encoding="utf-8")

    assert "vh-state-strip" not in conversation
    assert "vh-state-card" not in conversation
    assert "backdrop-filter" not in app
    assert "linear-gradient(" not in app


def test_inspector_copy_wraps_and_primary_actions_use_canonical_tokens() -> None:
    conversation = (STATIC / "conversation.css").read_text(encoding="utf-8")
    product = (STATIC / "product.css").read_text(encoding="utf-8")

    assert ".vh-inspector-finding" in conversation
    assert "overflow-wrap: anywhere" in conversation
    assert ".vh-button-primary" in product
    assert "background: var(--vh-pink)" in product
    assert "border-radius: 2px" in product
