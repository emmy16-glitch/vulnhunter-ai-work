import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOKENS = ROOT / "config" / "product_interface" / "design_tokens.json"
CSS = ROOT / "vulnhunter" / "web" / "static" / "web" / "tokens.css"
BASE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "base.html"


def _css_value(css: str, name: str) -> str:
    marker = f"{name}:"
    line = next(line for line in css.splitlines() if line.strip().startswith(marker))
    return line.split(":", 1)[1].strip().rstrip(";")


def test_critical_runtime_tokens_match_the_canonical_json_source() -> None:
    source = json.loads(TOKENS.read_text(encoding="utf-8"))
    css = CSS.read_text(encoding="utf-8")

    expected = {
        "--vh-color-accent": source["colors"]["accent"],
        "--vh-color-accent-hover": source["colors"]["accent_hover"],
        "--vh-color-background": source["colors"]["background"],
        "--vh-color-border": source["colors"]["border"],
        "--vh-color-danger": source["colors"]["danger"],
        "--vh-color-focus": source["colors"]["focus"],
        "--vh-color-info": source["colors"]["info"],
        "--vh-color-success": source["colors"]["success"],
        "--vh-color-surface": source["colors"]["surface"],
        "--vh-color-surface-elevated": source["colors"]["surface_elevated"],
        "--vh-color-text-primary": source["colors"]["text_primary"],
        "--vh-color-text-secondary": source["colors"]["text_secondary"],
        "--vh-color-warning": source["colors"]["warning"],
        "--vh-layout-sidebar": f"{source['layout']['sidebar_width_px']}px",
        "--vh-layout-topbar": f"{source['layout']['topbar_height_px']}px",
        "--vh-radius-card": f"{source['radii_px']['card']}px",
        "--vh-radius-control": f"{source['radii_px']['control']}px",
        "--vh-radius-modal": f"{source['radii_px']['modal']}px",
    }
    assert {_name: _css_value(css, _name) for _name in expected} == expected


def test_runtime_uses_the_canonical_chat_shell_owner_stack_after_tokens() -> None:
    base = BASE.read_text(encoding="utf-8")

    for owner in ("tokens.css", "app.css", "product.css", "chat-shell.css"):
        assert base.count(owner) == 1
    assert "workspace.css" not in base
    assert "workspace-polish.css" not in base
    assert "workspace-final-fixes.css" not in base
    assert "product-wide.css" not in base
    assert base.index("tokens.css") < base.index("app.css")
    assert base.index("app.css") < base.index("product.css")
    assert base.index("product.css") < base.index("chat-shell.css")
