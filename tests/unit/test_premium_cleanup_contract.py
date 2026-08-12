from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter/web/static/web"
BASE = ROOT / "vulnhunter/web/templates/web/base.html"


def test_retired_workspace_patch_layers_are_deleted() -> None:
    assert not (STATIC / "workspace-polish.css").exists()
    assert not (STATIC / "workspace-final-fixes.css").exists()
    assert not (STATIC / "product-wide.css").exists()


def test_shell_uses_canonical_visual_owner_stack_without_competing_workspace_layers() -> None:
    base = BASE.read_text(encoding="utf-8")

    for owner in ("tokens.css", "app.css", "product.css", "chat-shell.css"):
        assert base.count(owner) == 1
    assert base.count("premium-interaction.js") == 1
    assert "workspace.css" not in base
    assert "premium-interaction.css" not in base
    assert "workspace-polish.css" not in base
    assert "workspace-final-fixes.css" not in base
    assert base.index("tokens.css") < base.index("app.css")
    assert base.index("app.css") < base.index("product.css")
    assert base.index("product.css") < base.index("chat-shell.css")
