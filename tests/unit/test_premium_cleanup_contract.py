from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter/web/static/web"
BASE = ROOT / "vulnhunter/web/templates/web/base.html"


def test_retired_workspace_patch_layers_are_deleted() -> None:
    assert not (STATIC / "workspace-polish.css").exists()
    assert not (STATIC / "workspace-final-fixes.css").exists()


def test_shell_uses_single_workspace_owner_and_premium_interaction_layer() -> None:
    base = BASE.read_text(encoding="utf-8")

    assert base.count("workspace.css") == 1
    assert base.count("premium-interaction.css") == 1
    assert "workspace-polish.css" not in base
    assert "workspace-final-fixes.css" not in base
    assert base.index("tokens.css") < base.index("workspace.css")
    assert base.index("workspace.css") < base.index("premium-interaction.css")
