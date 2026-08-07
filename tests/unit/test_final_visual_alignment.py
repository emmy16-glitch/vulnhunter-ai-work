from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "base.html"
CSS = ROOT / "vulnhunter" / "web" / "static" / "web" / "workspace.css"


def test_workspace_owner_loads_globally_once():
    base = BASE.read_text(encoding="utf-8")

    assert base.count("workspace.css") == 1
    assert "workspace-polish.css" not in base
    assert "workspace-final-fixes.css" not in base
    assert base.index("tokens.css") < base.index("workspace.css")


def test_workspace_status_cards_stack_label_and_value():
    css = CSS.read_text(encoding="utf-8")

    assert ".vh-state-card" in css
    assert "flex-direction: column" in css
    assert ".vh-state-card .vh-state-label" in css
    assert ".vh-state-card strong" in css


def test_inspector_copy_wraps_and_attack_path_action_is_visibly_enabled():
    css = CSS.read_text(encoding="utf-8")

    assert ".vh-inspector .vh-tool-identity small" in css
    assert "white-space: normal" in css
    assert "overflow-wrap: anywhere" in css
    assert ".vh-bottom-dock .vh-attack-path button" in css
    assert "background: var(--vh-final-brand)" in css
