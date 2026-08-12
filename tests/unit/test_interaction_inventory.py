from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "interaction_inventory.py"


def _module():
    spec = importlib.util.spec_from_file_location("interaction_inventory", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_interaction_inventory_is_measurable_and_repository_owned() -> None:
    inventory = _module().collect_inventory(ROOT)
    metrics = inventory["metrics"]

    assert metrics["css_files"] > 0
    assert metrics["js_files"] > 0
    assert metrics["transition_declarations"] + metrics["animation_declarations"] > 0
    assert metrics["reduced_motion_blocks"] > 0
    assert metrics["animation_frames"] > 0
    assert metrics["native_dialog_opens"] > 0
    assert metrics["loading_markers"] > 0
    assert metrics["progress_markers"] > 0


def test_interaction_inventory_keeps_one_canonical_shared_owner_stack() -> None:
    module = _module()
    inventory = module.collect_inventory(ROOT)

    assert module.validate_inventory(inventory) == []
    assert all(inventory["shell_owners"].values())
    assert inventory["forbidden_global_owners"] == []
    assert inventory["retired_loaded"] == []
    assert inventory["retired_present"] == []


def test_inventory_does_not_turn_static_counts_into_runtime_truth() -> None:
    inventory = _module().collect_inventory(ROOT)
    limitations = " ".join(inventory["limitations"]).lower()

    assert "not frame-time" in limitations
    assert "physical android" in limitations
    assert "talkback" in limitations
    assert "do not imply assessment progress" in limitations
