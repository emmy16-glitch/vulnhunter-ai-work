from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate_total_programme_coverage.py"
ROADMAP = ROOT / "docs" / "intelligence" / "VULNHUNTER_FUTURE_MASTER_PLAN.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("total_programme_coverage", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_canonical_roadmap_has_complete_explicit_coverage() -> None:
    generator = _load_generator()

    requirements = generator.parse_requirements(ROADMAP)
    rendered = generator.render(ROADMAP.relative_to(ROOT), requirements)

    assert len(requirements) == 608
    assert len({item.section for item in requirements if item.section}) == 26
    assert sum(item.phase is not None for item in requirements) == 25
    assert all(
        generator.meta_for(item).classification in generator.ALLOWED_CLASSIFICATIONS
        for item in requirements
    )
    assert "- UNMAPPED: `0`" in rendered
    assert "- Transition gate: `PASS`" in rendered


def test_graphify_order_and_exclusions_remain_explicit() -> None:
    generator = _load_generator()
    requirements = generator.parse_requirements(ROADMAP)

    graphify = [item for item in requirements if item.section == 16]
    capabilities = "\n".join(item.capability for item in graphify)
    assert capabilities.index("Graphify CLI adapter first") < capabilities.index("Learning period")
    assert capabilities.index("Learning period") < capabilities.index(
        "Build the VulnHunter-native graph"
    )
    assert capabilities.index("Build the VulnHunter-native graph") < capabilities.index(
        "Restricted MCP service"
    )

    exclusions = [item for item in requirements if item.section == 24]
    assert exclusions
    assert all(
        generator.meta_for(item).classification == "INTENTIONALLY_EXCLUDED" for item in exclusions
    )
