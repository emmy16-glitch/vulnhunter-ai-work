import importlib.util
from pathlib import Path

import pytest


def _module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/nuclei_readiness.py"
    spec = importlib.util.spec_from_file_location("nuclei_readiness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "output",
    (
        "[INF] Current nuclei version: v3.8.0 (latest)",
        "[INF] Nuclei Engine Version: v3.8.0",
        "Nuclei Engine Version: 3.8.0",
    ),
)
def test_official_nuclei_380_version_output_matches_exact_pin(output):
    module = _module()

    assert module.EXPECTED_ENGINE == "v3.8.0"
    assert module._version_matches(module.EXPECTED_ENGINE, output) is True


@pytest.mark.parametrize(
    "output",
    (
        "[INF] Nuclei Engine Version: v3.8.1",
        "[INF] Nuclei Engine Version: v13.8.0",
        "[INF] Nuclei Engine Version: v3.8.0-unofficial",
    ),
)
def test_nuclei_version_parser_rejects_non_exact_engine_versions(output):
    module = _module()

    assert module._version_matches(module.EXPECTED_ENGINE, output) is False
