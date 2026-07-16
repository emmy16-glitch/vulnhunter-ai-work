import importlib.util
from pathlib import Path

import pytest


def _module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/validate_scanner_compatibility.py"
    spec = importlib.util.spec_from_file_location("validate_scanner_compatibility", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scanner_compatibility_validation_matches_documentation():
    root = Path(__file__).resolve().parents[2]

    fingerprint = _module().validate(root)

    assert len(fingerprint) == 64


def test_scanner_compatibility_validation_rejects_stale_document(tmp_path):
    source = Path(__file__).resolve().parents[2]
    root = tmp_path / "repository"
    (root / "config/security_tools").mkdir(parents=True)
    (root / "docs/product").mkdir(parents=True)

    for relative in (
        "config/security_tools/scanner_compatibility.json",
        "config/security_tools/runtime.json",
        "config/security_tools/nuclei_template_manifest.json",
        "docs/product/SCANNER_COMPATIBILITY.md",
    ):
        destination = root / relative
        destination.write_bytes((source / relative).read_bytes())

    document = root / "docs/product/SCANNER_COMPATIBILITY.md"
    document.write_text(
        document.read_text(encoding="utf-8").replace("v3.11.0", "v9.9.9"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="documentation is stale"):
        _module().validate(root)
