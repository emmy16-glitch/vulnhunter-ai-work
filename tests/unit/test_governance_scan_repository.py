from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunter.observations.storage import ScanRepository


def test_get_scan_returns_one_persisted_scan(tmp_path: Path) -> None:
    repository = ScanRepository.from_path(tmp_path / "scans.db")
    repository.initialize()
    scan_id = repository.create_scan("http://127.0.0.1:8000/")

    scan = repository.get_scan(scan_id)

    assert scan.id == scan_id
    assert scan.status == "running"


def test_get_scan_rejects_missing_id(tmp_path: Path) -> None:
    repository = ScanRepository.from_path(tmp_path / "scans.db")
    repository.initialize()

    with pytest.raises(ValueError, match="does not exist"):
        repository.get_scan(99)
