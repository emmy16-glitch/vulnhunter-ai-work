from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnhunter.binary_analysis import BinaryAnalysisError, BinaryFormat, StaticBinaryAnalyzer


def test_static_binary_analyzer_hashes_without_execution(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.bin"
    artifact.write_bytes(
        b"\x7fELF" + b"\x00" * 14 + (62).to_bytes(2, "little") + b"/bin/sh\x00hello world"
    )

    result = StaticBinaryAnalyzer(authorized_root=tmp_path).analyze(Path("sample.bin"))

    assert result.format == BinaryFormat.ELF
    assert result.executed is False
    assert len(result.sha256) == 64
    assert any(item.signal_id == "shell-reference" for item in result.signals)


def test_static_binary_analyzer_rejects_escape_and_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"MZ")
    analyzer = StaticBinaryAnalyzer(authorized_root=tmp_path)

    with pytest.raises(BinaryAnalysisError, match="escapes"):
        analyzer.analyze(outside)

    link = tmp_path / "link.bin"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(BinaryAnalysisError, match="symbolic"):
        analyzer.analyze(link)
