from __future__ import annotations

import zipfile
from pathlib import Path

from vulnhunter.mobile.package_sets import reconstruct_package_set


def _apk(path: Path, *, package: str, split: str | None = None, native: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        split_attr = f' split="{split}"' if split else ""
        archive.writestr(
            "AndroidManifest.xml",
            f'<manifest package="{package}"{split_attr}/>'.encode(),
        )
        archive.writestr("classes.dex", b"dex\n035\x00" + b"x" * 128)
        if native:
            archive.writestr("lib/arm64-v8a/libsample.so", b"\x7fELF" + b"x" * 32)


def test_reconstructs_directory_package_set(tmp_path: Path) -> None:
    _apk(tmp_path / "base.apk", package="com.example.app", native=True)
    _apk(
        tmp_path / "split_config.arm64_v8a.apk", package="com.example.app", split="config.arm64_v8a"
    )

    result = reconstruct_package_set(tmp_path)

    assert result.package_name == "com.example.app"
    assert len(result.members) == 2
    assert result.supplied_split_names == ("config.arm64_v8a",)
    assert result.native_abis == ("arm64-v8a",)
    assert result.complete is True


def test_single_apk_is_explicitly_incomplete_for_package_reconstruction(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    _apk(apk, package="com.example.app")

    result = reconstruct_package_set(apk)

    assert result.source_kind.value == "apk"
    assert result.complete is False
    assert any("split APKs" in gap for gap in result.gaps)
