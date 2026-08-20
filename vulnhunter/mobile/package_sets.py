"""Read-only Android package-set reconstruction.

The package-set layer identifies all supplied application components before any
security conclusion is made. It does not install, execute, or contact packages.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.mobile.layered_analysis import _manifest_payload


class PackageSetKind(StrEnum):
    APK = "apk"
    AAB = "aab"
    APKS = "apks"
    APKM = "apkm"
    XAPK = "xapk"
    ZIP = "zip"
    DIRECTORY = "directory"


class PackageSetMember(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    kind: str
    sha256: str
    size_bytes: int = Field(ge=0)
    package_name: str | None = None
    split_name: str | None = None
    native_abis: tuple[str, ...] = ()
    dex_count: int = Field(default=0, ge=0)
    native_library_count: int = Field(default=0, ge=0)
    archive_entry_count: int = Field(default=0, ge=0)


class AndroidPackageSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    set_id: str
    source_filename: str
    source_kind: PackageSetKind
    source_sha256: str
    members: tuple[PackageSetMember, ...]
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    required_split_types: tuple[str, ...] = ()
    supplied_split_names: tuple[str, ...] = ()
    missing_split_types: tuple[str, ...] = ()
    native_abis: tuple[str, ...] = ()
    complete: bool = False
    gaps: tuple[str, ...] = ()


class PackageSetError(ValueError):
    """Raised when a package set cannot be reconstructed safely."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _kind(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".apk"):
        return "apk"
    if lower.endswith(".aab"):
        return "aab"
    if lower.endswith(".obb"):
        return "obb"
    if "/assetpacks/" in lower or lower.startswith("assetpacks/"):
        return "asset_pack"
    if lower.endswith(".dex"):
        return "dex"
    if lower.endswith(".so"):
        return "native_library"
    return "file"


def _apk_member(path: str, data: bytes) -> PackageSetMember:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PackageSetError(f"nested APK is not a valid ZIP: {path}") from exc
    manifest = {}
    dex_count = 0
    native_count = 0
    native_abis: set[str] = set()
    for info in archive.infolist():
        if info.filename == "AndroidManifest.xml" and info.file_size <= 2_000_000:
            manifest = _manifest_payload(archive.read(info))
        if info.filename.startswith("classes") and info.filename.endswith(".dex"):
            dex_count += 1
        parts = info.filename.split("/")
        if len(parts) == 3 and parts[0] == "lib" and info.filename.endswith(".so"):
            native_count += 1
            native_abis.add(parts[1])
    return PackageSetMember(
        path=path,
        kind="apk",
        sha256=_sha256(data),
        size_bytes=len(data),
        package_name=manifest.get("package_name"),
        split_name=manifest.get("split_name"),
        native_abis=tuple(sorted(native_abis)),
        dex_count=dex_count,
        native_library_count=native_count,
        archive_entry_count=len(archive.infolist()),
    )


def _collect_container(source_name: str, data: bytes) -> tuple[list[PackageSetMember], bytes]:
    members: list[PackageSetMember] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PackageSetError("package-set source is not a valid ZIP-compatible container") from exc
    for info in archive.infolist():
        if info.is_dir() or info.file_size > 1_500_000_000:
            continue
        lower = info.filename.lower()
        child = archive.read(info)
        if lower.endswith(".apk"):
            members.append(_apk_member(info.filename, child))
        elif lower.endswith(".obb"):
            members.append(
                PackageSetMember(
                    path=info.filename,
                    kind="obb",
                    sha256=_sha256(child),
                    size_bytes=len(child),
                )
            )
        elif lower.startswith("assetpacks/") or "/assetpacks/" in lower:
            members.append(
                PackageSetMember(
                    path=info.filename,
                    kind="asset_pack",
                    sha256=_sha256(child),
                    size_bytes=len(child),
                )
            )
    return members, data


def reconstruct_package_set(source: Path) -> AndroidPackageSet:
    candidate = source.expanduser().resolve(strict=True)
    if candidate.is_dir():
        source_kind = PackageSetKind.DIRECTORY
        source_data = b""
        paths: Iterable[Path] = sorted(item for item in candidate.rglob("*") if item.is_file())
        members: list[PackageSetMember] = []
        for item in paths:
            relative = item.relative_to(candidate).as_posix()
            data = item.read_bytes()
            if item.suffix.lower() == ".apk":
                members.append(_apk_member(relative, data))
            elif item.suffix.lower() == ".obb":
                members.append(
                    PackageSetMember(
                        path=relative, kind="obb", sha256=_sha256(data), size_bytes=len(data)
                    )
                )
        source_hash = hashlib.sha256(
            "".join(f"{item.path}:{item.sha256}" for item in members).encode()
        ).hexdigest()
        source_name = candidate.name
    else:
        data = candidate.read_bytes()
        suffix = candidate.suffix.lower().lstrip(".")
        source_kind = PackageSetKind(
            suffix if suffix in {item.value for item in PackageSetKind} else "zip"
        )
        if source_kind is PackageSetKind.APK:
            members = [_apk_member(candidate.name, data)]
        else:
            members, source_data = _collect_container(candidate.name, data)
        source_hash = _sha256(data)
        source_name = candidate.name
    if not members:
        raise PackageSetError("no Android APK members were found in the supplied package set")
    package_names = {item.package_name for item in members if item.package_name}
    package_name = sorted(package_names)[0] if package_names else None
    versions = [item for item in members if item.package_name == package_name]
    base = next(
        (item for item in versions if not item.split_name), versions[0] if versions else None
    )
    required_split_types: set[str] = set()
    supplied_split_names = {item.split_name for item in members if item.split_name}
    gaps: list[str] = []
    if base is not None:
        # The full required split metadata is recovered by layered manifest analysis;
        # this record still exposes whether the supplied set contains split members.
        if supplied_split_names:
            required_split_types.add("split_components_supplied")
    if len(package_names) > 1:
        gaps.append(
            "Package members contain multiple package identities; manual set selection is required."
        )
    if not any(item.split_name for item in members) and len(members) == 1:
        gaps.append("Only one package member was supplied; associated split APKs may be missing.")
    return AndroidPackageSet(
        set_id=f"pkgset-{source_hash[:24]}",
        source_filename=source_name,
        source_kind=source_kind,
        source_sha256=source_hash,
        members=tuple(members),
        package_name=package_name,
        version_name=None,
        version_code=None,
        required_split_types=tuple(sorted(required_split_types)),
        supplied_split_names=tuple(sorted(item for item in supplied_split_names if item)),
        missing_split_types=(),
        native_abis=tuple(sorted({abi for item in members for abi in item.native_abis})),
        complete=not gaps,
        gaps=tuple(gaps),
    )


__all__ = [
    "AndroidPackageSet",
    "PackageSetError",
    "PackageSetKind",
    "PackageSetMember",
    "reconstruct_package_set",
]
