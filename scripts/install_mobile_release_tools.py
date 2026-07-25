#!/usr/bin/env python3
"""Install pinned mobile-analysis release assets into a private tool root.

GitHub release metadata supplies the asset URL and SHA-256 digest. Ghidra is
also checked against the digest published in the official release notes.
Archives are extracted without path traversal or out-of-root symbolic links.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

JADX_VERSION = "1.5.5"
RADARE2_VERSION = "6.1.4"
GHIDRA_VERSION = "12.1"
GHIDRA_SHA256 = "aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302"
_MAX_ARCHIVE_BYTES = 2_500_000_000
_MAX_EXTRACTED_BYTES = 6_000_000_000


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    sha256: str
    size: int


def _request_json(url: str) -> dict[str, object]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VulnHunter-Codespaces-Installer/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"release metadata is unavailable: {url}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("release metadata is not a JSON object")
    return payload


def _asset(owner: str, repository: str, tag: str, predicate) -> ReleaseAsset:
    payload = _request_json(
        f"https://api.github.com/repos/{owner}/{repository}/releases/tags/{tag}"
    )
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("release metadata contains no assets")
    for raw in assets:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        if not predicate(name):
            continue
        digest = str(raw.get("digest") or "")
        if not digest.startswith("sha256:"):
            raise RuntimeError(f"release asset {name} has no SHA-256 digest")
        url = str(raw.get("browser_download_url") or "")
        size = int(raw.get("size") or 0)
        if not url.startswith("https://github.com/"):
            raise RuntimeError(f"release asset {name} has an unsafe URL")
        if not 0 < size <= _MAX_ARCHIVE_BYTES:
            raise RuntimeError(f"release asset {name} has an unsafe size")
        return ReleaseAsset(
            name=name,
            url=url,
            sha256=digest.removeprefix("sha256:"),
            size=size,
        )
    raise RuntimeError(f"no matching release asset found for {repository} {tag}")


def _download(
    asset: ReleaseAsset,
    cache: Path,
    *,
    expected: str | None = None,
) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / asset.name
    expected_digest = expected or asset.sha256
    if expected and asset.sha256 != expected:
        raise RuntimeError(f"GitHub digest for {asset.name} disagrees with the pinned digest")
    if destination.is_file() and _sha256(destination) == expected_digest:
        return destination
    destination.unlink(missing_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{asset.name}.",
        dir=cache,
    )
    temporary = Path(temporary_name)
    os.close(descriptor)
    request = urllib.request.Request(
        asset.url,
        headers={"User-Agent": "VulnHunter-Codespaces-Installer/1.0"},
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=120) as response,
            temporary.open("wb") as target,
        ):
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > asset.size or total > _MAX_ARCHIVE_BYTES:
                    raise RuntimeError(f"downloaded asset {asset.name} exceeded its declared size")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if total != asset.size or digest.hexdigest() != expected_digest:
            raise RuntimeError(f"release asset verification failed for {asset.name}")
        os.replace(temporary, destination)
        destination.chmod(0o600)
        return destination
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_extract_zip(archive: Path, destination: Path) -> Path:
    if destination.exists():
        return destination
    temporary = destination.with_name(f".{destination.name}.extracting")
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True, mode=0o700)
    total = 0
    try:
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                pure = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if pure.is_absolute() or ".." in pure.parts or stat.S_ISLNK(mode):
                    raise RuntimeError(f"unsafe archive entry in {archive.name}")
                total += max(0, info.file_size)
                if total > _MAX_EXTRACTED_BYTES:
                    raise RuntimeError(f"archive {archive.name} exceeds the extraction boundary")
                target = temporary.joinpath(*pure.parts)
                if info.is_dir():
                    target.mkdir(parents=True, mode=0o700, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with (
                    bundle.open(info) as source,
                    os.fdopen(
                        descriptor,
                        "wb",
                    ) as output,
                ):
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if mode & 0o111:
                    target.chmod(0o700)
        os.replace(temporary, destination)
        return destination
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _validate_extracted_tree(root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    total = 0
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = path.resolve(strict=True)
                target.relative_to(resolved_root)
            except (OSError, ValueError) as exc:
                raise RuntimeError("package link escapes the extraction root") from exc
            continue
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("package contains an unsupported special file")
        total += metadata.st_size
        if total > _MAX_EXTRACTED_BYTES:
            raise RuntimeError("package exceeds the extraction boundary")


def _extract_deb(archive: Path, destination: Path) -> Path:
    if destination.exists():
        _validate_extracted_tree(destination)
        return destination
    temporary = destination.with_name(f".{destination.name}.extracting")
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True, mode=0o700)
    try:
        subprocess.run(
            ("dpkg-deb", "--extract", str(archive), str(temporary)),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=180,
        )
        _validate_extracted_tree(temporary)
        os.replace(temporary, destination)
        return destination
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _single_child(path: Path) -> Path:
    children = [item for item in path.iterdir() if item.name != "__MACOSX"]
    return children[0] if len(children) == 1 and children[0].is_dir() else path


def _link(link: Path, target: Path, *, tool_root: Path) -> None:
    resolved_root = tool_root.resolve(strict=True)
    resolved = target.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise RuntimeError(f"tool executable escapes its release root: {target}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"tool executable is unavailable: {target}")
    link.parent.mkdir(parents=True, exist_ok=True)
    temporary = link.with_name(f".{link.name}.new")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(resolved)
    os.replace(temporary, link)


def install(root: Path, *, include_ghidra: bool) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    cache = root / "downloads"
    bin_root = Path.home() / ".local" / "bin"
    installed: dict[str, str] = {}

    jadx_asset = _asset(
        "skylot",
        "jadx",
        f"v{JADX_VERSION}",
        lambda name: name == f"jadx-{JADX_VERSION}.zip",
    )
    jadx_archive = _download(jadx_asset, cache)
    jadx_release = _safe_extract_zip(
        jadx_archive,
        root / f"jadx-{JADX_VERSION}",
    )
    jadx_bundle = _single_child(jadx_release)
    jadx = jadx_bundle / "bin" / "jadx"
    jadx.chmod(jadx.stat().st_mode | 0o100)
    _link(bin_root / "jadx", jadx, tool_root=jadx_release)
    installed["jadx"] = str(jadx.resolve())

    machine = platform.machine().casefold()
    if machine in {"x86_64", "amd64"}:
        architecture = "amd64"
    elif machine in {"aarch64", "arm64"}:
        architecture = "arm64"
    else:
        raise RuntimeError(f"unsupported Radare2 architecture: {machine}")
    radare_asset = _asset(
        "radareorg",
        "radare2",
        RADARE2_VERSION,
        lambda name: name == f"radare2_{RADARE2_VERSION}_{architecture}.deb",
    )
    radare_archive = _download(radare_asset, cache)
    radare_root = _extract_deb(
        radare_archive,
        root / f"radare2-{RADARE2_VERSION}-{architecture}",
    )
    rabin2 = radare_root / "usr" / "bin" / "rabin2"
    _link(bin_root / "rabin2", rabin2, tool_root=radare_root)
    installed["radare2"] = str(rabin2.resolve())

    if include_ghidra:
        ghidra_asset = _asset(
            "NationalSecurityAgency",
            "ghidra",
            f"Ghidra_{GHIDRA_VERSION}_build",
            lambda name: (
                name.startswith(f"ghidra_{GHIDRA_VERSION}_PUBLIC_") and name.endswith(".zip")
            ),
        )
        ghidra_archive = _download(
            ghidra_asset,
            cache,
            expected=GHIDRA_SHA256,
        )
        ghidra_release = _safe_extract_zip(
            ghidra_archive,
            root / f"ghidra-{GHIDRA_VERSION}",
        )
        ghidra_root = _single_child(ghidra_release)
        headless = ghidra_root / "support" / "analyzeHeadless"
        headless.chmod(headless.stat().st_mode | 0o100)
        _link(
            bin_root / "analyzeHeadless",
            headless,
            tool_root=ghidra_release,
        )
        installed["ghidra"] = str(headless.resolve())

    return installed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--without-ghidra", action="store_true")
    args = parser.parse_args()
    try:
        installed = install(
            args.root.expanduser().resolve(),
            include_ghidra=not args.without_ghidra,
        )
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        urllib.error.URLError,
        zipfile.BadZipFile,
    ) as exc:
        print(
            f"Mobile release tool installation failed closed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    for name, path in installed.items():
        print(f"Installed {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
