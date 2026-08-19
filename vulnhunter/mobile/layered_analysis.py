"""Evidence-first layered Android package analysis.

The analyzer is deliberately offline and read-only. It reconstructs the package
and its static attack-surface architecture from bytes; it never installs, loads,
or executes application code and never contacts discovered endpoints.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.mobile.models import MobileArtifactRecord

try:
    from androguard.core.axml import AXMLPrinter
    from loguru import logger as _androguard_logger
except ImportError:  # pragma: no cover - optional decoder in minimal deployments
    AXMLPrinter = None
    _androguard_logger = None

_URL = re.compile(r"(?i)\b(?:https?|wss?|mqtt|rtsp|rtmp|tcp|udp)://[^\s\"'<>\\]+")
_HOST = re.compile(
    r"(?i)(?<![a-z0-9-])(?=[a-z0-9.-]{3,253}(?::\d{1,5})?(?:/[^\s\"'<>\\]*)?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
    r"(?::\d{1,5})?(?:/[^\s\"'<>\\]*)?"
)
_ASCII = re.compile(rb"[ -~]{4,}")
_UTF16LE = re.compile(rb"(?:[ -~]\x00){4,}")
_CLASS = re.compile(r"L([A-Za-z0-9_$/.]{3,});")
_NATIVE_SYMBOL = re.compile(r"(?:Java_[A-Za-z0-9_]+|JNI_OnLoad|RegisterNatives)")
_KNOWN_TLDS = {
    "ai",
    "app",
    "biz",
    "ca",
    "cc",
    "cn",
    "cloud",
    "co",
    "com",
    "de",
    "dev",
    "eu",
    "fr",
    "in",
    "info",
    "io",
    "jp",
    "kr",
    "live",
    "me",
    "net",
    "online",
    "org",
    "pro",
    "ru",
    "sa",
    "shop",
    "site",
    "sg",
    "tech",
    "top",
    "tv",
    "uk",
    "us",
    "xyz",
}


class EvidenceConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high_confidence"
    LIKELY = "likely"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"
    DISPROVED = "disproved"


class LayerStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_RUN = "not_run"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


class LayeredEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    source: str
    tool: str
    artifact_sha256: str
    file: str | None = None
    class_name: str | None = None
    method: str | None = None
    offset: int | None = Field(default=None, ge=0)
    confidence: EvidenceConfidence
    verification_status: str = "observed"
    details: dict[str, object] = Field(default_factory=dict)


class PackageComponent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    component_id: str
    kind: str
    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    parent_path: str | None = None
    entries: int = Field(default=0, ge=0)
    native_abis: tuple[str, ...] = ()
    package_name: str | None = None


class DEXInventory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str
    size_bytes: int
    class_count: int
    method_count: int
    string_count: int
    namespaces: tuple[str, ...]
    first_party_namespaces: tuple[str, ...]
    third_party_namespaces: tuple[str, ...]
    obfuscation_score: float = Field(ge=0, le=1)
    magic_valid: bool


class NativeInventory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    sha256: str
    size_bytes: int
    architecture: str
    endianness: str
    elf_type: str
    pie: bool | None
    relro: bool | None
    nx: bool | None
    stripped: bool | None
    build_id: str | None = None
    soname: str | None = None
    dependencies: tuple[str, ...] = ()
    exports: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    jni_symbols: tuple[str, ...] = ()
    interesting_strings: tuple[str, ...] = ()


class NetworkEndpoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoint: str
    host: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str
    likely_role: str
    source_file: str
    source_offset: int | None = Field(default=None, ge=0)
    static_or_runtime: str = "static"
    confidence: EvidenceConfidence = EvidenceConfidence.CONFIRMED


class ArchitectureEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    target: str
    relation: str
    confidence: EvidenceConfidence
    evidence_ids: tuple[str, ...] = ()


class LayerSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    layer: str
    status: LayerStatus
    item_count: int = Field(ge=0)
    gaps: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()


class CompletenessScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    percentage: float = Field(ge=0, le=100)
    layers: tuple[LayerSummary, ...]


class LayeredStaticReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    generated_at: datetime
    artifact_id: str
    artifact_sha256: str
    filename: str
    file_type: str
    size_bytes: int
    sha1: str
    md5: str
    archive_entry_count: int
    duplicate_entries: tuple[str, ...] = ()
    unsafe_entries: tuple[str, ...] = ()
    encrypted_entries: tuple[str, ...] = ()
    magic_inventory: dict[str, int] = Field(default_factory=dict)
    package_components: tuple[PackageComponent, ...] = ()
    manifest: dict[str, object] = Field(default_factory=dict)
    resource_inventory: dict[str, int] = Field(default_factory=dict)
    dex_inventory: tuple[DEXInventory, ...] = ()
    native_inventory: tuple[NativeInventory, ...] = ()
    network_endpoints: tuple[NetworkEndpoint, ...] = ()
    observations: tuple[dict[str, object], ...] = ()
    evidence: tuple[LayeredEvidence, ...] = ()
    architecture_nodes: tuple[str, ...] = ()
    architecture_edges: tuple[ArchitectureEdge, ...] = ()
    completeness: CompletenessScore
    gaps: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()


class LayeredAnalysisError(RuntimeError):
    """Raised only when the bounded static report cannot be produced safely."""


def _hash_bytes(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def _clean(value: str) -> str:
    edge = "\\\"'`,;()[]{}<>"
    value = value.strip()
    while value and value[0] in edge:
        value = value[1:]
    while value and value[-1] in edge + ".,;":
        value = value[:-1]
    return value


def _printable(data: bytes) -> list[tuple[int, str]]:
    values: list[tuple[int, str]] = []
    for match in _ASCII.finditer(data):
        values.append((match.start(), match.group().decode("utf-8", "replace")))
    for match in _UTF16LE.finditer(data):
        values.append((match.start(), match.group()[::2].decode("utf-8", "replace")))
    return sorted(values, key=lambda item: item[0])


def _sha256_stream(handle: BinaryIO) -> tuple[str, str, str, int]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
    size = 0
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        size += len(chunk)
        for digest in digests.values():
            digest.update(chunk)
    return tuple(digests[name].hexdigest() for name in ("sha256", "sha1", "md5")) + (size,)


def _magic(data: bytes) -> str:
    if data.startswith(b"dex\n"):
        return "DEX"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    if data.startswith(b"SQLite format 3"):
        return "SQLite"
    if data.startswith(b"#!"):
        return "script"
    return "other"


def _manifest_payload(data: bytes) -> dict[str, object]:
    payload: dict[str, object] = {
        "parse_status": "text_xml" if data.lstrip().startswith(b"<") else "binary_android_xml",
    }
    xml_bytes = data
    if not data.lstrip().startswith(b"<"):
        if AXMLPrinter is None:
            payload["parse_status"] = "binary_decoder_unavailable"
            return payload
        try:
            if _androguard_logger is not None:
                _androguard_logger.disable("androguard")
            xml_bytes = AXMLPrinter(data).get_xml()
        except Exception as exc:
            payload["parse_status"] = f"binary_decode_failed:{type(exc).__name__}"
            return payload
        finally:
            if _androguard_logger is not None:
                _androguard_logger.enable("androguard")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        payload["parse_status"] = "xml_parse_failed"
        return payload
    android = "{http://schemas.android.com/apk/res/android}"
    payload["package_name"] = root.get("package")
    payload["version_code"] = root.get(f"{android}versionCode")
    payload["version_name"] = root.get(f"{android}versionName")
    payload["compile_sdk"] = root.get(f"{android}compileSdkVersion")
    payload["required_split_types"] = root.get(f"{android}requiredSplitTypes")
    payload["split_types"] = root.get(f"{android}splitTypes")
    payload["split_name"] = root.get("split") or root.get(f"{android}split")
    sdk = root.find("uses-sdk")
    payload["min_sdk"] = sdk.get(f"{android}minSdkVersion") if sdk is not None else None
    payload["target_sdk"] = sdk.get(f"{android}targetSdkVersion") if sdk is not None else None
    payload["permissions"] = sorted(
        item.get(f"{android}name")
        for item in root.findall("uses-permission")
        if item.get(f"{android}name")
    )
    payload["features"] = sorted(
        item.get(f"{android}name")
        for item in root.findall("uses-feature")
        if item.get(f"{android}name")
    )
    payload["queries"] = [
        {"tag": child.tag.rsplit("}", 1)[-1], "attributes": dict(child.attrib)}
        for queries in root.findall("queries")
        for child in list(queries)
    ]
    application = root.find("application")
    payload["application"] = dict(application.attrib) if application is not None else {}
    components: list[dict[str, object]] = []
    if application is not None:
        for component_type in ("activity", "activity-alias", "service", "receiver", "provider"):
            for component in application.findall(component_type):
                filters = []
                for intent_filter in component.findall("intent-filter"):
                    filters.append(
                        {
                            "actions": [
                                item.get(f"{android}name")
                                for item in intent_filter.findall("action")
                            ],
                            "categories": [
                                item.get(f"{android}name")
                                for item in intent_filter.findall("category")
                            ],
                            "data": [dict(item.attrib) for item in intent_filter.findall("data")],
                        }
                    )
                components.append(
                    {
                        "type": component_type,
                        "name": component.get(f"{android}name"),
                        "exported": component.get(f"{android}exported"),
                        "enabled": component.get(f"{android}enabled"),
                        "permission": component.get(f"{android}permission"),
                        "authority": component.get(f"{android}authorities"),
                        "process": component.get(f"{android}process"),
                        "direct_boot_aware": component.get(f"{android}directBootAware"),
                        "intent_filters": filters,
                    }
                )
    payload["components"] = components
    payload["deep_links"] = [
        {
            "component": item["name"],
            "filter": intent_filter,
        }
        for item in components
        for intent_filter in item["intent_filters"]
        if intent_filter["data"]
    ]
    return payload


def _role(endpoint: str) -> str:
    value = endpoint.lower()
    if any(term in value for term in ("login", "auth", "token", "oauth", "account", "password")):
        return "authentication"
    if any(term in value for term in ("pay", "order", "recharge", "card")):
        return "payment"
    if any(
        term in value for term in ("log", "statistic", "analytics", "buried", "crash", "report")
    ):
        return "telemetry_or_crash_reporting"
    if any(term in value for term in ("ad", "promotion", "mraid", "vungle", "doubleclick")):
        return "advertising"
    if any(term in value for term in ("update", "version", "download", "firmware")):
        return "update_or_firmware"
    if any(term in value for term in ("stream", "play", "media", "rtsp", "rtmp")):
        return "media"
    if any(term in value for term in ("mqtt", "socket", "ws://", "wss://")):
        return "messaging_or_signalling"
    if any(term in value for term in ("lan", "p2p", "relay", "stun", "turn", "device", "ipc")):
        return "device_or_p2p"
    return "api_or_unknown_backend"


def _host_port(endpoint: str) -> tuple[str | None, int | None]:
    value = endpoint.split("://", 1)[-1].split("/", 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return value, None


def _dex_inventory(
    path: str, data: bytes, artifact_sha256: str, package_name: str | None
) -> tuple[DEXInventory, list[LayeredEvidence]]:
    strings = _printable(data)
    namespace_values = set()
    for _, value in strings:
        for match in _CLASS.finditer(value):
            namespace = match.group(1).replace("/", ".")
            namespace_values.add(namespace.rsplit(".", 1)[0] if "." in namespace else namespace)
    namespaces = sorted(namespace_values)[:2000]
    first_party = tuple(
        item for item in namespaces if package_name and item.startswith(package_name)
    )
    third_party = tuple(item for item in namespaces if item not in first_party)
    short_names = sum(1 for item in namespaces if len(item.rsplit(".", 1)[-1]) <= 2)
    score = min(1.0, short_names / max(1, len(namespaces)))
    header = len(data) >= 0x70 and data.startswith(b"dex\n")
    class_count = struct.unpack_from("<I", data, 0x60)[0] if len(data) >= 0x64 else 0
    string_count = struct.unpack_from("<I", data, 0x38)[0] if len(data) >= 0x3C else len(strings)
    method_count = struct.unpack_from("<I", data, 0x58)[0] if len(data) >= 0x5C else 0
    evidence = [
        LayeredEvidence(
            evidence_id=f"dex-{hashlib.sha256(path.encode()).hexdigest()[:16]}",
            source="dex_header_and_string_table",
            tool="layered-static-analyzer",
            artifact_sha256=artifact_sha256,
            file=path,
            confidence=EvidenceConfidence.CONFIRMED,
            verification_status="observed",
            details={
                "class_count": class_count,
                "method_count": method_count,
                "string_count": string_count,
            },
        )
    ]
    return (
        DEXInventory(
            path=path,
            sha256=_hash_bytes(data, "sha256"),
            size_bytes=len(data),
            class_count=class_count,
            method_count=method_count,
            string_count=string_count,
            namespaces=tuple(namespaces),
            first_party_namespaces=first_party,
            third_party_namespaces=third_party,
            obfuscation_score=score,
            magic_valid=header,
        ),
        evidence,
    )


def _elf_inventory(path: str, data: bytes) -> NativeInventory:
    little = data[5] == 1 if len(data) >= 6 else True
    endian = "little" if little else "big"
    prefix = "<" if little else ">"
    elf_class = data[4] if len(data) >= 5 else 0
    machine = struct.unpack_from(prefix + "H", data, 18)[0] if len(data) >= 20 else 0
    machines = {3: "x86", 40: "ARM32", 62: "x86_64", 183: "ARM64", 243: "riscv64"}
    architecture = machines.get(machine, f"unknown_machine_{machine}")
    elf_type_value = struct.unpack_from(prefix + "H", data, 16)[0] if len(data) >= 18 else 0
    elf_type = {2: "ET_EXEC", 3: "ET_DYN"}.get(elf_type_value, f"ET_{elf_type_value}")
    pie = elf_type_value == 3
    relro = None
    nx = None
    phoff = (
        struct.unpack_from(
            prefix + ("Q" if elf_class == 2 else "I"), data, 32 if elf_class == 2 else 28
        )[0]
        if len(data) >= (40 if elf_class == 2 else 32)
        else 0
    )
    phentsize_offset = 54 if elf_class == 2 else 42
    phnum_offset = 56 if elf_class == 2 else 44
    phentsize = (
        struct.unpack_from(prefix + "H", data, phentsize_offset)[0]
        if len(data) >= phentsize_offset + 2
        else 0
    )
    phnum = (
        struct.unpack_from(prefix + "H", data, phnum_offset)[0]
        if len(data) >= phnum_offset + 2
        else 0
    )
    stack_executable = None
    for index in range(min(phnum, 256)):
        offset = phoff + index * phentsize
        if offset + 8 > len(data):
            break
        p_type = struct.unpack_from(prefix + "I", data, offset)[0]
        if elf_class == 2:
            flags = struct.unpack_from(prefix + "I", data, offset + 4)[0]
        else:
            flags = (
                struct.unpack_from(prefix + "I", data, offset + 24)[0]
                if offset + 28 <= len(data)
                else 0
            )
        if p_type == 0x6474E552:
            relro = True
        if p_type == 0x6474E551:
            stack_executable = bool(flags & 1)
    if stack_executable is not None:
        nx = not stack_executable
    strings = tuple(value for _, value in _printable(data) if len(value) >= 6)[:200]
    jni = tuple(
        sorted({match.group(0) for value in strings for match in _NATIVE_SYMBOL.finditer(value)})
    )
    return NativeInventory(
        path=path,
        sha256=_hash_bytes(data, "sha256"),
        size_bytes=len(data),
        architecture=architecture,
        endianness=endian,
        elf_type=elf_type,
        pie=pie,
        relro=relro,
        nx=nx,
        stripped=None,
        dependencies=(),
        exports=(),
        imports=(),
        jni_symbols=jni,
        interesting_strings=strings,
    )


def _entry_kind(name: str, data: bytes) -> str:
    lower = name.lower()
    magic = _magic(data)
    if lower.endswith(".apk") or magic == "ZIP":
        return "apk_or_zip"
    if lower.endswith(".dex") or magic == "DEX":
        return "dex"
    if lower.endswith(".so") or magic == "ELF":
        return "native_elf"
    if lower.endswith(".obb"):
        return "obb"
    if lower.startswith("assetpacks/"):
        return "asset_pack"
    return "file"


def _inspect_zip_bytes(
    path: str,
    data: bytes,
    artifact_sha256: str,
    package_name: str | None,
    *,
    parent: str | None = None,
) -> tuple[
    list[PackageComponent],
    list[DEXInventory],
    list[NativeInventory],
    list[NetworkEndpoint],
    list[LayeredEvidence],
    dict[str, int],
    list[str],
    list[str],
    list[str],
    dict[str, object],
    dict[str, int],
]:
    components: list[PackageComponent] = []
    dexes: list[DEXInventory] = []
    natives: list[NativeInventory] = []
    endpoints: list[NetworkEndpoint] = []
    evidence: list[LayeredEvidence] = []
    magic_counts: Counter[str] = Counter()
    duplicates: list[str] = []
    unsafe: list[str] = []
    encrypted: list[str] = []
    manifest: dict[str, object] = {"entry": None, "parse_status": "not_present"}
    resources: Counter[str] = Counter()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise LayeredAnalysisError(f"{path} is not a valid ZIP container") from exc
    infos = archive.infolist()
    resolved_package_name = package_name
    for manifest_info in infos:
        if manifest_info.filename == "AndroidManifest.xml" and manifest_info.file_size <= 2_000_000:
            manifest_bytes = archive.read(manifest_info)
            match = re.search(rb"package\s*=\s*['\"]([^'\"]+)", manifest_bytes)
            if match is not None:
                resolved_package_name = match.group(1).decode("utf-8", "replace")
            break
    seen: set[str] = set()
    for info in infos:
        if info.filename in seen:
            duplicates.append(info.filename)
        seen.add(info.filename)
        pure = PurePosixPath(info.filename)
        if pure.is_absolute() or ".." in pure.parts or "\x00" in info.filename:
            unsafe.append(info.filename)
        if info.flag_bits & 1:
            encrypted.append(info.filename)
        entry_data = (
            archive.read(info) if not info.is_dir() and info.file_size <= 100_000_000 else b""
        )
        magic_counts[_magic(entry_data)] += 1
        lower_name = info.filename.lower()
        if lower_name == "resources.arsc":
            resources["resources.arsc"] += 1
        elif lower_name.startswith("res/"):
            resources["res"] += 1
        elif lower_name.startswith("assets/"):
            resources["assets"] += 1
        elif lower_name.endswith((".json", ".xml", ".html", ".js", ".proto", ".db", ".sqlite")):
            resources["configuration_or_data"] += 1
        if info.filename == "AndroidManifest.xml":
            manifest = _manifest_payload(entry_data)
            manifest["entry"] = info.filename
            manifest["magic"] = _magic(entry_data)
            manifest["size_bytes"] = info.file_size
            if resolved_package_name:
                manifest["package_name"] = resolved_package_name
        if info.filename.startswith("classes") and info.filename.endswith(".dex") and entry_data:
            dex, dex_evidence = _dex_inventory(
                info.filename, entry_data, artifact_sha256, resolved_package_name
            )
            dexes.append(dex)
            evidence.extend(dex_evidence)
        if (
            info.filename.startswith("lib/") or info.filename.endswith(".so")
        ) and entry_data.startswith(b"\x7fELF"):
            natives.append(_elf_inventory(info.filename, entry_data))
        if entry_data:
            for offset, value in _printable(entry_data):
                for match in _URL.finditer(value):
                    endpoint = _clean(match.group(0))
                    host, port = _host_port(endpoint)
                    protocol = endpoint.split(":", 1)[0].lower()
                    endpoints.append(
                        NetworkEndpoint(
                            endpoint=endpoint,
                            host=host,
                            port=port,
                            protocol=protocol,
                            likely_role=_role(endpoint),
                            source_file=info.filename,
                            source_offset=offset + match.start(),
                        )
                    )
        if info.filename.endswith(".apk") and entry_data and entry_data != data:
            nested = _inspect_zip_bytes(
                info.filename,
                entry_data,
                artifact_sha256,
                resolved_package_name,
                parent=path,
            )
            components.extend(nested[0])
            dexes.extend(nested[1])
            natives.extend(nested[2])
            endpoints.extend(nested[3])
            evidence.extend(nested[4])
            magic_counts.update(nested[5])
            duplicates.extend(nested[6])
            unsafe.extend(nested[7])
            encrypted.extend(nested[8])
            resources.update(nested[10])
            if manifest["entry"] is None and nested[9].get("entry") is not None:
                manifest = nested[9]
    components.append(
        PackageComponent(
            component_id=f"container-{hashlib.sha256(path.encode()).hexdigest()[:16]}",
            kind="package_container",
            path=path,
            sha256=_hash_bytes(data, "sha256"),
            size_bytes=len(data),
            parent_path=parent,
            entries=len(infos),
            native_abis=tuple(
                sorted(
                    {
                        item.path.split("/")[1]
                        for item in natives
                        if item.path.startswith("lib/") and len(item.path.split("/")) > 1
                    }
                )
            ),
            package_name=resolved_package_name,
        )
    )
    return (
        components,
        dexes,
        natives,
        endpoints,
        evidence,
        dict(magic_counts),
        duplicates,
        unsafe,
        encrypted,
        manifest,
        dict(resources),
    )


def _security_observations(
    dexes: list[DEXInventory],
    natives: list[NativeInventory],
    endpoints: list[NetworkEndpoint],
    artifact_sha256: str,
    manifest: dict[str, object] | None = None,
) -> tuple[tuple[dict[str, object], ...], tuple[LayeredEvidence, ...]]:
    observations: list[dict[str, object]] = []
    evidence: list[LayeredEvidence] = []
    patterns = {
        "crypto": re.compile(
            r"(?i)(aes|des|rsa|ecdh|curve25519|ed25519|chacha|poly1305|sha-?1|sha-?256|sha-?512|md5|hmac|pbkdf2|hkdf|keystore|trustmanager|certificatepinner)"
        ),
        "webview": re.compile(
            r"(?i)(webview|addjavascriptinterface|setjavascriptenabled|loadurl|evaluatejavascript|shouldoverrideurlloading)"
        ),
        "dynamic_loading": re.compile(
            r"(?i)(dexclassloader|pathclassloader|inmemorydexclassloader|system\.load|system\.loadlibrary|class\.forname)"
        ),
        "reflection": re.compile(
            r"(?i)(getdeclaredmethod|getmethod|method\.invoke|constructor\.newinstance|field\.set)"
        ),
        "storage": re.compile(
            r"(?i)(sharedpreferences|sqlite|room|realm|externalstorage|keychain|clipboard|webview.*cookie)"
        ),
        "anti_analysis": re.compile(
            r"(?i)(debug\.isdebuggerconnected|tracerpid|ptrace|qemu|magisk|frida|xposed|rootcheck|/proc/self/status)"
        ),
        "ipc_and_components": re.compile(
            r"(?i)(pendingintent|contentprovider|broadcastreceiver|bindservice|binder|aidl|fileprovider|exported)"
        ),
        "p2p_and_media": re.compile(
            r"(?i)(stun|turn|ice|p2p|relay|udp|rtsp|rtmp|mqtt|websocket|stream|lan|device)"
        ),
    }
    for dex in dexes:
        for category, pattern in patterns.items():
            matches = [
                item
                for item in dex.third_party_namespaces + dex.first_party_namespaces
                if pattern.search(item)
            ]
            if matches:
                evidence_id = (
                    f"obs-{hashlib.sha256(f'{dex.path}:{category}'.encode()).hexdigest()[:16]}"
                )
                evidence.append(
                    LayeredEvidence(
                        evidence_id=evidence_id,
                        source="dex_namespace_inventory",
                        tool="layered-static-analyzer",
                        artifact_sha256=artifact_sha256,
                        file=dex.path,
                        confidence=EvidenceConfidence.CANDIDATE,
                        verification_status="observed",
                        details={"category": category, "matches": matches[:50]},
                    )
                )
                observations.append(
                    {
                        "observation_id": evidence_id,
                        "category": category,
                        "status": "candidate",
                        "confidence": EvidenceConfidence.CANDIDATE.value,
                        "component": dex.path,
                        "matches": matches[:50],
                    }
                )
    if manifest and manifest.get("entry"):
        components = [item for item in manifest.get("components", ()) if isinstance(item, dict)]
        exported = [item for item in components if item.get("exported") == "true"]
        deep_links = manifest.get("deep_links", ())
        evidence_id = "manifest-attack-surface"
        evidence.append(
            LayeredEvidence(
                evidence_id=evidence_id,
                source="normalized_android_manifest",
                tool="layered-static-analyzer",
                artifact_sha256=artifact_sha256,
                file=str(manifest.get("entry")),
                confidence=EvidenceConfidence.CONFIRMED,
                verification_status="observed",
                details={
                    "component_count": len(components),
                    "exported_count": len(exported),
                    "deep_link_count": len(deep_links),
                    "permission_count": len(manifest.get("permissions", ())),
                },
            )
        )
        observations.append(
            {
                "observation_id": evidence_id,
                "category": "android_attack_surface",
                "status": "observed",
                "confidence": EvidenceConfidence.CONFIRMED.value,
                "exported_components": exported[:200],
                "deep_links": list(deep_links)[:200],
                "permissions": list(manifest.get("permissions", ()))[:500],
            }
        )
    if endpoints:
        observations.append(
            {
                "observation_id": "network-static-inventory",
                "category": "network_static",
                "status": "observed",
                "confidence": EvidenceConfidence.CONFIRMED.value,
                "endpoint_count": len(endpoints),
                "note": (
                    "Embedded URI literals are static indicators and do not prove runtime contact."
                ),
            }
        )
    if natives:
        observations.append(
            {
                "observation_id": "native-elf-inventory",
                "category": "native_inventory",
                "status": "observed",
                "confidence": EvidenceConfidence.CONFIRMED.value,
                "library_count": len(natives),
                "architectures": sorted({item.architecture for item in natives}),
            }
        )
    return tuple(observations), tuple(evidence)


def analyze_package(
    path: Path, *, artifact: MobileArtifactRecord | None = None
) -> LayeredStaticReport:
    resolved = path.expanduser().resolve(strict=True)
    with resolved.open("rb") as handle:
        sha256, sha1, md5, size = _sha256_stream(handle)
    if artifact is not None and sha256 != artifact.sha256:
        raise LayeredAnalysisError("analysis input digest does not match the ingested artifact")
    package_name = None
    if artifact is not None:
        package_name = None
    data = resolved.read_bytes()
    file_type = _entry_kind(resolved.name, data)
    if file_type == "apk_or_zip":
        (
            components,
            dexes,
            natives,
            endpoints,
            evidence,
            magic,
            duplicates,
            unsafe,
            encrypted,
            manifest,
            resources,
        ) = _inspect_zip_bytes(resolved.name, data, sha256, package_name)
    else:
        components = [
            PackageComponent(
                component_id=f"file-{sha256[:16]}",
                kind=file_type,
                path=resolved.name,
                sha256=sha256,
                size_bytes=size,
            )
        ]
        dexes = []
        natives = [_elf_inventory(resolved.name, data)] if file_type == "native_elf" else []
        endpoints = []
        evidence = []
        magic = {_magic(data): 1}
        duplicates = []
        unsafe = []
        encrypted = []
        manifest = {"entry": None, "parse_status": "not_applicable"}
        resources = {}
    observations, additional_evidence = _security_observations(
        dexes, natives, endpoints, sha256, manifest
    )
    evidence.extend(additional_evidence)
    nodes = [f"artifact:{sha256}"]
    edges: list[ArchitectureEdge] = []
    for component in components:
        node = f"component:{component.path}"
        nodes.append(node)
        edges.append(
            ArchitectureEdge(
                source=nodes[0],
                target=node,
                relation="contains_component",
                confidence=EvidenceConfidence.CONFIRMED,
            )
        )
    for dex in dexes:
        node = f"dex:{dex.path}"
        nodes.append(node)
        edges.append(
            ArchitectureEdge(
                source=nodes[0],
                target=node,
                relation="contains_dex",
                confidence=EvidenceConfidence.CONFIRMED,
            )
        )
    for native in natives:
        node = f"native:{native.path}"
        nodes.append(node)
        edges.append(
            ArchitectureEdge(
                source=nodes[0],
                target=node,
                relation="contains_native_library",
                confidence=EvidenceConfidence.CONFIRMED,
            )
        )
        for dependency in native.dependencies:
            edges.append(
                ArchitectureEdge(
                    source=node,
                    target=f"native:{dependency}",
                    relation="depends_on",
                    confidence=EvidenceConfidence.LIKELY,
                )
            )
    for endpoint in sorted({item.endpoint for item in endpoints}):
        node = f"endpoint:{endpoint}"
        nodes.append(node)
        edges.append(
            ArchitectureEdge(
                source=nodes[0],
                target=node,
                relation="declares_endpoint",
                confidence=EvidenceConfidence.CONFIRMED,
                evidence_ids=("network-static-inventory",),
            )
        )
    layer_items = {
        "artifact_identity": 1,
        "container_reconstruction": len(components),
        "manifest": 1 if manifest.get("entry") else 0,
        "resources": sum(resources.values()),
        "dex": len(dexes),
        "native": len(natives),
        "network_static": len(endpoints),
        "crypto_static": sum(item["category"] == "crypto" for item in observations),
        "android_attack_surface": sum(
            item["category"] == "ipc_and_components" for item in observations
        ),
        "runtime": 0,
    }
    layer_status = []
    for layer, count in layer_items.items():
        if (
            layer == "container_reconstruction"
            and manifest.get("required_split_types")
            and len(components) <= 1
        ):
            status = LayerStatus.PARTIAL
            gaps = (
                "The manifest declares required split types, but no associated split package "
                "was supplied.",
            )
            next_actions = (
                "Ingest the complete base-plus-split package set before final native/package "
                "claims.",
            )
        elif layer == "runtime":
            status = LayerStatus.BLOCKED
            gaps = ("No approved disposable Android runtime was available during this analysis.",)
            next_actions = (
                "Provision and register a disposable emulator, then issue exact artifact-bound "
                "approval.",
            )
        elif count > 0 and layer in {"resources", "crypto_static", "android_attack_surface"}:
            status = LayerStatus.PARTIAL
            gaps = (
                "Static indicator coverage exists; method-level reachability and runtime "
                "validation remain unresolved.",
            )
            next_actions = (
                "Run targeted decompiler, call-graph, and evidence verification passes.",
            )
        elif count > 0:
            status = LayerStatus.COMPLETE
            gaps = ()
            next_actions = ()
        else:
            status = LayerStatus.UNAVAILABLE
            gaps = (
                f"No {layer.replace('_', ' ')} evidence was available in the supplied package.",
            )
            next_actions = (
                "Add or reconstruct package components needed for "
                f"{layer.replace('_', ' ')} analysis.",
            )
        layer_status.append(
            LayerSummary(
                layer=layer, status=status, item_count=count, gaps=gaps, next_actions=next_actions
            )
        )
    complete = sum(item.status == LayerStatus.COMPLETE for item in layer_status)
    percentage = round(complete / max(1, len(layer_status)) * 100, 2)
    gaps = tuple(gap for item in layer_status for gap in item.gaps)
    next_actions = tuple(
        dict.fromkeys(action for item in layer_status for action in item.next_actions)
    )
    return LayeredStaticReport(
        generated_at=datetime.now(UTC),
        artifact_id=artifact.artifact_id if artifact is not None else f"file-{sha256[:24]}",
        artifact_sha256=sha256,
        filename=resolved.name,
        file_type=file_type,
        size_bytes=size,
        sha1=sha1,
        md5=md5,
        archive_entry_count=sum(item.entries for item in components),
        duplicate_entries=tuple(sorted(set(duplicates))),
        unsafe_entries=tuple(sorted(set(unsafe))),
        encrypted_entries=tuple(sorted(set(encrypted))),
        magic_inventory=magic,
        package_components=tuple(components),
        manifest=manifest,
        resource_inventory=resources,
        dex_inventory=tuple(dexes),
        native_inventory=tuple(natives),
        network_endpoints=tuple(
            sorted(
                {item.endpoint: item for item in endpoints}.values(),
                key=lambda item: (item.endpoint, item.source_file, item.source_offset or 0),
            )
        ),
        observations=observations,
        evidence=tuple(evidence),
        architecture_nodes=tuple(dict.fromkeys(nodes)),
        architecture_edges=tuple(edges),
        completeness=CompletenessScore(percentage=percentage, layers=tuple(layer_status)),
        gaps=tuple(dict.fromkeys(gaps)),
        next_actions=next_actions,
    )


__all__ = [
    "ArchitectureEdge",
    "CompletenessScore",
    "DEXInventory",
    "EvidenceConfidence",
    "LayeredAnalysisError",
    "LayeredEvidence",
    "LayeredStaticReport",
    "LayerStatus",
    "NativeInventory",
    "NetworkEndpoint",
    "PackageComponent",
    "analyze_package",
]
