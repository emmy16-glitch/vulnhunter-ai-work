"""Built-in registry for free security assessment and Android analysis tools."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from vulnhunter.actions.models import ActionClass
from vulnhunter.security_tools.models import (
    SecurityToolDefinition,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolProfile,
    ToolTargetKind,
)

_VERSION_PROBES: dict[str, tuple[str, ...]] = {
    "nmap": ("--version",),
    "httpx": ("--version",),
    "nuclei": ("-version",),
    "ffuf": ("-V",),
    "testssl": ("--version",),
    "trivy": ("--version",),
    "bearer": ("--version",),
    "bandit": ("--version",),
    "detect-secrets": ("--version",),
    "gitleaks": ("version",),
    "syft": ("version",),
    "grype": ("version",),
    "osv-scanner": ("--version",),
    "capa": ("--version",),
    "apksigner": ("--version",),
    "aapt2": ("version",),
    "apktool": ("--version",),
    "jadx": ("--version",),
    "apkid": ("--version",),
    "yara": ("--version",),
    "radare2": ("-v",),
    "adb": ("version",),
    "frida": ("--version",),
    "metasploit": ("--version",),
}

_PROBE_TIMEOUTS = {
    "bandit": 60,
    "detect-secrets": 60,
    "testssl": 60,
    "capa": 60,
    "jadx": 45,
    "apktool": 45,
}

# Version probes can be CPU-heavy during interpreter or ruleset startup.  The
# supported deployment VM has two cores, and higher fan-out caused healthy
# tools to exceed their bounded process timeouts.  Keep one authoritative,
# deliberately small cap for every bulk readiness path.
_MAX_READINESS_PROBE_WORKERS = 2

_ProbeInput = TypeVar("_ProbeInput")
_ProbeResult = TypeVar("_ProbeResult")


def readiness_probe_worker_count(item_count: int) -> int:
    """Return a non-zero, CPU-aware worker count capped for readiness safety."""
    if item_count < 0:
        raise ValueError("item_count must not be negative")
    cpu_count = os.cpu_count() or 1
    return max(1, min(item_count or 1, cpu_count, _MAX_READINESS_PROBE_WORKERS))


def run_ordered_readiness_probes(
    items: Iterable[_ProbeInput],
    probe: Callable[[_ProbeInput], _ProbeResult],
) -> tuple[_ProbeResult, ...]:
    """Run bulk probes with the shared limit while preserving input order."""
    ordered_items = tuple(items)
    if not ordered_items:
        return ()
    with ThreadPoolExecutor(max_workers=readiness_probe_worker_count(len(ordered_items))) as pool:
        return tuple(pool.map(probe, ordered_items))


def _probe_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    return {key: os.environ[key] for key in allowed if key in os.environ}


class SecurityToolCatalogError(ValueError):
    pass


class SecurityToolCatalog:
    def __init__(self, definitions: Iterable[SecurityToolDefinition]) -> None:
        self._definitions: dict[str, SecurityToolDefinition] = {}
        for definition in definitions:
            if definition.tool_id in self._definitions:
                raise SecurityToolCatalogError(f"Duplicate security tool: {definition.tool_id}")
            self._definitions[definition.tool_id] = definition

    def get(self, tool_id: str) -> SecurityToolDefinition:
        try:
            return self._definitions[tool_id]
        except KeyError as exc:
            raise SecurityToolCatalogError(f"Unknown security tool: {tool_id}") from exc

    def list(self) -> tuple[SecurityToolDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))

    def detect(self, tool_id: str) -> ToolAvailability:
        definition = self.get(tool_id)
        executable_path = None
        for candidate in definition.executable_candidates:
            executable_path = shutil.which(candidate)
            if executable_path:
                break
        if executable_path is None:
            return ToolAvailability(
                tool_id=tool_id,
                available=False,
                usable=False,
                status=ToolAvailabilityStatus.NOT_DETECTED,
            )

        probe = _VERSION_PROBES.get(tool_id)
        if probe is None:
            return ToolAvailability(
                tool_id=tool_id,
                available=True,
                usable=True,
                status=ToolAvailabilityStatus.DETECTED_UNVERIFIED,
                executable_path=executable_path,
            )

        timeout = _PROBE_TIMEOUTS.get(tool_id, 20)
        try:
            completed = subprocess.run(
                (executable_path, *probe),
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=_probe_environment(),
            )
        except subprocess.TimeoutExpired:
            return ToolAvailability(
                tool_id=tool_id,
                available=True,
                usable=False,
                status=ToolAvailabilityStatus.TIMED_OUT,
                executable_path=executable_path,
                error_summary=f"Version probe exceeded {timeout} seconds.",
            )
        except OSError as exc:
            return ToolAvailability(
                tool_id=tool_id,
                available=True,
                usable=False,
                status=ToolAvailabilityStatus.UNUSABLE,
                executable_path=executable_path,
                error_summary=str(exc)[:500],
            )

        text = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        summary = next((line.strip() for line in text.splitlines() if line.strip()), None)
        if completed.returncode == 0:
            return ToolAvailability(
                tool_id=tool_id,
                available=True,
                usable=True,
                status=ToolAvailabilityStatus.READY,
                executable_path=executable_path,
                version_summary=summary[:500] if summary else None,
                return_code=completed.returncode,
            )
        return ToolAvailability(
            tool_id=tool_id,
            available=True,
            usable=False,
            status=ToolAvailabilityStatus.UNUSABLE,
            executable_path=executable_path,
            version_summary=summary[:500] if summary else None,
            return_code=completed.returncode,
            error_summary=(summary or "Version probe returned a non-zero status.")[:500],
        )

    def detect_all(self) -> tuple[ToolAvailability, ...]:
        return self.detect_many(item.tool_id for item in self.list())

    def detect_many(self, tool_ids: Iterable[str]) -> tuple[ToolAvailability, ...]:
        """Detect selected tools with the shared bounded, ordered probe policy."""
        return run_ordered_readiness_probes(tool_ids, self.detect)


def default_catalog() -> SecurityToolCatalog:
    network = (ToolTargetKind.NETWORK,)
    definitions = (
        SecurityToolDefinition(
            tool_id="nmap",
            display_name="Nmap",
            executable_candidates=("nmap",),
            profiles=(
                ToolProfile.DISCOVERY,
                ToolProfile.SAFE_ASSESSMENT,
                ToolProfile.RETEST,
            ),
            target_kinds=network,
            action_class=ActionClass.CONSEQUENTIAL,
            approval_required=True,
            output_formats=("xml",),
            description="Network host, port, service, and version discovery.",
        ),
        SecurityToolDefinition(
            tool_id="httpx",
            display_name="ProjectDiscovery httpx",
            executable_candidates=("httpx", "httpx-toolkit"),
            profiles=(
                ToolProfile.DISCOVERY,
                ToolProfile.SAFE_ASSESSMENT,
                ToolProfile.RETEST,
            ),
            target_kinds=network,
            action_class=ActionClass.CONSEQUENTIAL,
            approval_required=True,
            output_formats=("jsonl",),
            description="HTTP service probing and technology metadata collection.",
        ),
        SecurityToolDefinition(
            tool_id="nuclei",
            display_name="ProjectDiscovery Nuclei",
            executable_candidates=("nuclei",),
            profiles=(
                ToolProfile.SAFE_ASSESSMENT,
                ToolProfile.ACTIVE_ASSESSMENT,
                ToolProfile.VALIDATION,
                ToolProfile.RETEST,
            ),
            target_kinds=network,
            action_class=ActionClass.CONSEQUENTIAL,
            approval_required=True,
            output_formats=("jsonl",),
            description="Template-based vulnerability assessment with governed fixed profiles.",
            homepage="https://github.com/projectdiscovery/nuclei",
        ),
        SecurityToolDefinition(
            tool_id="zap",
            display_name="OWASP ZAP",
            executable_candidates=("zap.sh", "zaproxy", "zap-baseline.py"),
            profiles=(
                ToolProfile.SAFE_ASSESSMENT,
                ToolProfile.ACTIVE_ASSESSMENT,
                ToolProfile.RETEST,
            ),
            target_kinds=network,
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            output_formats=("json", "html"),
            description="Web application and API crawling and security assessment.",
        ),
        SecurityToolDefinition(
            tool_id="testssl",
            display_name="testssl.sh",
            executable_candidates=("testssl.sh", "testssl"),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=network,
            action_class=ActionClass.CONSEQUENTIAL,
            approval_required=True,
            output_formats=("json",),
            description="TLS certificate, protocol, and cipher assessment.",
        ),
        SecurityToolDefinition(
            tool_id="trivy",
            display_name="Trivy",
            executable_candidates=("trivy",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH, ToolTargetKind.CONTAINER_IMAGE),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json",),
            description="Container, filesystem, configuration, and dependency scanning.",
        ),
        SecurityToolDefinition(
            tool_id="bearer",
            display_name="Bearer CLI",
            executable_candidates=("bearer",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json", "sarif"),
            description="Multi-language static application security and data-flow analysis.",
        ),
        SecurityToolDefinition(
            tool_id="bandit",
            display_name="Bandit",
            executable_candidates=("bandit",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json", "sarif"),
            description="Python-specific static analysis for common security defects.",
        ),
        SecurityToolDefinition(
            tool_id="detect-secrets",
            display_name="detect-secrets",
            executable_candidates=("detect-secrets",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json",),
            description="Local secret-candidate discovery with a reviewable baseline format.",
        ),
        SecurityToolDefinition(
            tool_id="gitleaks",
            display_name="Gitleaks",
            executable_candidates=("gitleaks",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json", "sarif"),
            description="Redacted secret scanning for files and repository content.",
        ),
        SecurityToolDefinition(
            tool_id="syft",
            display_name="Syft",
            executable_candidates=("syft",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH, ToolTargetKind.CONTAINER_IMAGE),
            action_class=ActionClass.READ_ONLY,
            approval_required=True,
            output_formats=("syft-json", "cyclonedx-json", "spdx-json"),
            description="Software bill of materials generation for filesystems and images.",
        ),
        SecurityToolDefinition(
            tool_id="grype",
            display_name="Grype",
            executable_candidates=("grype",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH, ToolTargetKind.CONTAINER_IMAGE),
            action_class=ActionClass.READ_ONLY,
            approval_required=True,
            output_formats=("json", "sarif"),
            description="Known-vulnerability analysis for filesystems, images, and SBOMs.",
        ),
        SecurityToolDefinition(
            tool_id="osv-scanner",
            display_name="OSV-Scanner",
            executable_candidates=("osv-scanner",),
            profiles=(ToolProfile.SAFE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json", "sarif"),
            description="Dependency vulnerability analysis using OSV advisory data.",
        ),
        SecurityToolDefinition(
            tool_id="capa",
            display_name="capa",
            executable_candidates=("capa",),
            profiles=(
                ToolProfile.SAFE_ASSESSMENT,
                ToolProfile.RETEST,
                ToolProfile.MOBILE_NATIVE,
            ),
            target_kinds=(ToolTargetKind.BINARY_FILE,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json",),
            description="Static capability extraction from executable and native binary files.",
        ),
        SecurityToolDefinition(
            tool_id="amass",
            display_name="OWASP Amass",
            executable_candidates=("amass",),
            profiles=(ToolProfile.DISCOVERY,),
            target_kinds=network,
            action_class=ActionClass.CONSEQUENTIAL,
            approval_required=True,
            output_formats=("json",),
            description="Authorised attack-surface and domain relationship mapping.",
        ),
        SecurityToolDefinition(
            tool_id="ffuf",
            display_name="ffuf",
            executable_candidates=("ffuf",),
            profiles=(ToolProfile.ACTIVE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=network,
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            output_formats=("json",),
            description="Bounded web content and parameter discovery.",
        ),
        SecurityToolDefinition(
            tool_id="sqlmap",
            display_name="sqlmap",
            executable_candidates=("sqlmap", "sqlmap.py"),
            profiles=(ToolProfile.VALIDATION,),
            target_kinds=network,
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            output_formats=("text",),
            description="Separately approved SQL injection exploitability validation.",
        ),
        SecurityToolDefinition(
            tool_id="metasploit",
            display_name="Metasploit Framework",
            executable_candidates=("msfconsole",),
            profiles=(ToolProfile.VALIDATION,),
            target_kinds=(ToolTargetKind.FINDING_REFERENCE, ToolTargetKind.NETWORK),
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            requires_isolation=True,
            output_formats=("json", "text"),
            description="Separately approved module-based exploitability validation.",
        ),
        SecurityToolDefinition(
            tool_id="apksigner",
            display_name="Android apksigner",
            executable_candidates=("apksigner",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("text",),
            description="APK signature verification and signing-certificate metadata inspection.",
        ),
        SecurityToolDefinition(
            tool_id="aapt2",
            display_name="Android Asset Packaging Tool",
            executable_candidates=("aapt2", "aapt"),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("text",),
            description="APK package, SDK, permission, and resource metadata inspection.",
        ),
        SecurityToolDefinition(
            tool_id="apktool",
            display_name="Apktool",
            executable_candidates=("apktool",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.REVERSIBLE_LOCAL,
            approval_required=False,
            output_formats=("directory",),
            description="Decode AndroidManifest resources and smali into an evidence directory.",
        ),
        SecurityToolDefinition(
            tool_id="jadx",
            display_name="JADX",
            executable_candidates=("jadx",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.REVERSIBLE_LOCAL,
            approval_required=False,
            output_formats=("directory",),
            description="Decompile APK DEX bytecode into reviewable Java-like source.",
        ),
        SecurityToolDefinition(
            tool_id="apkid",
            display_name="APKiD",
            executable_candidates=("apkid",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json",),
            description="Detect APK compilers, packers, protectors, and obfuscation indicators.",
        ),
        SecurityToolDefinition(
            tool_id="yara",
            display_name="YARA",
            executable_candidates=("yara",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE, ToolTargetKind.LOCAL_PATH),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("text",),
            description="Apply a governed local ruleset to APK and extracted artifact content.",
        ),
        SecurityToolDefinition(
            tool_id="androguard",
            display_name="Androguard",
            executable_candidates=("androguard",),
            profiles=(ToolProfile.MOBILE_STATIC, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            connector_only=True,
            output_formats=("json",),
            description="Python bytecode and manifest analysis through a dedicated connector.",
        ),
        SecurityToolDefinition(
            tool_id="mobsf",
            display_name="Mobile Security Framework (MobSF)",
            executable_candidates=("mobsf", "runserver.sh"),
            profiles=(
                ToolProfile.MOBILE_STATIC,
                ToolProfile.MOBILE_DYNAMIC,
                ToolProfile.MOBILE_RETEST,
            ),
            target_kinds=(ToolTargetKind.APK_FILE,),
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            requires_isolation=True,
            output_formats=("json", "pdf"),
            description=(
                "Static and separately approved dynamic mobile security analysis connector."
            ),
        ),
        SecurityToolDefinition(
            tool_id="radare2",
            display_name="radare2 / rabin2",
            executable_candidates=("rabin2",),
            profiles=(ToolProfile.MOBILE_NATIVE, ToolProfile.MOBILE_RETEST),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.READ_ONLY,
            approval_required=False,
            output_formats=("json",),
            description="Read-only native-library metadata and symbol inspection.",
        ),
        SecurityToolDefinition(
            tool_id="ghidra",
            display_name="Ghidra Headless Analyzer",
            executable_candidates=("analyzeHeadless",),
            profiles=(ToolProfile.MOBILE_NATIVE,),
            target_kinds=(ToolTargetKind.LOCAL_PATH,),
            action_class=ActionClass.REVERSIBLE_LOCAL,
            approval_required=True,
            connector_only=True,
            output_formats=("directory", "json"),
            description="Isolated native-library reverse engineering through a governed connector.",
        ),
        SecurityToolDefinition(
            tool_id="adb",
            display_name="Android Debug Bridge",
            executable_candidates=("adb",),
            profiles=(ToolProfile.MOBILE_DYNAMIC,),
            target_kinds=(ToolTargetKind.ANDROID_DEVICE,),
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            requires_isolation=True,
            output_formats=("json", "text"),
            description="Bounded interaction with an explicitly isolated Android emulator.",
        ),
        SecurityToolDefinition(
            tool_id="frida",
            display_name="Frida",
            executable_candidates=("frida", "frida-ps"),
            profiles=(ToolProfile.MOBILE_DYNAMIC,),
            target_kinds=(ToolTargetKind.ANDROID_DEVICE,),
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            requires_isolation=True,
            output_formats=("json", "text"),
            description="Separately approved runtime instrumentation in an isolated emulator.",
        ),
    )
    return SecurityToolCatalog(definitions)
