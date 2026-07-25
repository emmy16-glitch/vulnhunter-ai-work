"""Isolated, read-only static and native APK worker boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.mobile.artifacts import MobileArtifactError, copy_artifact_for_analysis
from vulnhunter.mobile.manifest import analyze_decoded_manifest
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.security import redact_text

_ANALYSIS_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SAFE_TOOL = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_JSON_LINE = re.compile(r"^VULNHUNTER_JSON:(\{.*\})$")
_DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
ProgressCallback = Callable[[dict[str, object]], None]


class MobileStaticWorkerError(RuntimeError):
    """Raised when static mobile analysis cannot preserve its safety boundary."""


class MobileStaticWorkerPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.1"] = "1.1"
    enabled: bool = False
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    workspace_root: Path
    aapt2_executable: Path | None = None
    apksigner_executable: Path | None = None
    apkid_executable: Path | None = None
    apktool_executable: Path | None = None
    jadx_executable: Path | None = None
    python_executable: Path | None = None
    androguard_adapter: Path | None = None
    yara_adapter: Path | None = None
    yara_rules_file: Path | None = None
    radare2_executable: Path | None = None
    ghidra_headless_executable: Path | None = None
    ghidra_script_root: Path | None = None
    timeout_seconds: int = Field(default=180, ge=5, le=1_800)
    heavy_timeout_seconds: int = Field(default=600, ge=30, le=3_600)
    maximum_output_bytes: int = Field(default=1_000_000, ge=4_096, le=10_000_000)
    maximum_generated_bytes: int = Field(default=750_000_000, ge=10_000_000, le=4_000_000_000)
    maximum_generated_file_bytes: int = Field(default=200_000_000, ge=1_000_000, le=1_000_000_000)
    maximum_memory_bytes: int = Field(default=4_000_000_000, ge=256_000_000, le=12_000_000_000)
    maximum_native_libraries: int = Field(default=24, ge=1, le=128)
    network_isolation: Literal["process_policy", "os_enforced"] = "process_policy"

    @field_validator(
        "workspace_root",
        "aapt2_executable",
        "apksigner_executable",
        "apkid_executable",
        "apktool_executable",
        "jadx_executable",
        "python_executable",
        "androguard_adapter",
        "yara_adapter",
        "yara_rules_file",
        "radare2_executable",
        "ghidra_headless_executable",
        "ghidra_script_root",
    )
    @classmethod
    def validate_paths(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        candidate = value.expanduser()
        if not candidate.is_absolute():
            raise ValueError("mobile worker paths must be absolute")
        return candidate

    @model_validator(mode="after")
    def validate_contract(self):
        tools = (
            self.aapt2_executable,
            self.apksigner_executable,
            self.apkid_executable,
            self.apktool_executable,
            self.jadx_executable,
            self.androguard_adapter,
            self.yara_adapter,
            self.radare2_executable,
            self.ghidra_headless_executable,
        )
        if self.enabled and not any(tools):
            raise ValueError("enabled mobile static worker requires at least one fixed tool")
        if self.androguard_adapter is not None and self.python_executable is None:
            raise ValueError("Androguard adapter requires a fixed Python executable")
        if self.yara_adapter is not None and (
            self.python_executable is None or self.yara_rules_file is None
        ):
            raise ValueError("YARA adapter requires fixed Python and rules paths")
        if (self.ghidra_headless_executable is None) != (self.ghidra_script_root is None):
            raise ValueError("Ghidra executable and script root must be configured together")
        return self

    @classmethod
    def from_path(cls, path: Path) -> MobileStaticWorkerPolicy:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise MobileStaticWorkerError("mobile worker policy must not be a symbolic link")
        try:
            metadata = candidate.stat()
            text = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise MobileStaticWorkerError("mobile worker policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise MobileStaticWorkerError("mobile worker policy permissions are unsafe")
        try:
            return cls.model_validate_json(text)
        except ValueError as exc:
            raise MobileStaticWorkerError("mobile worker policy is invalid") from exc

    def active_tools(self) -> tuple[str, ...]:
        configured = (
            ("aapt2", self.aapt2_executable),
            ("apksigner", self.apksigner_executable),
            ("apkid", self.apkid_executable),
            ("apktool", self.apktool_executable),
            ("jadx", self.jadx_executable),
            ("androguard", self.androguard_adapter),
            ("yara", self.yara_adapter),
            ("radare2", self.radare2_executable),
            ("ghidra", self.ghidra_headless_executable),
        )
        return tuple(name for name, path in configured if path is not None)


class MobileToolCapture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    return_code: int
    output: str
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0)
    evidence: dict[str, object] = Field(default_factory=dict)


class MobileStaticAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    state: Literal["completed", "blocked", "failed"]
    captures: tuple[MobileToolCapture, ...] = ()
    candidate_observations: tuple[dict[str, object], ...] = ()
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)


class MobileStaticWorker:
    """Run fixed tools against a private APK copy; never execute the APK."""

    def __init__(self, policy: MobileStaticWorkerPolicy) -> None:
        self.policy = policy

    def analyze(
        self,
        record: MobileArtifactRecord,
        *,
        analysis_reference: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> MobileStaticAnalysisResult:
        now = datetime.now(UTC)
        if not self.policy.enabled:
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="blocked",
                completed_at=now,
                reason="Mobile static worker is disabled by worker policy.",
            )
        if analysis_reference is not None and _ANALYSIS_REFERENCE.fullmatch(analysis_reference) is None:
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=now,
                reason="Mobile static analysis failed closed: invalid analysis reference.",
            )
        workspace = self.policy.workspace_root / record.artifact_id
        if analysis_reference:
            workspace /= analysis_reference
        try:
            apk = copy_artifact_for_analysis(record, workspace)
            private_home = workspace / "home"
            private_home.mkdir(mode=0o700, exist_ok=True)
            extracted = self._extract_analysis_entries(record, apk, workspace)
            self._emit(
                progress_callback,
                state="running",
                stage="ingest",
                detail="APK identity was rebound to the ingested SHA-256 and copied read-only.",
                tools=self.policy.active_tools(),
            )
            captures = tuple(
                self._run_all(
                    record,
                    apk,
                    workspace,
                    private_home,
                    extracted,
                    progress_callback,
                )
            )
            self._enforce_workspace_bound(workspace)
            observations = self._observations(record, captures, workspace)
        except (OSError, MobileArtifactError, MobileStaticWorkerError, ValueError, zipfile.BadZipFile) as exc:
            self._emit(
                progress_callback,
                state="failed",
                stage="worker",
                detail=f"Static analysis failed closed: {type(exc).__name__}.",
            )
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=datetime.now(UTC),
                reason=f"Mobile static analysis failed closed: {type(exc).__name__}.",
            )
        result = MobileStaticAnalysisResult(
            artifact_id=record.artifact_id,
            state="completed",
            captures=captures,
            candidate_observations=tuple(observations),
            completed_at=datetime.now(UTC),
            reason="Read-only static and native APK inspection completed.",
        )
        output = workspace / "static-analysis.json"
        self._write_exclusive(output, result.model_dump_json(indent=2) + "\n")
        self._emit(
            progress_callback,
            state="completed",
            stage="report",
            detail=(
                f"Collected {len(captures)} bounded tool receipt(s) and "
                f"{len(observations)} candidate observation(s)."
            ),
        )
        return result

    @staticmethod
    def _emit(callback: ProgressCallback | None, **payload: object) -> None:
        if callback is None:
            return
        event = {"at": datetime.now(UTC).isoformat(), **payload}
        callback(event)

    def _extract_analysis_entries(
        self,
        record: MobileArtifactRecord,
        apk: Path,
        workspace: Path,
    ) -> dict[str, tuple[Path, ...]]:
        root = workspace / "extracted"
        root.mkdir(mode=0o700, exist_ok=False)
        wanted_dex = set(record.dex_entries)
        wanted_native = set(record.native_libraries[: self.policy.maximum_native_libraries])
        dex_paths: list[Path] = []
        native_paths: list[Path] = []
        total = 0
        with zipfile.ZipFile(apk) as archive:
            members = {item.filename: item for item in archive.infolist()}
            for entry in sorted(wanted_dex | wanted_native):
                pure = PurePosixPath(entry)
                if pure.is_absolute() or ".." in pure.parts or entry not in members:
                    raise MobileStaticWorkerError("APK analysis entry failed path validation")
                info = members[entry]
                if info.is_dir() or info.file_size > self.policy.maximum_generated_file_bytes:
                    raise MobileStaticWorkerError("APK analysis entry exceeds the per-file boundary")
                total += info.file_size
                if total > self.policy.maximum_generated_bytes:
                    raise MobileStaticWorkerError("APK analysis entries exceed the workspace boundary")
                bucket = "native" if entry in wanted_native else "dex"
                destination = root / bucket / hashlib.sha256(entry.encode()).hexdigest()[:16] / pure.name
                destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    with archive.open(info) as source, os.fdopen(descriptor, "wb") as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                except BaseException:
                    destination.unlink(missing_ok=True)
                    raise
                if bucket == "native":
                    native_paths.append(destination)
                else:
                    dex_paths.append(destination)
        return {"dex": tuple(dex_paths), "native": tuple(native_paths)}

    def _run_all(
        self,
        record: MobileArtifactRecord,
        apk: Path,
        workspace: Path,
        private_home: Path,
        extracted: dict[str, tuple[Path, ...]],
        progress_callback: ProgressCallback | None,
    ) -> Iterable[MobileToolCapture]:
        commands: list[tuple[str, Path | None, tuple[str, ...], int, dict[str, object]]] = [
            ("aapt2", self.policy.aapt2_executable, ("dump", "badging", str(apk)), self.policy.timeout_seconds, {}),
            (
                "apksigner",
                self.policy.apksigner_executable,
                ("verify", "--print-certs", str(apk)),
                self.policy.timeout_seconds,
                {},
            ),
            ("apkid", self.policy.apkid_executable, ("-j", str(apk)), self.policy.timeout_seconds, {}),
            (
                "apktool",
                self.policy.apktool_executable,
                (
                    "decode",
                    "--force",
                    "--frame-path",
                    str(workspace / "apktool-framework"),
                    "--output",
                    str(workspace / "apktool-decoded"),
                    str(apk),
                ),
                self.policy.timeout_seconds,
                {},
            ),
            (
                "jadx",
                self.policy.jadx_executable,
                (
                    "--no-res",
                    "--threads-count",
                    "1",
                    "--output-dir",
                    str(workspace / "jadx-output"),
                    str(apk),
                ),
                self.policy.heavy_timeout_seconds,
                {},
            ),
        ]
        if self.policy.androguard_adapter is not None and self.policy.python_executable is not None:
            commands.append(
                (
                    "androguard",
                    self.policy.python_executable,
                    (str(self.policy.androguard_adapter), str(apk)),
                    self.policy.heavy_timeout_seconds,
                    {},
                )
            )
        if (
            self.policy.yara_adapter is not None
            and self.policy.python_executable is not None
            and self.policy.yara_rules_file is not None
        ):
            commands.append(
                (
                    "yara",
                    self.policy.python_executable,
                    (
                        str(self.policy.yara_adapter),
                        "--rules",
                        str(self.policy.yara_rules_file),
                        "--target",
                        str(workspace / "extracted"),
                    ),
                    self.policy.heavy_timeout_seconds,
                    {},
                )
            )

        for tool, executable, arguments, timeout, evidence in commands:
            if executable is None:
                continue
            capture = self._run_tool(
                tool,
                executable,
                arguments,
                workspace,
                private_home,
                timeout=timeout,
                evidence=evidence,
                progress_callback=progress_callback,
            )
            capture = self._enrich_capture(capture, workspace)
            yield capture
            self._enforce_workspace_bound(workspace)

        for index, native in enumerate(extracted.get("native", ())):
            label = f"native-{index + 1}"
            if self.policy.radare2_executable is not None:
                capture = self._run_tool(
                    "radare2",
                    self.policy.radare2_executable,
                    ("-Ij", str(native)),
                    workspace,
                    private_home,
                    timeout=self.policy.timeout_seconds,
                    evidence={"library": native.name, "library_reference": label},
                    progress_callback=progress_callback,
                )
                yield self._enrich_capture(capture, workspace)
            if (
                self.policy.ghidra_headless_executable is not None
                and self.policy.ghidra_script_root is not None
            ):
                project = workspace / "ghidra-projects" / label
                project.mkdir(parents=True, mode=0o700, exist_ok=True)
                capture = self._run_tool(
                    "ghidra",
                    self.policy.ghidra_headless_executable,
                    (
                        str(project),
                        "analysis",
                        "-import",
                        str(native),
                        "-analysisTimeoutPerFile",
                        str(self.policy.heavy_timeout_seconds),
                        "-scriptPath",
                        str(self.policy.ghidra_script_root),
                        "-postScript",
                        "VulnHunterNativeSummary.java",
                        "-deleteProject",
                    ),
                    workspace,
                    private_home,
                    timeout=self.policy.heavy_timeout_seconds,
                    evidence={"library": native.name, "library_reference": label},
                    progress_callback=progress_callback,
                )
                yield self._enrich_capture(capture, workspace)
            self._enforce_workspace_bound(workspace)

    def _run_tool(
        self,
        tool: str,
        executable: Path,
        arguments: tuple[str, ...],
        workspace: Path,
        private_home: Path,
        *,
        timeout: int,
        evidence: dict[str, object],
        progress_callback: ProgressCallback | None,
    ) -> MobileToolCapture:
        if _SAFE_TOOL.fullmatch(tool) is None:
            raise MobileStaticWorkerError("tool identifier is unsafe")
        resolved = self._verified_regular_file(executable, executable=True, label=f"{tool} executable")
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        self._emit(
            progress_callback,
            state="running",
            stage="tool",
            tool=tool,
            tool_state="running",
            detail=f"{tool} started in the isolated analysis workspace.",
        )
        output_path = workspace / f".{tool}-{hashlib.sha256(repr(arguments).encode()).hexdigest()[:12]}.capture"
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

        def apply_limits() -> None:
            file_limit = self.policy.maximum_generated_file_bytes
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 2))
            memory = self.policy.maximum_memory_bytes
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
            os.umask(0o077)

        try:
            with os.fdopen(descriptor, "wb") as capture_file:
                completed = subprocess.run(
                    (str(resolved), *arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=capture_file,
                    stderr=subprocess.STDOUT,
                    cwd=workspace,
                    env={
                        "PATH": f"{resolved.parent}:{_DEFAULT_PATH}",
                        "HOME": str(private_home),
                        "TMPDIR": str(workspace),
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "NO_PROXY": "*",
                        "no_proxy": "*",
                        "http_proxy": "",
                        "https_proxy": "",
                        "HTTP_PROXY": "",
                        "HTTPS_PROXY": "",
                        "PYTHONNOUSERSITE": "1",
                    },
                    timeout=timeout,
                    check=False,
                    preexec_fn=apply_limits,
                )
            raw = output_path.read_bytes()
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            raw = b"tool timed out"
            return_code = 124
        finally:
            output_path.unlink(missing_ok=True)
        completed_at = datetime.now(UTC)
        truncated = len(raw) > self.policy.maximum_output_bytes
        bounded = raw[: self.policy.maximum_output_bytes]
        text = redact_text(bounded.decode("utf-8", errors="replace"))
        capture = MobileToolCapture(
            tool=tool,
            return_code=return_code,
            output=text,
            output_sha256=hashlib.sha256(bounded).hexdigest(),
            truncated=truncated,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - started_monotonic) * 1_000)),
            evidence=evidence,
        )
        self._emit(
            progress_callback,
            state="running",
            stage="tool",
            tool=tool,
            tool_state="completed" if return_code == 0 else "failed",
            return_code=return_code,
            output_sha256=capture.output_sha256,
            duration_ms=capture.duration_ms,
            detail=(
                f"{tool} completed and produced a bounded evidence receipt."
                if return_code == 0
                else f"{tool} failed with exit code {return_code}; no finding was inferred."
            ),
        )
        return capture

    def _enrich_capture(self, capture: MobileToolCapture, workspace: Path) -> MobileToolCapture:
        evidence = dict(capture.evidence)
        if capture.return_code == 0 and capture.tool in {"androguard", "yara", "radare2"}:
            payload = self._json_object(capture.output)
            if payload is not None:
                evidence["structured"] = payload
        elif capture.return_code == 0 and capture.tool == "ghidra":
            for line in capture.output.splitlines():
                match = _JSON_LINE.fullmatch(line.strip())
                if match:
                    payload = self._json_object(match.group(1))
                    if payload is not None:
                        evidence["structured"] = payload
                        break
        elif capture.return_code == 0 and capture.tool == "jadx":
            root = workspace / "jadx-output"
            files = [item for item in root.rglob("*") if item.is_file() and not item.is_symlink()] if root.is_dir() else []
            evidence["generated_files"] = len(files)
            evidence["generated_bytes"] = sum(item.stat().st_size for item in files)
            evidence["source_files"] = sum(item.suffix in {".java", ".kt"} for item in files)
        return MobileToolCapture.model_validate(
            capture.model_copy(update={"evidence": evidence}).model_dump(mode="json")
        )

    def _observations(
        self,
        record: MobileArtifactRecord,
        captures: tuple[MobileToolCapture, ...],
        workspace: Path,
    ) -> list[dict[str, object]]:
        observations: list[dict[str, object]] = []
        if record.native_libraries:
            observations.append(
                {
                    "observation_id": f"mobile-native-{record.sha256[:20]}",
                    "title": "APK contains native libraries requiring native-code scrutiny",
                    "status": "evidence_required",
                    "count": len(record.native_libraries),
                    "abis": list(record.native_abis),
                }
            )
        for capture in captures:
            if capture.return_code != 0:
                observations.append(
                    {
                        "observation_id": (
                            f"mobile-tool-{capture.tool}-{capture.output_sha256[:16]}"
                        ),
                        "title": f"{capture.tool} could not complete static inspection",
                        "status": "operational_failure",
                        "return_code": capture.return_code,
                        "evidence": {
                            "tool": capture.tool,
                            "output_sha256": capture.output_sha256,
                        },
                    }
                )
        apktool_capture = next((item for item in captures if item.tool == "apktool"), None)
        decoded_manifest = workspace / "apktool-decoded" / "AndroidManifest.xml"
        if (
            apktool_capture is not None
            and apktool_capture.return_code == 0
            and decoded_manifest.is_file()
        ):
            observations.extend(
                {
                    "observation_id": finding.finding_id,
                    "weakness_id": finding.weakness_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.confidence,
                    "component": finding.component,
                    "evidence": finding.evidence,
                    "tool_ids": list(finding.tool_ids),
                }
                for finding in analyze_decoded_manifest(
                    decoded_manifest,
                    artifact_sha256=record.sha256,
                )
            )
        for capture in captures:
            structured = capture.evidence.get("structured")
            if not isinstance(structured, dict):
                continue
            if capture.tool == "androguard":
                dangerous = structured.get("dangerous_permissions")
                if isinstance(dangerous, list) and dangerous:
                    observations.append(
                        {
                            "observation_id": f"androguard-permissions-{record.sha256[:16]}",
                            "weakness_id": "mobile-dangerous-permissions",
                            "title": "Application requests sensitive Android permissions",
                            "severity": "info",
                            "status": "evidence_required",
                            "component": "AndroidManifest.xml",
                            "evidence": {
                                "permissions": dangerous[:100],
                                "package_name": structured.get("package_name", ""),
                            },
                            "tool_ids": ["androguard"],
                        }
                    )
            elif capture.tool == "yara":
                matches = structured.get("matches")
                if not isinstance(matches, list):
                    continue
                for index, raw_match in enumerate(matches[:250], start=1):
                    if not isinstance(raw_match, dict):
                        continue
                    meta = raw_match.get("meta") if isinstance(raw_match.get("meta"), dict) else {}
                    rule = str(raw_match.get("rule") or f"rule-{index}")
                    observations.append(
                        {
                            "observation_id": (
                                f"yara-{hashlib.sha256((rule + str(raw_match.get('file', ''))).encode()).hexdigest()[:20]}"
                            ),
                            "weakness_id": str(meta.get("weakness_id") or "mobile-yara-match"),
                            "title": str(meta.get("title") or f"YARA rule matched: {rule}"),
                            "severity": str(meta.get("severity") or "unknown"),
                            "status": str(meta.get("confidence") or "evidence_required"),
                            "component": str(raw_match.get("file") or "APK content"),
                            "evidence": {
                                "rule": rule,
                                "namespace": raw_match.get("namespace", ""),
                                "tags": raw_match.get("tags", []),
                                "strings": raw_match.get("strings", []),
                                "ruleset_sha256": self._sha256_file(self.policy.yara_rules_file),
                            },
                            "tool_ids": ["yara"],
                        }
                    )
            elif capture.tool == "radare2":
                hardening = self._native_hardening(structured)
                for name, present in hardening.items():
                    if present is not False:
                        continue
                    observations.append(
                        {
                            "observation_id": (
                                f"native-{name}-{hashlib.sha256(str(capture.evidence).encode()).hexdigest()[:16]}"
                            ),
                            "weakness_id": "mobile-native-hardening",
                            "title": f"Native library is missing {name.upper()} hardening",
                            "severity": "medium",
                            "status": "verified_configuration",
                            "component": str(capture.evidence.get("library") or "native library"),
                            "evidence": {
                                "control": name,
                                "present": False,
                                "tool_output_sha256": capture.output_sha256,
                            },
                            "tool_ids": ["radare2"],
                        }
                    )
        return observations

    @staticmethod
    def _native_hardening(payload: dict[str, object]) -> dict[str, bool | None]:
        info = payload.get("info") if isinstance(payload.get("info"), dict) else payload

        def boolean(*names: str) -> bool | None:
            for name in names:
                value = info.get(name) if isinstance(info, dict) else None
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    lowered = value.casefold()
                    if lowered in {"true", "yes", "full", "partial"}:
                        return True
                    if lowered in {"false", "no", "none"}:
                        return False
            return None

        return {
            "nx": boolean("nx", "has_nx"),
            "canary": boolean("canary", "has_canary"),
            "pic": boolean("pic", "pie", "has_pi"),
            "relro": boolean("relro", "has_relro"),
        }

    def _enforce_workspace_bound(self, workspace: Path) -> None:
        total = 0
        for path in workspace.rglob("*"):
            if path.is_symlink():
                raise MobileStaticWorkerError("analysis workspace contains a symbolic link")
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size > self.policy.maximum_generated_file_bytes:
                raise MobileStaticWorkerError("tool generated an oversized workspace file")
            total += size
            if total > self.policy.maximum_generated_bytes:
                raise MobileStaticWorkerError("tool generated an oversized analysis workspace")

    @staticmethod
    def _json_object(value: str) -> dict[str, object] | None:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _verified_regular_file(path: Path, *, executable: bool, label: str) -> Path:
        if path.is_symlink():
            raise MobileStaticWorkerError(f"{label} must not be a symbolic link")
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise MobileStaticWorkerError(f"{label} is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise MobileStaticWorkerError(f"{label} is not a regular file")
        if executable and not os.access(resolved, os.X_OK):
            raise MobileStaticWorkerError(f"{label} is not executable")
        return resolved

    @staticmethod
    def _sha256_file(path: Path | None) -> str:
        if path is None:
            return ""
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return ""

    @staticmethod
    def _write_exclusive(path: Path, content: str) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)


__all__ = [
    "MobileStaticAnalysisResult",
    "MobileStaticWorker",
    "MobileStaticWorkerError",
    "MobileStaticWorkerPolicy",
    "MobileToolCapture",
]
