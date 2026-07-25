"""Fixed-command static and native APK toolchain with bounded evidence output."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import time
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.mobile.manifest import analyze_decoded_manifest
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.security import redact_text

_SAFE_TOOL = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_JSON_LINE = re.compile(r"^VULNHUNTER_JSON:(\{.*\})$")
_DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
ProgressCallback = Callable[[dict[str, object]], None]


class MobileStaticToolchainError(RuntimeError):
    """Raised when a fixed tool cannot preserve the worker boundary."""


class MobileStaticWorkerPolicy(BaseModel):
    """Owner-private fixed paths and resource boundaries for APK analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0", "1.1"] = "1.1"
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
    maximum_generated_bytes: int = Field(
        default=750_000_000,
        ge=10_000_000,
        le=4_000_000_000,
    )
    maximum_generated_file_bytes: int = Field(
        default=200_000_000,
        ge=1_000_000,
        le=1_000_000_000,
    )
    maximum_memory_bytes: int = Field(
        default=8_000_000_000,
        ge=256_000_000,
        le=12_000_000_000,
    )
    maximum_native_libraries: int = Field(default=24, ge=1, le=128)
    network_isolation: Literal["process_policy", "os_enforced"] = "process_policy"
    networkless_runtime_required: bool | None = None

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
    def validate_contract(self) -> Self:
        if self.enabled and not self.active_tools():
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
            raise MobileStaticToolchainError("mobile worker policy must not be a symbolic link")
        try:
            metadata = candidate.stat()
            text = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise MobileStaticToolchainError("mobile worker policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise MobileStaticToolchainError("mobile worker policy permissions are unsafe")
        try:
            return cls.model_validate_json(text)
        except ValueError as exc:
            raise MobileStaticToolchainError("mobile worker policy is invalid") from exc

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
    """One bounded tool receipt; unrestricted output remains private."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    return_code: int
    output: str
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = Field(default=0, ge=0)
    evidence: dict[str, object] = Field(default_factory=dict)


@dataclass(frozen=True)
class _ToolSpec:
    name: str
    executable: Path
    arguments: tuple[str, ...]
    timeout_seconds: int
    evidence: dict[str, object]


class MobileStaticToolchain:
    """Execute fixed static/native tools and convert their output to observations."""

    def __init__(self, policy: MobileStaticWorkerPolicy) -> None:
        self.policy = policy

    def run(
        self,
        *,
        record: MobileArtifactRecord,
        apk: Path,
        workspace: Path,
        private_home: Path,
        progress_callback: ProgressCallback | None,
    ) -> tuple[tuple[MobileToolCapture, ...], tuple[dict[str, object], ...]]:
        extracted = self._extract_analysis_entries(record, apk, workspace)
        captures = tuple(
            self._run_all(
                apk=apk,
                workspace=workspace,
                private_home=private_home,
                extracted=extracted,
                progress_callback=progress_callback,
            )
        )
        self.enforce_workspace_bound(workspace)
        observations = tuple(self._observations(record, captures, workspace))
        return captures, observations

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
                    raise MobileStaticToolchainError("APK analysis entry failed path validation")
                info = members[entry]
                if info.is_dir() or info.file_size > self.policy.maximum_generated_file_bytes:
                    raise MobileStaticToolchainError(
                        "APK analysis entry exceeds the per-file boundary"
                    )
                total += info.file_size
                if total > self.policy.maximum_generated_bytes:
                    raise MobileStaticToolchainError(
                        "APK analysis entries exceed the workspace boundary"
                    )
                bucket = "native" if entry in wanted_native else "dex"
                entry_digest = hashlib.sha256(entry.encode()).hexdigest()[:16]
                destination = root / bucket / entry_digest / pure.name
                destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    with (
                        archive.open(info) as source,
                        os.fdopen(
                            descriptor,
                            "wb",
                        ) as target,
                    ):
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
        *,
        apk: Path,
        workspace: Path,
        private_home: Path,
        extracted: dict[str, tuple[Path, ...]],
        progress_callback: ProgressCallback | None,
    ) -> Iterable[MobileToolCapture]:
        for spec in self._primary_specs(apk, workspace):
            capture = self._run_tool(
                spec,
                workspace=workspace,
                private_home=private_home,
                progress_callback=progress_callback,
            )
            yield self._enrich_capture(capture, workspace)
            self.enforce_workspace_bound(workspace)

        yara_spec = self._yara_spec(apk, workspace)
        if yara_spec is not None:
            capture = self._run_tool(
                yara_spec,
                workspace=workspace,
                private_home=private_home,
                progress_callback=progress_callback,
            )
            yield self._enrich_capture(capture, workspace)
            self.enforce_workspace_bound(workspace)

        for index, native in enumerate(extracted.get("native", ())):
            label = f"native-{index + 1}"
            for spec in self._native_specs(native, label, workspace):
                capture = self._run_tool(
                    spec,
                    workspace=workspace,
                    private_home=private_home,
                    progress_callback=progress_callback,
                )
                yield self._enrich_capture(capture, workspace)
                self.enforce_workspace_bound(workspace)

    def _primary_specs(self, apk: Path, workspace: Path) -> tuple[_ToolSpec, ...]:
        specifications: list[_ToolSpec] = []
        self._append_spec(
            specifications,
            "aapt2",
            self.policy.aapt2_executable,
            ("dump", "badging", str(apk)),
            self.policy.timeout_seconds,
        )
        self._append_spec(
            specifications,
            "apksigner",
            self.policy.apksigner_executable,
            ("verify", "--print-certs", str(apk)),
            self.policy.timeout_seconds,
        )
        self._append_spec(
            specifications,
            "apkid",
            self.policy.apkid_executable,
            ("-j", str(apk)),
            self.policy.timeout_seconds,
        )
        self._append_spec(
            specifications,
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
        )
        self._append_spec(
            specifications,
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
        )
        if self.policy.androguard_adapter is not None and self.policy.python_executable is not None:
            adapter = self._verified_regular_file(
                self.policy.androguard_adapter,
                executable=False,
                label="Androguard adapter",
            )
            self._append_spec(
                specifications,
                "androguard",
                self.policy.python_executable,
                (str(adapter), str(apk)),
                self.policy.heavy_timeout_seconds,
            )
        return tuple(specifications)

    def _yara_spec(self, apk: Path, workspace: Path) -> _ToolSpec | None:
        if (
            self.policy.yara_adapter is None
            or self.policy.python_executable is None
            or self.policy.yara_rules_file is None
        ):
            return None
        adapter = self._verified_regular_file(
            self.policy.yara_adapter,
            executable=False,
            label="YARA adapter",
        )
        rules = self._verified_regular_file(
            self.policy.yara_rules_file,
            executable=False,
            label="YARA rules file",
        )
        targets = [apk, workspace / "extracted"]
        for candidate in (workspace / "apktool-decoded", workspace / "jadx-output"):
            if candidate.is_dir() and not candidate.is_symlink():
                targets.append(candidate)
        arguments: list[str] = [str(adapter), "--rules", str(rules)]
        for target in targets:
            arguments.extend(("--target", str(target)))
        executable = self._verified_regular_file(
            self.policy.python_executable,
            executable=True,
            label="YARA Python executable",
        )
        return _ToolSpec(
            name="yara",
            executable=executable,
            arguments=tuple(arguments),
            timeout_seconds=self.policy.heavy_timeout_seconds,
            evidence={"ruleset_sha256": self._sha256_file(rules)},
        )

    def _native_specs(
        self,
        native: Path,
        label: str,
        workspace: Path,
    ) -> tuple[_ToolSpec, ...]:
        specifications: list[_ToolSpec] = []
        evidence = {"library": native.name, "library_reference": label}
        self._append_spec(
            specifications,
            "radare2",
            self.policy.radare2_executable,
            ("-Ij", str(native)),
            self.policy.timeout_seconds,
            evidence=evidence,
        )
        if (
            self.policy.ghidra_headless_executable is not None
            and self.policy.ghidra_script_root is not None
        ):
            script_root = self.policy.ghidra_script_root.resolve(strict=True)
            if script_root.is_symlink() or not script_root.is_dir():
                raise MobileStaticToolchainError("Ghidra script root is unsafe")
            summary_script = self._verified_regular_file(
                script_root / "VulnHunterNativeSummary.java",
                executable=False,
                label="Ghidra summary script",
            )
            project = workspace / "ghidra-projects" / label
            project.mkdir(parents=True, mode=0o700, exist_ok=True)
            ghidra_evidence = {
                **evidence,
                "script_sha256": self._sha256_file(summary_script),
            }
            self._append_spec(
                specifications,
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
                    str(script_root),
                    "-postScript",
                    summary_script.name,
                    "-deleteProject",
                ),
                self.policy.heavy_timeout_seconds,
                evidence=ghidra_evidence,
            )
        return tuple(specifications)

    def _append_spec(
        self,
        target: list[_ToolSpec],
        name: str,
        executable: Path | None,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        *,
        evidence: dict[str, object] | None = None,
    ) -> None:
        if executable is None:
            return
        target.append(
            _ToolSpec(
                name=name,
                executable=self._verified_regular_file(
                    executable,
                    executable=True,
                    label=f"{name} executable",
                ),
                arguments=arguments,
                timeout_seconds=timeout_seconds,
                evidence=dict(evidence or {}),
            )
        )

    def _run_tool(
        self,
        spec: _ToolSpec,
        *,
        workspace: Path,
        private_home: Path,
        progress_callback: ProgressCallback | None,
    ) -> MobileToolCapture:
        if _SAFE_TOOL.fullmatch(spec.name) is None:
            raise MobileStaticToolchainError("tool identifier is unsafe")
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        self._emit(
            progress_callback,
            state="running",
            stage="tool",
            tool=spec.name,
            tool_state="running",
            detail=f"{spec.name} started in the isolated analysis workspace.",
        )
        arguments_digest = hashlib.sha256(repr(spec.arguments).encode()).hexdigest()
        output_path = workspace / f".{spec.name}-{arguments_digest[:12]}.capture"
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

        def apply_limits() -> None:
            file_limit = self.policy.maximum_generated_file_bytes
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (spec.timeout_seconds, spec.timeout_seconds + 2),
            )
            memory = self.policy.maximum_memory_bytes
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
            os.umask(0o077)

        try:
            with os.fdopen(descriptor, "wb") as capture_file:
                completed = subprocess.run(
                    (str(spec.executable), *spec.arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=capture_file,
                    stderr=subprocess.STDOUT,
                    cwd=workspace,
                    env=self._tool_environment(
                        spec.executable,
                        workspace,
                        private_home,
                    ),
                    timeout=spec.timeout_seconds,
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
        output = redact_text(bounded.decode("utf-8", errors="replace"))
        capture = MobileToolCapture(
            tool=spec.name,
            return_code=return_code,
            output=output,
            output_sha256=hashlib.sha256(bounded).hexdigest(),
            truncated=truncated,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(
                0,
                int((time.monotonic() - started_monotonic) * 1_000),
            ),
            evidence=spec.evidence,
        )
        self._emit(
            progress_callback,
            state="running",
            stage="tool",
            tool=spec.name,
            tool_state="completed" if return_code == 0 else "failed",
            return_code=return_code,
            output_sha256=capture.output_sha256,
            duration_ms=capture.duration_ms,
            detail=(
                f"{spec.name} completed and produced a bounded evidence receipt."
                if return_code == 0
                else (f"{spec.name} failed with exit code {return_code}; no finding was inferred.")
            ),
        )
        return capture

    @staticmethod
    def _tool_environment(
        executable: Path,
        workspace: Path,
        private_home: Path,
    ) -> dict[str, str]:
        java_options = "-Xms64m -Xmx4096m -XX:MaxMetaspaceSize=512m"
        return {
            "PATH": f"{executable.parent}:{_DEFAULT_PATH}",
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
            "JAVA_TOOL_OPTIONS": java_options,
            "_JAVA_OPTIONS": java_options,
        }

    def _enrich_capture(
        self,
        capture: MobileToolCapture,
        workspace: Path,
    ) -> MobileToolCapture:
        evidence = dict(capture.evidence)
        if capture.return_code == 0 and capture.tool in {
            "androguard",
            "yara",
            "radare2",
        }:
            payload = self._json_object(capture.output)
            if payload is not None:
                evidence["structured"] = payload
        elif capture.return_code == 0 and capture.tool == "ghidra":
            for line in capture.output.splitlines():
                match = _JSON_LINE.fullmatch(line.strip())
                if match is None:
                    continue
                payload = self._json_object(match.group(1))
                if payload is not None:
                    evidence["structured"] = payload
                    break
        elif capture.return_code == 0 and capture.tool == "jadx":
            root = workspace / "jadx-output"
            files = (
                [item for item in root.rglob("*") if item.is_file() and not item.is_symlink()]
                if root.is_dir()
                else []
            )
            evidence["generated_files"] = len(files)
            evidence["generated_bytes"] = sum(item.stat().st_size for item in files)
            evidence["source_files"] = sum(item.suffix in {".java", ".kt"} for item in files)
        return capture.model_copy(update={"evidence": evidence})

    def _observations(
        self,
        record: MobileArtifactRecord,
        captures: tuple[MobileToolCapture, ...],
        workspace: Path,
    ) -> list[dict[str, object]]:
        observations = self._base_observations(record, captures)
        observations.extend(self._manifest_observations(record, captures, workspace))
        for capture in captures:
            structured = capture.evidence.get("structured")
            if not isinstance(structured, dict):
                continue
            if capture.tool == "androguard":
                observations.extend(self._androguard_observations(record, structured))
            elif capture.tool == "yara":
                observations.extend(self._yara_observations(capture, structured))
            elif capture.tool == "radare2":
                observations.extend(self._radare_observations(capture, structured))
            elif capture.tool == "ghidra":
                observations.extend(self._ghidra_observations(capture, structured))
        return observations

    @staticmethod
    def _base_observations(
        record: MobileArtifactRecord,
        captures: tuple[MobileToolCapture, ...],
    ) -> list[dict[str, object]]:
        observations: list[dict[str, object]] = []
        if record.native_libraries:
            observations.append(
                {
                    "observation_id": f"mobile-native-{record.sha256[:20]}",
                    "title": ("APK contains native libraries requiring native-code scrutiny"),
                    "status": "evidence_required",
                    "count": len(record.native_libraries),
                    "abis": list(record.native_abis),
                }
            )
        for capture in captures:
            if capture.return_code == 0:
                continue
            observations.append(
                {
                    "observation_id": (f"mobile-tool-{capture.tool}-{capture.output_sha256[:16]}"),
                    "title": f"{capture.tool} could not complete static inspection",
                    "status": "operational_failure",
                    "return_code": capture.return_code,
                    "evidence": {
                        "tool": capture.tool,
                        "output_sha256": capture.output_sha256,
                    },
                }
            )
        return observations

    @staticmethod
    def _manifest_observations(
        record: MobileArtifactRecord,
        captures: tuple[MobileToolCapture, ...],
        workspace: Path,
    ) -> list[dict[str, object]]:
        apktool_capture = next(
            (item for item in captures if item.tool == "apktool"),
            None,
        )
        decoded_manifest = workspace / "apktool-decoded" / "AndroidManifest.xml"
        if (
            apktool_capture is None
            or apktool_capture.return_code != 0
            or not decoded_manifest.is_file()
        ):
            return []
        observations: list[dict[str, object]] = []
        for finding in analyze_decoded_manifest(
            decoded_manifest,
            artifact_sha256=record.sha256,
        ):
            status = (
                "evidence_required"
                if finding.weakness_id == "android-dangerous-permissions"
                else "verified_configuration"
            )
            observations.append(
                {
                    "observation_id": finding.finding_id,
                    "weakness_id": finding.weakness_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": status,
                    "component": finding.component,
                    "evidence": finding.evidence,
                    "tool_ids": list(finding.tool_ids),
                }
            )
        return observations

    @staticmethod
    def _androguard_observations(
        record: MobileArtifactRecord,
        structured: dict[str, object],
    ) -> list[dict[str, object]]:
        dangerous = structured.get("dangerous_permissions")
        if not isinstance(dangerous, list) or not dangerous:
            return []
        return [
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
        ]

    def _yara_observations(
        self,
        capture: MobileToolCapture,
        structured: dict[str, object],
    ) -> list[dict[str, object]]:
        matches = structured.get("matches")
        if not isinstance(matches, list):
            return []
        observations: list[dict[str, object]] = []
        for index, raw_match in enumerate(matches[:250], start=1):
            if not isinstance(raw_match, dict):
                continue
            raw_meta = raw_match.get("meta")
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            rule = str(raw_match.get("rule") or f"rule-{index}")
            component = str(raw_match.get("file") or "APK content")
            identity_source = f"{rule}:{component}"
            identity = hashlib.sha256(identity_source.encode()).hexdigest()[:20]
            observations.append(
                {
                    "observation_id": f"yara-{identity}",
                    "weakness_id": str(meta.get("weakness_id") or "mobile-yara-match"),
                    "title": str(meta.get("title") or f"YARA rule matched: {rule}"),
                    "severity": str(meta.get("severity") or "unknown"),
                    "status": str(meta.get("confidence") or "evidence_required"),
                    "component": component,
                    "evidence": {
                        "rule": rule,
                        "namespace": raw_match.get("namespace", ""),
                        "tags": raw_match.get("tags", []),
                        "strings": raw_match.get("strings", []),
                        "ruleset_sha256": capture.evidence.get(
                            "ruleset_sha256",
                            "",
                        ),
                    },
                    "tool_ids": ["yara"],
                }
            )
        return observations

    @classmethod
    def _radare_observations(
        cls,
        capture: MobileToolCapture,
        structured: dict[str, object],
    ) -> list[dict[str, object]]:
        observations: list[dict[str, object]] = []
        hardening = cls._native_hardening(structured)
        evidence_identity = hashlib.sha256(str(capture.evidence).encode()).hexdigest()[:16]
        for name, present in hardening.items():
            if present is not False:
                continue
            observations.append(
                {
                    "observation_id": f"native-{name}-{evidence_identity}",
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
    def _ghidra_observations(
        capture: MobileToolCapture,
        structured: dict[str, object],
    ) -> list[dict[str, object]]:
        count = structured.get("jni_export_count")
        if not isinstance(count, int) or count <= 0:
            return []
        library = str(capture.evidence.get("library") or "native library")
        identity = hashlib.sha256(library.encode()).hexdigest()[:16]
        return [
            {
                "observation_id": f"native-jni-surface-{identity}",
                "weakness_id": "mobile-native-jni-surface",
                "title": "Native library exposes JNI entry points",
                "severity": "info",
                "status": "evidence_required",
                "component": library,
                "evidence": {
                    "jni_export_count": count,
                    "jni_exports": structured.get("jni_exports", []),
                    "tool_output_sha256": capture.output_sha256,
                },
                "tool_ids": ["ghidra"],
            }
        ]

    @staticmethod
    def _native_hardening(
        payload: dict[str, object],
    ) -> dict[str, bool | None]:
        raw_info = payload.get("info")
        info = raw_info if isinstance(raw_info, dict) else payload

        def boolean(*names: str) -> bool | None:
            for name in names:
                value = info.get(name)
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

    def enforce_workspace_bound(self, workspace: Path) -> None:
        total = 0
        for path in workspace.rglob("*"):
            if path.is_symlink():
                raise MobileStaticToolchainError("analysis workspace contains a symbolic link")
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size > self.policy.maximum_generated_file_bytes:
                raise MobileStaticToolchainError("tool generated an oversized workspace file")
            total += size
            if total > self.policy.maximum_generated_bytes:
                raise MobileStaticToolchainError("tool generated an oversized analysis workspace")

    @staticmethod
    def _json_object(value: str) -> dict[str, object] | None:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _verified_regular_file(
        path: Path,
        *,
        executable: bool,
        label: str,
    ) -> Path:
        if path.is_symlink():
            raise MobileStaticToolchainError(f"{label} must not be a symbolic link")
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise MobileStaticToolchainError(f"{label} is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise MobileStaticToolchainError(f"{label} is not a regular file")
        if executable and not os.access(resolved, os.X_OK):
            raise MobileStaticToolchainError(f"{label} is not executable")
        return resolved

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _emit(callback: ProgressCallback | None, **payload: object) -> None:
        if callback is None:
            return
        callback({"at": datetime.now(UTC).isoformat(), **payload})


__all__ = [
    "MobileStaticToolchain",
    "MobileStaticToolchainError",
    "MobileStaticWorkerPolicy",
    "MobileToolCapture",
    "ProgressCallback",
]
