"""Networkless, read-only static APK worker boundary."""

from __future__ import annotations

import hashlib
import os
import resource
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.mobile.artifacts import MobileArtifactError, copy_artifact_for_analysis
from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.security import redact_text


class MobileStaticWorkerError(RuntimeError):
    """Raised when static mobile analysis cannot preserve its safety boundary."""


class MobileStaticWorkerPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    enabled: bool = False
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    workspace_root: Path
    aapt2_executable: Path | None = None
    apksigner_executable: Path | None = None
    apkid_executable: Path | None = None
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    maximum_output_bytes: int = Field(default=500_000, ge=4_096, le=2_000_000)
    networkless_runtime_required: Literal[True] = True

    @field_validator(
        "workspace_root",
        "aapt2_executable",
        "apksigner_executable",
        "apkid_executable",
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
    def require_tool_when_enabled(self):
        if self.enabled and not any(
            (self.aapt2_executable, self.apksigner_executable, self.apkid_executable)
        ):
            raise ValueError("enabled mobile static worker requires at least one fixed tool")
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


class MobileToolCapture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    return_code: int
    output: str
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool


class MobileStaticAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    state: Literal["completed", "blocked", "failed"]
    captures: tuple[MobileToolCapture, ...] = ()
    candidate_observations: tuple[dict[str, object], ...] = ()
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)


class MobileStaticWorker:
    """Run fixed metadata tools against a read-only APK copy; never execute the APK."""

    def __init__(self, policy: MobileStaticWorkerPolicy) -> None:
        self.policy = policy

    def analyze(self, record: MobileArtifactRecord) -> MobileStaticAnalysisResult:
        now = datetime.now(UTC)
        if not self.policy.enabled:
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="blocked",
                completed_at=now,
                reason="Mobile static worker is disabled by worker policy.",
            )
        workspace = self.policy.workspace_root / record.artifact_id
        try:
            apk = copy_artifact_for_analysis(record, workspace)
            captures = tuple(self._run_all(apk, workspace))
        except (OSError, MobileArtifactError, MobileStaticWorkerError) as exc:
            return MobileStaticAnalysisResult(
                artifact_id=record.artifact_id,
                state="failed",
                completed_at=datetime.now(UTC),
                reason=f"Mobile static analysis failed closed: {type(exc).__name__}.",
            )
        observations: list[dict[str, object]] = []
        if record.native_libraries:
            observations.append(
                {
                    "observation_id": f"mobile-native-{record.sha256[:20]}",
                    "title": "APK contains native libraries",
                    "status": "candidate",
                    "count": len(record.native_libraries),
                    "abis": list(record.native_abis),
                }
            )
        for capture in captures:
            if capture.return_code != 0:
                observations.append(
                    {
                        "observation_id": (f"mobile-tool-{capture.tool}-{record.sha256[:16]}"),
                        "title": f"{capture.tool} could not complete static inspection",
                        "status": "candidate",
                        "return_code": capture.return_code,
                    }
                )
        result = MobileStaticAnalysisResult(
            artifact_id=record.artifact_id,
            state="completed",
            captures=captures,
            candidate_observations=tuple(observations),
            completed_at=datetime.now(UTC),
            reason="Read-only static APK inspection completed.",
        )
        output = workspace / "static-analysis.json"
        self._write_exclusive(output, result.model_dump_json(indent=2) + "\n")
        return result

    def _run_all(self, apk: Path, workspace: Path):
        commands = (
            ("aapt2", self.policy.aapt2_executable, ("dump", "badging", str(apk))),
            (
                "apksigner",
                self.policy.apksigner_executable,
                ("verify", "--print-certs", str(apk)),
            ),
            ("apkid", self.policy.apkid_executable, ("-j", str(apk))),
        )
        for tool, executable, arguments in commands:
            if executable is None:
                continue
            yield self._run_tool(tool, executable, arguments, workspace)

    def _run_tool(
        self,
        tool: str,
        executable: Path,
        arguments: tuple[str, ...],
        workspace: Path,
    ) -> MobileToolCapture:
        if executable.is_symlink():
            raise MobileStaticWorkerError(f"{tool} executable must not be a symbolic link")
        try:
            resolved = executable.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise MobileStaticWorkerError(f"{tool} executable is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise MobileStaticWorkerError(f"{tool} executable is unsafe")
        output_path = workspace / f".{tool}.capture"
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

        def apply_limits() -> None:
            maximum = self.policy.maximum_output_bytes
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (self.policy.timeout_seconds, self.policy.timeout_seconds + 1),
            )

        try:
            with os.fdopen(descriptor, "wb") as capture:
                completed = subprocess.run(
                    (str(resolved), *arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=capture,
                    stderr=subprocess.STDOUT,
                    cwd=workspace,
                    env={
                        "PATH": str(resolved.parent),
                        "HOME": "/nonexistent",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "NO_PROXY": "*",
                        "no_proxy": "*",
                    },
                    timeout=self.policy.timeout_seconds,
                    check=False,
                    preexec_fn=apply_limits,
                )
            raw = output_path.read_bytes()
        except subprocess.TimeoutExpired:
            raw = b"tool timed out"
            return_code = 124
        else:
            return_code = completed.returncode
        finally:
            output_path.unlink(missing_ok=True)
        truncated = len(raw) > self.policy.maximum_output_bytes
        bounded = raw[: self.policy.maximum_output_bytes]
        text = redact_text(bounded.decode("utf-8", errors="replace"))
        return MobileToolCapture(
            tool=tool,
            return_code=return_code,
            output=text,
            output_sha256=hashlib.sha256(bounded).hexdigest(),
            truncated=truncated,
        )

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
