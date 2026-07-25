"""Signed disposable Android runtime boundary for approved ADB and Frida checks."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import resource
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.security import redact_text

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DEVICE_REFERENCE = re.compile(r"^[A-Za-z0-9._:@-]{1,255}$")
ProgressCallback = Callable[[dict[str, object]], None]


class MobileRuntimeError(RuntimeError):
    """Raised when dynamic analysis cannot preserve its exact runtime contract."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("runtime timestamps must be timezone-aware")
    return value.astimezone(UTC)


class MobileRuntimePolicy(BaseModel):
    """Owner-private identity and fixed executables for one disposable emulator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    enabled: bool = False
    runtime_id: str
    adb_executable: Path
    python_executable: Path
    frida_executable: Path
    frida_inventory_adapter: Path
    adb_serial: str
    frida_device_id: str
    expected_fingerprint: str
    expected_api_level: int = Field(ge=23, le=99)
    expected_abi: str = Field(min_length=2, max_length=64)
    expected_frida_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    expires_at: datetime
    disposable: bool = True
    emulator_required: bool = True
    maximum_command_seconds: int = Field(default=120, ge=5, le=600)
    maximum_session_seconds: int = Field(default=900, ge=30, le=3_600)
    maximum_output_bytes: int = Field(default=1_000_000, ge=4_096, le=10_000_000)
    maximum_memory_bytes: int = Field(
        default=2_000_000_000,
        ge=256_000_000,
        le=8_000_000_000,
    )

    @field_validator("runtime_id")
    @classmethod
    def validate_runtime_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("runtime_id must be a stable lowercase identifier")
        return value

    @field_validator(
        "adb_executable",
        "python_executable",
        "frida_executable",
        "frida_inventory_adapter",
    )
    @classmethod
    def validate_paths(cls, value: Path) -> Path:
        candidate = value.expanduser()
        if not candidate.is_absolute():
            raise ValueError("runtime executable and adapter paths must be absolute")
        return candidate

    @field_validator("adb_serial", "frida_device_id")
    @classmethod
    def validate_device_reference(cls, value: str) -> str:
        if _DEVICE_REFERENCE.fullmatch(value) is None:
            raise ValueError("runtime device reference is invalid")
        return value

    @field_validator("expected_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not 8 <= len(normalized) <= 512:
            raise ValueError("runtime fingerprint is invalid")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.enabled and (not self.disposable or not self.emulator_required):
            raise ValueError("enabled runtime must be a disposable emulator")
        return self

    @classmethod
    def from_path(cls, path: Path) -> MobileRuntimePolicy:
        candidate = path.expanduser()
        if candidate.is_symlink():
            raise MobileRuntimeError("runtime policy must not be a symbolic link")
        try:
            metadata = candidate.stat()
            content = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise MobileRuntimeError("runtime policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise MobileRuntimeError("runtime policy permissions are unsafe")
        try:
            return cls.model_validate_json(content)
        except ValueError as exc:
            raise MobileRuntimeError("runtime policy is invalid") from exc


class SignedMobileRuntimeApproval(BaseModel):
    """Exact digest-bound approval for one APK, package and disposable runtime."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    approval_id: str
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_name: str
    runtime_id: str
    adb_serial: str
    frida_device_id: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("approval_id", "runtime_id", "approved_by")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("runtime approval identifier is invalid")
        return value

    @field_validator("package_name")
    @classmethod
    def validate_package(cls, value: str) -> str:
        if _PACKAGE.fullmatch(value) is None:
            raise ValueError("runtime approval package name is invalid")
        return value

    @field_validator("adb_serial", "frida_device_id")
    @classmethod
    def validate_device_reference(cls, value: str) -> str:
        if _DEVICE_REFERENCE.fullmatch(value) is None:
            raise ValueError("runtime approval device reference is invalid")
        return value

    @field_validator("approved_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("runtime approval must expire after approval")
        return self

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def expected_signature(self, key: bytes) -> str:
        encoded = json.dumps(
            self.unsigned_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, encoded, hashlib.sha256).hexdigest()

    def verify(
        self,
        *,
        key: bytes,
        policy: MobileRuntimePolicy,
        artifact_sha256: str,
        plan_sha256: str,
        package_name: str,
        now: datetime,
    ) -> None:
        if not hmac.compare_digest(self.signature, self.expected_signature(key)):
            raise MobileRuntimeError("runtime approval signature is invalid")
        current = _utc(now)
        if current < self.approved_at or current >= self.expires_at:
            raise MobileRuntimeError("runtime approval is not currently valid")
        if policy.expires_at <= current:
            raise MobileRuntimeError("registered disposable runtime has expired")
        expected = {
            "runtime_id": policy.runtime_id,
            "adb_serial": policy.adb_serial,
            "frida_device_id": policy.frida_device_id,
            "artifact_sha256": artifact_sha256,
            "plan_sha256": plan_sha256,
            "package_name": package_name,
        }
        actual = {
            "runtime_id": self.runtime_id,
            "adb_serial": self.adb_serial,
            "frida_device_id": self.frida_device_id,
            "artifact_sha256": self.artifact_sha256,
            "plan_sha256": self.plan_sha256,
            "package_name": self.package_name,
        }
        if actual != expected:
            raise MobileRuntimeError("runtime approval does not match the exact execution")

    @classmethod
    def create(
        cls,
        *,
        approval_id: str,
        plan_sha256: str,
        artifact_sha256: str,
        package_name: str,
        runtime_id: str,
        adb_serial: str,
        frida_device_id: str,
        approved_by: str,
        approved_at: datetime,
        expires_at: datetime,
        key: bytes,
    ) -> SignedMobileRuntimeApproval:
        provisional = cls.model_construct(
            schema_version="1.0",
            approval_id=approval_id,
            plan_sha256=plan_sha256,
            artifact_sha256=artifact_sha256,
            package_name=package_name,
            runtime_id=runtime_id,
            adb_serial=adb_serial,
            frida_device_id=frida_device_id,
            approved_by=approved_by,
            approved_at=_utc(approved_at),
            expires_at=_utc(expires_at),
            signature="0" * 64,
        )
        return cls(
            **provisional.model_dump(exclude={"signature"}),
            signature=provisional.expected_signature(key),
        )


class MobileRuntimeCapture(BaseModel):
    """One bounded dynamic execution receipt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    return_code: int
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output: str
    truncated: bool
    duration_ms: int = Field(ge=0)
    evidence: dict[str, object] = Field(default_factory=dict)


class MobileRuntimeResult(BaseModel):
    """Terminal receipt from one approved disposable runtime session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_name: str
    state: Literal["completed", "failed", "blocked"]
    device_identity: dict[str, object] = Field(default_factory=dict)
    captures: tuple[MobileRuntimeCapture, ...] = ()
    completed_at: datetime
    reason: str = Field(min_length=3, max_length=500)
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MobileRuntimeExecutor:
    """Install, inspect and remove one APK using only fixed ADB/Frida actions."""

    def __init__(self, policy: MobileRuntimePolicy) -> None:
        self.policy = policy

    def readiness(self, *, now: datetime | None = None) -> dict[str, object]:
        current = _utc(now or datetime.now(UTC))
        if not self.policy.enabled:
            return {"ready": False, "reason": "runtime policy is disabled"}
        if self.policy.expires_at <= current:
            return {"ready": False, "reason": "runtime registration has expired"}
        try:
            identity = self._verify_device_identity()
            frida_version = self._frida_version()
        except MobileRuntimeError as exc:
            return {"ready": False, "reason": str(exc)}
        return {
            "ready": True,
            "runtime_id": self.policy.runtime_id,
            "device_identity": identity,
            "frida_version": frida_version,
            "expires_at": self.policy.expires_at.isoformat(),
        }

    def execute(
        self,
        *,
        apk_path: Path,
        artifact_sha256: str,
        package_name: str,
        plan_sha256: str,
        approval: SignedMobileRuntimeApproval,
        approval_key: bytes,
        now: datetime | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> MobileRuntimeResult:
        current = _utc(now or datetime.now(UTC))
        if not self.policy.enabled:
            return self._terminal(
                artifact_sha256=artifact_sha256,
                package_name=package_name,
                state="blocked",
                captures=(),
                device_identity={},
                reason="Disposable Android runtime is disabled by policy.",
            )
        if _PACKAGE.fullmatch(package_name) is None:
            raise MobileRuntimeError("Android package name is invalid")
        approval.verify(
            key=approval_key,
            policy=self.policy,
            artifact_sha256=artifact_sha256,
            plan_sha256=plan_sha256,
            package_name=package_name,
            now=current,
        )
        apk = self._verified_apk(apk_path, artifact_sha256=artifact_sha256)
        started = time.monotonic()
        captures: list[MobileRuntimeCapture] = []
        installed = False
        identity: dict[str, object] = {}
        failure: Exception | None = None
        try:
            self._emit(
                progress_callback,
                state="running",
                stage="runtime_identity",
                detail="Verifying the exact disposable emulator identity.",
            )
            identity = self._verify_device_identity()
            self._frida_version()
            captures.append(
                self._run_adb(
                    "install",
                    ("install", "-r", "-t", str(apk)),
                )
            )
            installed = captures[-1].return_code == 0
            if not installed:
                raise MobileRuntimeError("ADB could not install the approved APK")
            self._emit(
                progress_callback,
                state="running",
                stage="runtime_launch",
                tool="adb",
                tool_state="running",
                detail="Launching the approved package in the disposable emulator.",
            )
            captures.append(
                self._run_adb(
                    "launch",
                    (
                        "shell",
                        "monkey",
                        "-p",
                        package_name,
                        "-c",
                        "android.intent.category.LAUNCHER",
                        "1",
                    ),
                )
            )
            if captures[-1].return_code != 0:
                raise MobileRuntimeError("ADB could not launch the approved package")
            time.sleep(2)
            self._emit(
                progress_callback,
                state="running",
                stage="runtime_inventory",
                tool="frida",
                tool_state="running",
                detail="Collecting the fixed Frida module and loaded-class inventory.",
            )
            captures.append(self._run_frida_inventory(package_name))
            if captures[-1].return_code != 0:
                raise MobileRuntimeError("Frida inventory could not complete")
        except (OSError, subprocess.SubprocessError, MobileRuntimeError) as exc:
            failure = exc
        finally:
            if installed:
                captures.extend(self._cleanup(package_name))
        if time.monotonic() - started > self.policy.maximum_session_seconds:
            failure = MobileRuntimeError("runtime session exceeded the configured duration")
        if failure is not None:
            self._emit(
                progress_callback,
                state="failed",
                stage="runtime_cleanup",
                detail=f"Runtime session failed closed: {type(failure).__name__}.",
            )
            return self._terminal(
                artifact_sha256=artifact_sha256,
                package_name=package_name,
                state="failed",
                captures=tuple(captures),
                device_identity=identity,
                reason=f"Runtime session failed closed: {type(failure).__name__}.",
            )
        self._emit(
            progress_callback,
            state="completed",
            stage="runtime_cleanup",
            detail="Runtime inventory completed and the approved package was removed.",
        )
        return self._terminal(
            artifact_sha256=artifact_sha256,
            package_name=package_name,
            state="completed",
            captures=tuple(captures),
            device_identity=identity,
            reason="Approved disposable ADB and Frida runtime inventory completed.",
        )

    def _verify_device_identity(self) -> dict[str, object]:
        state = self._run_adb("get-state", ("get-state",))
        if state.return_code != 0 or state.output.strip() != "device":
            raise MobileRuntimeError("registered ADB device is not online")
        qemu = self._adb_property("ro.boot.qemu")
        fingerprint = self._adb_property("ro.build.fingerprint")
        api_level = self._adb_property("ro.build.version.sdk")
        abi = self._adb_property("ro.product.cpu.abi")
        if self.policy.emulator_required and qemu != "1":
            raise MobileRuntimeError("registered Android device is not an emulator")
        if fingerprint != self.policy.expected_fingerprint:
            raise MobileRuntimeError("Android build fingerprint changed")
        try:
            parsed_api = int(api_level)
        except ValueError as exc:
            raise MobileRuntimeError("Android API level is invalid") from exc
        if parsed_api != self.policy.expected_api_level:
            raise MobileRuntimeError("Android API level changed")
        if abi != self.policy.expected_abi:
            raise MobileRuntimeError("Android ABI changed")
        return {
            "adb_serial": self.policy.adb_serial,
            "frida_device_id": self.policy.frida_device_id,
            "fingerprint": fingerprint,
            "api_level": parsed_api,
            "abi": abi,
            "emulator": True,
        }

    def _adb_property(self, name: str) -> str:
        capture = self._run_adb(f"getprop-{name}", ("shell", "getprop", name))
        if capture.return_code != 0:
            raise MobileRuntimeError(f"ADB could not read {name}")
        return capture.output.strip()

    def _frida_version(self) -> str:
        executable = self._verified_file(
            self.policy.frida_executable,
            executable=True,
            label="Frida executable",
        )
        capture = self._run_command(
            action="frida-version",
            command=(str(executable), "--version"),
            timeout_seconds=30,
        )
        version = capture.output.strip()
        if capture.return_code != 0 or version != self.policy.expected_frida_version:
            raise MobileRuntimeError("Frida client version does not match runtime policy")
        return version

    def _run_adb(self, action: str, arguments: tuple[str, ...]) -> MobileRuntimeCapture:
        executable = self._verified_file(
            self.policy.adb_executable,
            executable=True,
            label="ADB executable",
        )
        return self._run_command(
            action=f"adb-{action}",
            command=(str(executable), "-s", self.policy.adb_serial, *arguments),
            timeout_seconds=self.policy.maximum_command_seconds,
        )

    def _run_frida_inventory(self, package_name: str) -> MobileRuntimeCapture:
        python = self._verified_file(
            self.policy.python_executable,
            executable=True,
            label="runtime Python executable",
        )
        adapter = self._verified_file(
            self.policy.frida_inventory_adapter,
            executable=False,
            label="Frida inventory adapter",
        )
        capture = self._run_command(
            action="frida-inventory",
            command=(
                str(python),
                str(adapter),
                "--device-id",
                self.policy.frida_device_id,
                "--package",
                package_name,
                "--timeout-seconds",
                "30",
            ),
            timeout_seconds=60,
        )
        if capture.return_code != 0:
            return capture
        try:
            payload = json.loads(capture.output)
        except ValueError:
            return capture.model_copy(
                update={
                    "return_code": 2,
                    "evidence": {"reason": "Frida adapter returned invalid JSON"},
                }
            )
        if not isinstance(payload, dict):
            return capture.model_copy(
                update={
                    "return_code": 2,
                    "evidence": {"reason": "Frida adapter returned invalid evidence"},
                }
            )
        if payload.get("frida_version") != self.policy.expected_frida_version:
            raise MobileRuntimeError("Frida server/client evidence version changed")
        return capture.model_copy(update={"evidence": payload})

    def _cleanup(self, package_name: str) -> tuple[MobileRuntimeCapture, ...]:
        captures = [
            self._run_adb(
                "force-stop",
                ("shell", "am", "force-stop", package_name),
            ),
            self._run_adb("uninstall", ("uninstall", package_name)),
        ]
        return tuple(captures)

    def _run_command(
        self,
        *,
        action: str,
        command: tuple[str, ...],
        timeout_seconds: int,
    ) -> MobileRuntimeCapture:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout_seconds,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/nonexistent",
                    "TMPDIR": "/tmp",
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
                preexec_fn=self._apply_limits,
            )
            raw = completed.stdout
            return_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            raw = bytes(exc.stdout or b"") + b"\ncommand timed out"
            return_code = 124
        truncated = len(raw) > self.policy.maximum_output_bytes
        bounded = raw[: self.policy.maximum_output_bytes]
        return MobileRuntimeCapture(
            action=action,
            return_code=return_code,
            output_sha256=hashlib.sha256(bounded).hexdigest(),
            output=redact_text(bounded.decode("utf-8", errors="replace")),
            truncated=truncated,
            duration_ms=max(0, int((time.monotonic() - started) * 1_000)),
        )

    def _apply_limits(self) -> None:
        output = self.policy.maximum_output_bytes
        resource.setrlimit(resource.RLIMIT_FSIZE, (output, output))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        memory = self.policy.maximum_memory_bytes
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        os.umask(0o077)

    @staticmethod
    def _verified_file(path: Path, *, executable: bool, label: str) -> Path:
        if path.is_symlink():
            raise MobileRuntimeError(f"{label} must not be a symbolic link")
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise MobileRuntimeError(f"{label} is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise MobileRuntimeError(f"{label} is not a regular file")
        if executable and not os.access(resolved, os.X_OK):
            raise MobileRuntimeError(f"{label} is not executable")
        return resolved

    @classmethod
    def _verified_apk(cls, path: Path, *, artifact_sha256: str) -> Path:
        if _SHA256.fullmatch(artifact_sha256) is None:
            raise MobileRuntimeError("artifact digest is invalid")
        apk = cls._verified_file(path, executable=False, label="runtime APK")
        if apk.suffix.casefold() != ".apk":
            raise MobileRuntimeError("runtime input is not an APK")
        digest = hashlib.sha256()
        with apk.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact_sha256:
            raise MobileRuntimeError("runtime APK does not match the ingested artifact")
        return apk

    def _terminal(
        self,
        *,
        artifact_sha256: str,
        package_name: str,
        state: Literal["completed", "failed", "blocked"],
        captures: tuple[MobileRuntimeCapture, ...],
        device_identity: dict[str, object],
        reason: str,
    ) -> MobileRuntimeResult:
        completed_at = datetime.now(UTC)
        unsigned = {
            "runtime_id": self.policy.runtime_id,
            "artifact_sha256": artifact_sha256,
            "package_name": package_name,
            "state": state,
            "device_identity": device_identity,
            "captures": [item.model_dump(mode="json") for item in captures],
            "completed_at": completed_at.isoformat(),
            "reason": reason,
        }
        digest = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return MobileRuntimeResult(
            runtime_id=self.policy.runtime_id,
            artifact_sha256=artifact_sha256,
            package_name=package_name,
            state=state,
            device_identity=device_identity,
            captures=captures,
            completed_at=completed_at,
            reason=reason,
            receipt_sha256=digest,
        )

    @staticmethod
    def _emit(callback: ProgressCallback | None, **payload: object) -> None:
        if callback is None:
            return
        callback({"at": datetime.now(UTC).isoformat(), **payload})


__all__ = [
    "MobileRuntimeCapture",
    "MobileRuntimeError",
    "MobileRuntimeExecutor",
    "MobileRuntimePolicy",
    "MobileRuntimeResult",
    "SignedMobileRuntimeApproval",
]
