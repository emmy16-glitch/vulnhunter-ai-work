"""Passive-only isolated Nuclei worker pilot.

This module is never enabled by a browser request. A worker-local policy file must
be mounted with ``enabled=true`` after the operator has installed the pinned
Nuclei binary and reviewed the private laboratory target. The existing manager
still owns authorization, scope, approval, evidence, and finding state.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import resource
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.security import redact_text
from vulnhunter.security_tools.nuclei_activation import (
    NucleiCancellationError,
    NucleiTemplateManifest,
    NucleiTimeoutError,
    ProcessGroupTerminator,
    TemplateRiskClass,
)
from vulnhunter.security_tools.nuclei_execution import (
    BoundedTextCapture,
    NucleiExecutionError,
    NucleiExecutionHarness,
    NucleiExecutionInvocation,
    NucleiExecutionRecord,
    NucleiRunnerResult,
    NucleiValidatedSpecification,
    _StoreAwareRunControl,
)
from vulnhunter.security_tools.scanner_protocol import (
    ScannerCandidateObservation,
    ScannerJobState,
)


class NucleiPilotPolicy(BaseModel):
    """Worker-owned activation policy; never accepted from assessment form data."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    enabled: bool = False
    worker_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    nuclei_executable: Path
    template_root: Path
    maximum_rate_limit: int = Field(default=1, ge=1, le=1)
    maximum_concurrency: int = Field(default=1, ge=1, le=1)
    maximum_observations: int = Field(default=250, ge=1, le=1_000)
    poll_interval_seconds: float = Field(default=0.1, ge=0.02, le=1.0)
    private_targets_only: bool = True

    @field_validator("nuclei_executable", "template_root")
    @classmethod
    def require_absolute_paths(cls, value: Path) -> Path:
        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("worker paths must be absolute")
        return expanded

    @model_validator(mode="after")
    def preserve_pilot_boundary(self):
        if not self.private_targets_only:
            raise ValueError("the pilot is restricted to private laboratory targets")
        return self

    @classmethod
    def from_path(cls, path: Path) -> NucleiPilotPolicy:
        expanded = path.expanduser()
        if expanded.is_symlink():
            raise NucleiExecutionError("worker policy must not be a symbolic link")
        try:
            metadata = expanded.stat()
            raw = expanded.read_text(encoding="utf-8")
        except OSError as exc:
            raise NucleiExecutionError("worker policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise NucleiExecutionError("worker policy must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise NucleiExecutionError("worker policy must not be group or world writable")
        try:
            return cls.model_validate_json(raw)
        except ValueError as exc:
            raise NucleiExecutionError("worker policy is invalid") from exc


class ProcessGroupTerminatorImpl(ProcessGroupTerminator):
    """Terminate the complete scanner process group after a bounded grace period."""

    def terminate_process_group(self, process_group_id: int, *, grace_seconds: float) -> None:
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group_id, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return


class PassiveNucleiProcessRunner:
    """Launch one fixed passive Nuclei command inside the isolated worker."""

    is_test_double = False

    def __init__(
        self,
        *,
        policy: NucleiPilotPolicy,
        template_manifest: NucleiTemplateManifest,
    ) -> None:
        self.policy = policy
        self.template_manifest = template_manifest

    def _validated_executable(self) -> Path:
        path = self.policy.nuclei_executable
        if path.is_symlink():
            raise NucleiExecutionError("Nuclei executable must not be a symbolic link")
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise NucleiExecutionError("Nuclei executable is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise NucleiExecutionError("Nuclei executable is not an executable regular file")
        return resolved

    def _selected_templates(self, specification: NucleiValidatedSpecification) -> tuple[Path, ...]:
        root = self.policy.template_root.resolve(strict=True)
        selected = set(specification.request.template_manifest_hashes)
        paths: list[Path] = []
        for entry in self.template_manifest.entries:
            if entry.fingerprint() not in selected:
                continue
            if not entry.enabled or entry.risk_class is not TemplateRiskClass.PASSIVE:
                raise NucleiExecutionError("the pilot accepts reviewed passive templates only")
            candidate = root.joinpath(*Path(entry.relative_path).parts)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise NucleiExecutionError(
                    "approved template is unavailable or escaped its root"
                ) from exc
            if resolved.is_symlink() or not resolved.is_file():
                raise NucleiExecutionError("approved template is not a regular file")
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if digest != entry.sha256:
                raise NucleiExecutionError("approved template digest changed before execution")
            paths.append(resolved)
        if not paths or len(paths) != len(selected):
            raise NucleiExecutionError(
                "the exact reviewed template selection could not be resolved"
            )
        return tuple(paths)

    def _validate_pilot_scope(self, specification: NucleiValidatedSpecification) -> str:
        request = specification.request
        if not self.policy.enabled:
            raise NucleiExecutionError("the isolated Nuclei worker pilot is disabled")
        if request.exact_profile != "passive":
            raise NucleiExecutionError("the pilot permits the passive profile only")
        if request.limits.rate_limit != 1 or request.limits.concurrency != 1:
            raise NucleiExecutionError("the pilot requires rate limit 1 and concurrency 1")
        if len(request.exact_targets) != 1:
            raise NucleiExecutionError("the pilot accepts exactly one target")
        target = request.exact_targets[0]
        if target.address_class != "private":
            raise NucleiExecutionError("the pilot accepts private laboratory targets only")
        try:
            literal = ipaddress.ip_address(target.hostname)
        except ValueError as exc:
            raise NucleiExecutionError(
                "the pilot requires a literal private IP target to prevent DNS rebinding"
            ) from exc
        if str(literal) not in target.resolved_addresses:
            raise NucleiExecutionError("the literal target is not present in the approved pins")
        for value in target.resolved_addresses:
            address = ipaddress.ip_address(value)
            if not address.is_private or address.is_link_local or address.is_loopback:
                raise NucleiExecutionError("the target address is outside the private-lab boundary")
        return target.url

    def run(
        self,
        specification: NucleiValidatedSpecification,
        *,
        control,
    ) -> NucleiRunnerResult:
        executable = self._validated_executable()
        target = self._validate_pilot_scope(specification)
        templates = self._selected_templates(specification)
        command = [
            str(executable),
            "-target",
            target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-no-interactsh",
            "-rate-limit",
            "1",
            "-concurrency",
            "1",
            "-bulk-size",
            "1",
            "-retries",
            "0",
            "-timeout",
            "5",
        ]
        for template in templates:
            command.extend(("-templates", str(template)))

        environment = {
            "PATH": str(executable.parent),
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        request = specification.request
        output_root = request.output_directory
        stdout_path = output_root / f".{request.execution_id}.stdout"
        stderr_path = output_root / f".{request.execution_id}.stderr"
        maximum_file_bytes = max(
            request.limits.maximum_stdout_bytes,
            request.limits.maximum_stderr_bytes,
        )

        def apply_limits() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum_file_bytes, maximum_file_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (request.limits.timeout_seconds + 1, request.limits.timeout_seconds + 2),
            )

        stdout_descriptor = os.open(
            stdout_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        stderr_descriptor = os.open(
            stderr_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with (
                open(os.devnull, "rb") as stdin_handle,
                os.fdopen(stdout_descriptor, "wb") as stdout_handle,
                os.fdopen(stderr_descriptor, "wb") as stderr_handle,
                subprocess.Popen(
                    command,
                    stdin=stdin_handle,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    env=environment,
                    cwd=output_root,
                    start_new_session=True,
                    text=False,
                    preexec_fn=apply_limits,
                ) as process,
            ):
                while process.poll() is None:
                    control.checkpoint(process_group_id=process.pid)
                    time.sleep(self.policy.poll_interval_seconds)
                return_code = process.returncode
            stdout_bytes = stdout_path.read_bytes()[: request.limits.maximum_stdout_bytes + 1]
            stderr_bytes = stderr_path.read_bytes()[: request.limits.maximum_stderr_bytes + 1]
        finally:
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        observations = self._parse_observations(stdout)
        if return_code != 0:
            return NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason=f"Nuclei exited with code {return_code}.",
                stdout=stdout,
                stderr=stderr,
                observations=observations,
            )
        return NucleiRunnerResult(
            state=ScannerJobState.COMPLETED,
            reason="Passive private-lab Nuclei worker completed.",
            stdout=stdout,
            stderr=stderr,
            observations=observations,
        )

    def _parse_observations(self, output: str) -> tuple[ScannerCandidateObservation, ...]:
        observations: list[ScannerCandidateObservation] = []
        for line in output.splitlines():
            if len(observations) >= self.policy.maximum_observations:
                break
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            template_id = str(item.get("template-id") or item.get("template_id") or "nuclei-match")
            matched = str(
                item.get("matched-at") or item.get("matched_at") or item.get("host") or ""
            )
            if not matched:
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            title = str(info.get("name") or template_id)
            severity = str(info.get("severity") or "info")
            fingerprint = hashlib.sha256(f"{template_id}\0{matched}".encode()).hexdigest()[:24]
            metadata = {
                "scanner": "nuclei",
                "template_id": template_id,
                "matcher_name": str(item.get("matcher-name") or "")[:200],
                "type": str(item.get("type") or "http")[:50],
            }
            observations.append(
                ScannerCandidateObservation(
                    observation_id=f"nuclei-{fingerprint}",
                    scanner_id="nuclei",
                    title=redact_text(title)[:500],
                    severity=redact_text(severity)[:32],
                    confidence="scanner_match",
                    target_reference=redact_text(matched)[:2_000],
                    template_id=template_id,
                    metadata=metadata,
                )
            )
        return tuple(observations)


class NucleiPilotExecutionHarness(NucleiExecutionHarness):
    """Run the real process only when the worker-local passive pilot policy is enabled."""

    def __init__(
        self,
        *,
        policy: NucleiPilotPolicy,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        **kwargs,
    ) -> None:
        super().__init__(maximum_concurrency=1, terminator=ProcessGroupTerminatorImpl(), **kwargs)
        self.policy = policy
        self.clock = clock

    def execute_pilot(self, invocation: NucleiExecutionInvocation) -> NucleiExecutionRecord:
        request = invocation.request
        self.store.prepare(request, actor_id=invocation.actor_id, now=invocation.now)
        if not self.policy.enabled:
            return self.store.transition(
                request.execution_id,
                ScannerJobState.BLOCKED_EXECUTION_DISABLED,
                actor_id=invocation.actor_id,
                reason="The isolated Nuclei worker pilot is disabled by worker policy.",
                now=self.clock(),
            )
        try:
            specification = self._revalidate(invocation)
        except (NucleiExecutionError, OSError, ValueError) as exc:
            return self.store.transition(
                request.execution_id,
                ScannerJobState.FAILED,
                actor_id=invocation.actor_id,
                reason=str(exc),
                now=self.clock(),
            )

        self.store.transition(
            request.execution_id,
            ScannerJobState.VALIDATED,
            actor_id=invocation.actor_id,
            reason="Authorization, approval, target, templates, and version pins revalidated.",
            now=self.clock(),
        )
        acquired = self._slots.acquire(blocking=False)
        if not acquired:
            return self.store.transition(
                request.execution_id,
                ScannerJobState.FAILED,
                actor_id=invocation.actor_id,
                reason="The passive worker already has an active job.",
                now=self.clock(),
            )
        self.store.transition(
            request.execution_id,
            ScannerJobState.STARTING,
            actor_id=invocation.actor_id,
            reason="The isolated passive scanner process is starting.",
            now=self.clock(),
        )
        self.store.transition(
            request.execution_id,
            ScannerJobState.RUNNING,
            actor_id=invocation.actor_id,
            reason="The isolated passive scanner process is running.",
            now=self.clock(),
        )
        control = _StoreAwareRunControl(
            store=self.store,
            execution_id=request.execution_id,
            timeout_seconds=request.limits.timeout_seconds,
            terminator=self.terminator,
            monotonic=self.monotonic,
            grace_seconds=request.limits.termination_grace_seconds,
        )
        try:
            result = self.runner.run(specification, control=control)
        except NucleiCancellationError as exc:
            result = NucleiRunnerResult(state=ScannerJobState.CANCELLED, reason=str(exc))
        except NucleiTimeoutError as exc:
            result = NucleiRunnerResult(state=ScannerJobState.TIMED_OUT, reason=str(exc))
        except Exception as exc:
            result = NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason=f"Isolated scanner failed closed: {type(exc).__name__}",
            )
        finally:
            self._slots.release()

        stdout = BoundedTextCapture.capture(
            result.stdout,
            maximum_bytes=request.limits.maximum_stdout_bytes,
        )
        stderr = BoundedTextCapture.capture(
            result.stderr,
            maximum_bytes=request.limits.maximum_stderr_bytes,
        )
        observations = self._sanitize_observations(result.observations)
        evidence = self._persist_summary(
            request=request,
            result=result,
            stdout=stdout,
            stderr=stderr,
            observations=observations,
        )
        current = self.store.load(request.execution_id)
        target_state = result.state
        if (
            current.state is ScannerJobState.CANCELLING
            and target_state is not ScannerJobState.CANCELLED
        ):
            target_state = ScannerJobState.CANCELLED
        return self.store.transition(
            request.execution_id,
            target_state,
            actor_id=invocation.actor_id,
            reason=result.reason,
            now=self.clock(),
            stdout=stdout,
            stderr=stderr,
            observations=observations,
            evidence=(evidence,),
        )


__all__ = [
    "NucleiPilotExecutionHarness",
    "NucleiPilotPolicy",
    "PassiveNucleiProcessRunner",
    "ProcessGroupTerminatorImpl",
]
