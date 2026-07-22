"""Restricted SSH runner for the signed passive Nuclei worker workflow."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from vulnhunter.security import redact_text
from vulnhunter.security_tools.nuclei_execution import (
    NucleiRunnerResult,
    NucleiValidatedSpecification,
)
from vulnhunter.security_tools.remote_nuclei_models import (
    REMOTE_NUCLEI_PROTOCOL_VERSION,
    RemoteNucleiCandidate,
    RemoteNucleiRequest,
    RemoteNucleiResult,
    RemoteNucleiWorkerError,
    RemoteNucleiWorkerPolicy,
)
from vulnhunter.security_tools.scanner_protocol import (
    ScannerCandidateObservation,
    ScannerJobState,
)

__all__ = [
    "REMOTE_NUCLEI_PROTOCOL_VERSION",
    "RemoteNucleiCandidate",
    "RemoteNucleiRequest",
    "RemoteNucleiResult",
    "RemoteNucleiWorkerError",
    "RemoteNucleiWorkerPolicy",
    "RestrictedSshNucleiRunner",
]


class RestrictedSshNucleiRunner:
    """Execute one fixed worker request through a dedicated restricted SSH key."""

    is_test_double = False

    def __init__(self, *, policy: RemoteNucleiWorkerPolicy) -> None:
        policy.validate_runtime_files()
        self.policy = policy

    def _ssh_command(self) -> tuple[str, ...]:
        policy = self.policy
        return (
            str(policy.ssh_executable),
            "-T",
            "-p",
            str(policy.remote_port),
            "-i",
            str(policy.identity_file),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={policy.known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            f"ConnectTimeout={policy.connect_timeout_seconds}",
            f"{policy.remote_user}@{policy.remote_host}",
        )

    def _request(
        self,
        *,
        operation: Literal["readiness", "scan"],
        reference: str,
        timeout_seconds: int,
        maximum_candidates: int,
    ) -> RemoteNucleiRequest:
        return RemoteNucleiRequest.create(
            operation=operation,
            request_id=reference,
            worker_id=self.policy.worker_id,
            logical_target=self.policy.logical_target,
            transport_target=self.policy.transport_target,
            engine_version=self.policy.engine_version,
            template_sha256=self.policy.template_sha256,
            timeout_seconds=timeout_seconds,
            maximum_candidates=maximum_candidates,
            issued_at=datetime.now(UTC),
        )

    @staticmethod
    def _terminate(process_group_id: int) -> None:
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            return
        time.sleep(0.2)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return

    def _exchange(self, request: RemoteNucleiRequest, *, control=None) -> RemoteNucleiResult:
        payload = (request.model_dump_json() + "\n").encode()
        environment = {
            "PATH": str(self.policy.ssh_executable.parent),
            "HOME": str(Path.home()),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        deadline = (
            time.monotonic()
            + request.timeout_seconds
            + self.policy.connect_timeout_seconds
            + 5
        )
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                self._ssh_command(),
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                env=environment,
                start_new_session=True,
            )
            try:
                if process.stdin is None:
                    raise RemoteNucleiWorkerError("restricted SSH stdin is unavailable")
                process.stdin.write(payload)
                process.stdin.close()
                while process.poll() is None:
                    if control is not None:
                        control.checkpoint(process_group_id=process.pid)
                    if time.monotonic() >= deadline:
                        raise RemoteNucleiWorkerError("remote worker exchange timed out")
                    time.sleep(self.policy.poll_interval_seconds)
            except Exception:
                self._terminate(process.pid)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                raise
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(self.policy.maximum_response_bytes + 1)
            stderr = stderr_file.read(16_385)

        if len(stdout) > self.policy.maximum_response_bytes:
            raise RemoteNucleiWorkerError("remote worker response exceeded the configured limit")
        if process.returncode != 0:
            reason = redact_text(stderr.decode("utf-8", errors="replace"))[:300]
            raise RemoteNucleiWorkerError(reason or "restricted SSH worker failed")
        try:
            result = RemoteNucleiResult.model_validate_json(stdout.decode("utf-8"))
        except ValueError as exc:
            raise RemoteNucleiWorkerError("remote worker returned an invalid response") from exc
        self._validate_binding(request, result)
        return result

    def _validate_binding(
        self,
        request: RemoteNucleiRequest,
        result: RemoteNucleiResult,
    ) -> None:
        if result.operation != request.operation:
            raise RemoteNucleiWorkerError("remote worker operation mismatch")
        if result.worker_id != self.policy.worker_id:
            raise RemoteNucleiWorkerError("remote worker identity mismatch")
        if result.request_digest != request.request_digest:
            raise RemoteNucleiWorkerError("remote worker response is bound to another request")
        if result.template_sha256 != self.policy.template_sha256:
            raise RemoteNucleiWorkerError("remote worker template digest differs from policy")
        if result.engine_version != self.policy.engine_version:
            raise RemoteNucleiWorkerError("remote worker engine pin differs from readiness")
        if result.candidate_count > self.policy.maximum_candidates:
            raise RemoteNucleiWorkerError("remote worker returned too many candidates")

    def verify_readiness(self) -> RemoteNucleiResult:
        request = self._request(
            operation="readiness",
            reference="readiness-check",
            timeout_seconds=self.policy.connect_timeout_seconds + 10,
            maximum_candidates=0,
        )
        return self._exchange(request)

    def _validate_specification(self, specification: NucleiValidatedSpecification) -> None:
        request = specification.request
        if request.exact_profile != "passive":
            raise RemoteNucleiWorkerError("remote worker accepts the passive profile only")
        if request.limits.rate_limit != 1 or request.limits.concurrency != 1:
            raise RemoteNucleiWorkerError("remote worker requires rate and concurrency of one")
        if len(request.exact_targets) != 1:
            raise RemoteNucleiWorkerError("remote worker accepts exactly one target")
        if request.exact_targets[0].url.rstrip("/") != self.policy.logical_target:
            raise RemoteNucleiWorkerError("approved logical target differs from remote policy")
        if self.policy.template_manifest_hash not in request.template_manifest_hashes:
            raise RemoteNucleiWorkerError("approved template selection differs from remote policy")

    def run(
        self,
        specification: NucleiValidatedSpecification,
        *,
        control,
    ) -> NucleiRunnerResult:
        self._validate_specification(specification)
        request = self._request(
            operation="scan",
            reference=specification.request.execution_id,
            timeout_seconds=min(specification.request.limits.timeout_seconds, 300),
            maximum_candidates=min(
                self.policy.maximum_candidates,
                specification.request.limits.maximum_stdout_bytes // 256,
            ),
        )
        result = self._exchange(request, control=control)
        state = {
            "completed": ScannerJobState.COMPLETED,
            "failed": ScannerJobState.FAILED,
            "timed_out": ScannerJobState.TIMED_OUT,
            "cancelled": ScannerJobState.CANCELLED,
        }.get(result.execution_state, ScannerJobState.FAILED)
        observations = tuple(self._observation(item, result) for item in result.candidates)
        summary = {
            "worker_id": result.worker_id,
            "state": result.execution_state,
            "candidate_count": result.candidate_count,
            "request_digest": result.request_digest,
            "result_digest": result.result_digest,
            "http_status": result.http_status,
        }
        return NucleiRunnerResult(
            state=state,
            reason=result.reason,
            stdout=json.dumps(summary, sort_keys=True, separators=(",", ":")),
            stderr="",
            observations=observations,
        )

    def _observation(
        self,
        candidate: RemoteNucleiCandidate,
        result: RemoteNucleiResult,
    ) -> ScannerCandidateObservation:
        fingerprint = hashlib.sha256(
            (
                f"{candidate.template_id}\0{self.policy.logical_target}\0"
                f"{candidate.matcher_name}"
            ).encode()
        ).hexdigest()[:24]
        return ScannerCandidateObservation(
            observation_id=f"nuclei-{fingerprint}",
            scanner_id="nuclei",
            target_reference=self.policy.logical_target,
            title=redact_text(candidate.title)[:500],
            severity=redact_text(candidate.severity)[:32],
            confidence="scanner_match",
            template_id=candidate.template_id,
            metadata={
                "scanner": "nuclei",
                "transport": "restricted_ssh",
                "worker_id": self.policy.worker_id,
                "matcher_name": redact_text(candidate.matcher_name)[:200],
                "type": redact_text(candidate.protocol)[:50],
                "remote_result_digest": result.result_digest,
                "http_status": result.http_status,
            },
        )
