from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block missing from {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''from vulnhunter.security_tools.nuclei_activation import (
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiTemplateManifest,
)
''',
        '''from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiActivationError,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiTemplateManifest,
)
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''from vulnhunter.web.assessment_workflow import load_nuclei_authorization


class NucleiPilotServiceError(RuntimeError):
''',
        '''

class NucleiPilotServiceError(RuntimeError):
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''class NucleiPilotServiceError(RuntimeError):
    """Raised when the manager or worker cannot preserve the pilot boundary."""


def build_approved_pilot_job(
''',
        '''class NucleiPilotServiceError(RuntimeError):
    """Raised when the manager or worker cannot preserve the pilot boundary."""


def _load_nuclei_authorization(
    store: AuthorizationStore,
    authorization_id: str,
) -> EngagementAuthorization:
    record = store.get(authorization_id)
    for event in store.list_events(authorization_id):
        if event.event_type != "nuclei_activation_bound":
            continue
        if event.detail.get("source_record_sha256") != record.record_sha256:
            raise NucleiPilotServiceError("Nuclei binding is stale")
        try:
            engagement = EngagementAuthorization.model_validate(
                event.detail.get("engagement_record")
            )
        except (TypeError, ValueError) as exc:
            raise NucleiPilotServiceError("Nuclei binding is invalid") from exc
        if engagement.authorization_id != record.authorization_id:
            raise NucleiPilotServiceError("Nuclei binding references another authorization")
        return engagement
    raise NucleiPilotServiceError("No reviewed Nuclei activation binding exists")


def build_approved_pilot_job(
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_pilot_service.py",
        '''    _, authorization = load_nuclei_authorization(
        authorization_store,
        plan.authorization_id,
    )
''',
        '''    authorization = _load_nuclei_authorization(
        authorization_store,
        plan.authorization_id,
    )
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''import os
import signal
import stat
import subprocess
import time
''',
        '''import os
import resource
import signal
import stat
import subprocess
import time
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''        if target.address_class != "private":
            raise NucleiExecutionError("the pilot accepts private laboratory targets only")
        for value in target.resolved_addresses:
            address = ipaddress.ip_address(value)
            if not address.is_private or address.is_link_local or address.is_loopback:
                raise NucleiExecutionError("the target address is outside the private-lab boundary")
        return target.url
''',
        '''        if target.address_class != "private":
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
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''        with open(os.devnull, "rb") as stdin_handle, subprocess.Popen(
            command,
            stdin=stdin_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd=specification.request.output_directory,
            start_new_session=True,
            text=False,
        ) as process:
            while process.poll() is None:
                control.checkpoint(process_group_id=process.pid)
                time.sleep(self.policy.poll_interval_seconds)
            stdout_bytes, stderr_bytes = process.communicate()

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
''',
        '''        request = specification.request
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
''',
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '''        if process.returncode != 0:
            return NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason=f"Nuclei exited with code {process.returncode}.",
''',
        '''        if return_code != 0:
            return NucleiRunnerResult(
                state=ScannerJobState.FAILED,
                reason=f"Nuclei exited with code {return_code}.",
''',
    )
    replace_once(
        "vulnhunter/security_tools/worker_spool.py",
        '''    def load_claimed(
        self,
        path: Path,
''',
        '''    def cancel_pending(self, job_id: str, *, reason: str, now: datetime) -> bool:
        source = self.pending / f"{job_id}.json"
        if not source.exists():
            return False
        if source.is_symlink():
            raise WorkerSpoolError("pending worker job must not be a symbolic link")
        destination = self.failed / source.name
        os.replace(source, destination)
        safe_reason = " ".join(reason.split())[:500] or "Worker job cancelled."
        receipt = WorkerJobReceipt(
            job_id=job_id,
            state="cancelled",
            execution_id="pending-job",
            result_sha256=hashlib.sha256(safe_reason.encode()).hexdigest(),
            completed_at=now,
            reason=safe_reason,
        )
        self._write_exclusive(
            self.failed / f"{job_id}.receipt.json",
            receipt.model_dump_json(indent=2) + "\\n",
        )
        return True

    def load_claimed(
        self,
        path: Path,
''',
    )
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''from vulnhunter.security_tools.nuclei_activation import (
''',
        '''from vulnhunter.security_tools.nuclei_pilot_service import (
    NucleiPilotServiceError,
    build_approved_pilot_job,
)
from vulnhunter.security_tools.scanner_protocol import ScannerCompatibilityManifest
from vulnhunter.security_tools.worker_spool import (
    SignedWorkerSpool,
    WorkerSpoolError,
    load_worker_signing_key,
)
from vulnhunter.security_tools.nuclei_activation import (
''',
    )
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''        approved = request.decision is not None and request.decision.value.startswith("approve_")
        new_state = "execution_blocked" if approved else "denied"
        new_status = TaskStatus.BLOCKED if approved else TaskStatus.CANCELLED
        reason = (
            "Approval recorded; Nuclei execution remains globally disabled."
            if approved
            else "The exact command plan was denied by a human approver."
        )
        updated = task.evolved(
            status=new_status,
            paused_reason=reason,
''',
        '''        approved = request.decision is not None and request.decision.value.startswith("approve_")
        queued_job = None
        queue_error = None
        if (
            approved
            and plan.exact_profile == "passive"
            and getattr(settings, "VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED", False)
        ):
            try:
                signing_key = load_worker_signing_key(
                    Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)
                )
                compatibility = ScannerCompatibilityManifest.load(
                    Path(settings.VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST)
                )
                compatibility.verify_repository_manifests(Path(settings.BASE_DIR))
                queued_job = build_approved_pilot_job(
                    task=task,
                    approval_request=request,
                    authorization_store=self.authorization_store,
                    compatibility_manifest=compatibility,
                    signing_key=signing_key,
                    actor_id=actor_id,
                    now=now,
                )
                SignedWorkerSpool(
                    Path(settings.VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT)
                ).enqueue(queued_job)
            except (
                OSError,
                ValueError,
                NucleiPilotServiceError,
                WorkerSpoolError,
            ) as exc:
                queue_error = type(exc).__name__
        if queued_job is not None:
            new_state = "queued"
            new_status = TaskStatus.RUNNING
            reason = "Approved passive plan queued for the isolated Nuclei worker."
        elif approved:
            new_state = "execution_blocked"
            new_status = TaskStatus.BLOCKED
            reason = (
                "Approval recorded; the isolated Nuclei worker remains disabled."
                if queue_error is None
                else "Approval recorded; worker queue activation failed closed."
            )
        else:
            new_state = "denied"
            new_status = TaskStatus.CANCELLED
            reason = "The exact command plan was denied by a human approver."
        updated = task.evolved(
            status=new_status,
            paused_reason=None if queued_job is not None else reason,
''',
    )
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''                    "execution_enabled": False,
                    "blocking_reason": reason,
''',
        '''                    "execution_enabled": False,
                    "execution_id": (
                        queued_job.invocation.request.execution_id if queued_job else None
                    ),
                    "queue_error": queue_error,
                    "blocking_reason": None if queued_job is not None else reason,
''',
    )
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''                "execution_enabled": False,
            },
        )
''',
        '''                "execution_enabled": False,
                "pilot_queued": queued_job is not None,
                "queue_error": queue_error,
            },
        )
''',
    )
    replace_once(
        "vulnhunter/web/assessment_workflow.py",
        '''            event_type="run_blocked" if approved else "approval_rejected",
            run_state="blocked" if approved else "cancelled",
''',
        '''            event_type=(
                "scanner_queued"
                if queued_job is not None
                else "run_blocked" if approved else "approval_rejected"
            ),
            run_state=("queued" if queued_job is not None else "blocked" if approved else "cancelled"),
''',
    )
    replace_once(
        "vulnhunter/web/settings.py",
        '''VULNHUNTER_NUCLEI_READINESS_REPORT = os.environ.get(
    "VULNHUNTER_NUCLEI_READINESS_REPORT",
    str(BASE_DIR / ".local" / "nuclei-readiness" / "readiness.json"),
)
''',
        '''VULNHUNTER_NUCLEI_READINESS_REPORT = os.environ.get(
    "VULNHUNTER_NUCLEI_READINESS_REPORT",
    str(BASE_DIR / ".local" / "nuclei-readiness" / "readiness.json"),
)
VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED = env_bool(
    "VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED", False
)
VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE",
    str(Path.home() / ".vulnhunter-nuclei-worker-key"),
)
VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT",
    str(BASE_DIR / ".local" / "nuclei-worker-spool"),
)
VULNHUNTER_NUCLEI_WORKER_POLICY = os.environ.get(
    "VULNHUNTER_NUCLEI_WORKER_POLICY",
    str(BASE_DIR / "config" / "security_tools" / "nuclei_worker_pilot.json"),
)
VULNHUNTER_NUCLEI_EXECUTION_ROOT = os.environ.get(
    "VULNHUNTER_NUCLEI_EXECUTION_ROOT",
    str(BASE_DIR / ".local" / "nuclei-executions"),
)
VULNHUNTER_VERIFICATION_ROOT = os.environ.get(
    "VULNHUNTER_VERIFICATION_ROOT",
    str(BASE_DIR / ".local" / "verification"),
)
VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST = os.environ.get(
    "VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST",
    str(BASE_DIR / "config" / "security_tools" / "scanner_compatibility.json"),
)
''',
    )
    replace_once(
        ".env.example",
        '''VULNHUNTER_TOOLS_ROOT=/mnt/vulnhunter-data/tools/vulnhunter-external
''',
        '''VULNHUNTER_TOOLS_ROOT=/mnt/vulnhunter-data/tools/vulnhunter-external

# Isolated passive Nuclei worker pilot. Keep enqueue disabled until the worker,
# owner-private signing key, reviewed policy, and private-lab target are ready.
VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED=false
VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE=/run/secrets/vulnhunter-nuclei-worker-key
VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT=/srv/vulnhunter/state/nuclei-worker-spool
VULNHUNTER_NUCLEI_WORKER_POLICY=/etc/vulnhunter/nuclei-worker-pilot.json
VULNHUNTER_NUCLEI_EXECUTION_ROOT=/srv/vulnhunter/state/nuclei-executions
VULNHUNTER_VERIFICATION_ROOT=/srv/vulnhunter/state/verification
VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST=/srv/vulnhunter/app/config/security_tools/scanner_compatibility.json
''',
    )


if __name__ == "__main__":
    main()
