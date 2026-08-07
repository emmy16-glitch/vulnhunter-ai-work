"""Chat-facing activation and status helpers for the mobile analysis worker."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest

from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_progress import (
    MobileStaticProgressError,
    MobileStaticProgressStore,
)
from vulnhunter.mobile.static_service import create_mobile_static_job
from vulnhunter.mobile.static_spool import (
    MobileStaticSpool,
    MobileStaticSpoolError,
    SignedMobileStaticJob,
)
from vulnhunter.mobile.static_worker import MobileStaticWorkerError, MobileStaticWorkerPolicy
from vulnhunter.security_tools.worker_spool import WorkerSpoolError, load_worker_signing_key
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.mobile_failures import execution_failure, mobile_failure

_SESSION_MOBILE_JOBS = "vulnhunter_conversation_mobile_jobs"
_DEFAULT_ANALYSIS_RESERVE_BYTES = 1024 * 1024 * 1024


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def _configured_int(name: str, default: int) -> int:
    configured = getattr(settings, name, None)
    raw = configured if configured is not None else os.environ.get(name, str(default))
    return int(raw)


def _spool_root() -> Path:
    return Path(
        os.environ.get(
            "VULNHUNTER_MOBILE_STATIC_SPOOL_ROOT",
            str(Path(settings.BASE_DIR) / ".local" / "mobile-static-spool"),
        )
    )


def _signing_key_path() -> Path:
    return Path(
        os.environ.get(
            "VULNHUNTER_MOBILE_STATIC_SIGNING_KEY_FILE",
            str(Path.home() / ".vulnhunter-mobile-worker-key"),
        )
    )


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def _analysis_capacity_reason(
    policy: MobileStaticWorkerPolicy,
    artifact: MobileArtifactRecord,
) -> str | None:
    """Fail before queueing when the bounded analysis cannot fit safely."""

    if artifact.total_uncompressed_bytes > policy.maximum_generated_bytes:
        return (
            "The APK declares more uncompressed content than the configured mobile-analysis "
            "workspace can safely contain."
        )

    root = policy.workspace_root.expanduser()
    if root.is_symlink():
        return "The mobile-analysis workspace must not be a symbolic link."
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    resolved = root.resolve(strict=True)
    reserve = max(
        0,
        _configured_int(
            "VULNHUNTER_MOBILE_ANALYSIS_MIN_FREE_BYTES",
            _DEFAULT_ANALYSIS_RESERVE_BYTES,
        ),
    )
    required = artifact.size_bytes + policy.maximum_generated_bytes + reserve
    available = shutil.disk_usage(resolved).free
    if available < required:
        return (
            "There is not enough free storage to start bounded APK analysis safely. "
            f"Required {_format_bytes(required)}; available {_format_bytes(available)}."
        )
    return None


def _remember_job(request: HttpRequest, *, job_id: str, requested_by: str) -> None:
    raw = request.session.get(_SESSION_MOBILE_JOBS, {})
    jobs = dict(raw) if isinstance(raw, dict) else {}
    jobs[job_id] = requested_by
    request.session[_SESSION_MOBILE_JOBS] = jobs
    request.session.modified = True


def _activation_failure(
    *,
    plan: dict[str, object],
    category: str,
    reason_code: str,
    message: str,
    user_action: str | None = None,
    operator_action: str | None = None,
    safe_retry: bool = False,
) -> dict[str, object]:
    run_id = str(plan.get("run_id") or "") or None
    return execution_failure(
        state="gated",
        failure=mobile_failure(
            category=category,
            stage="worker_activation",
            reason_code=reason_code,
            message=message,
            operation_id=run_id,
            user_action=user_action,
            operator_action=operator_action,
            safe_retry=safe_retry,
            retry_scope="worker_activation" if safe_retry else None,
            preserved=("artifact", "assessment", "plan", "approval"),
        ),
    )


def _same_job_binding(
    job: SignedMobileStaticJob,
    *,
    run_id: str,
    artifact: MobileArtifactRecord,
    plan_digest: str,
    requested_by: str,
) -> bool:
    return (
        job.job_id == run_id
        and job.run_id == run_id
        and job.artifact_id == artifact.artifact_id
        and job.artifact_sha256 == artifact.sha256
        and job.hunt_plan_sha256 == plan_digest
        and job.requested_by == requested_by
    )


def enqueue_mobile_static_if_ready(
    request: HttpRequest,
    *,
    plan: dict[str, object],
    attachment: ConversationAttachment,
    artifact: MobileArtifactRecord,
    requested_by: str,
) -> dict[str, object]:
    """Enqueue once, or recover the exact persisted job after timeout/reconnect."""

    if not _env_bool("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED"):
        return _activation_failure(
            plan=plan,
            category="worker_unavailable",
            reason_code="worker_not_activated",
            message="Static APK analysis is not activated in this deployment.",
            operator_action=(
                "Enable the isolated mobile worker after its policy and signing key pass preflight."
            ),
        )
    policy_path = Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
    try:
        policy = MobileStaticWorkerPolicy.from_path(policy_path)
        if not policy.enabled:
            return _activation_failure(
                plan=plan,
                category="policy_denied",
                reason_code="worker_policy_disabled",
                message="Static APK analysis is disabled by the current worker policy.",
                operator_action="Review and explicitly enable the mobile worker policy.",
            )
        signing_key = load_worker_signing_key(_signing_key_path())
        spool = MobileStaticSpool(_spool_root())
        run_id = str(plan["run_id"])
        plan_digest = str(plan["plan_digest"])
        existing = spool.existing_job(run_id, key=signing_key)
        if existing is not None:
            if not _same_job_binding(
                existing,
                run_id=run_id,
                artifact=artifact,
                plan_digest=plan_digest,
                requested_by=requested_by,
            ):
                return _activation_failure(
                    plan=plan,
                    category="policy_denied",
                    reason_code="existing_job_binding_mismatch",
                    message="The existing APK worker job does not match this assessment binding.",
                    operator_action="Inspect the persisted signed mobile job before retrying.",
                )
            _remember_job(request, job_id=run_id, requested_by=requested_by)
            status = spool.status(run_id) or {"state": "queued", "job_id": run_id}
            return {
                **status,
                "artifact_id": attachment.artifact_id,
                "worker_id": policy.worker_id,
                "tools": list(policy.active_tools()),
                "network_isolation": policy.network_isolation,
                "reused": True,
            }

        capacity_reason = _analysis_capacity_reason(policy, artifact)
        if capacity_reason is not None:
            return _activation_failure(
                plan=plan,
                category="storage_failure",
                reason_code="insufficient_analysis_capacity",
                message=capacity_reason,
                operator_action=(
                    "Free storage or reduce the configured bounded workspace limits before "
                    "retrying."
                ),
                safe_retry=True,
            )
        job = create_mobile_static_job(
            run_id=run_id,
            artifact_id=artifact.artifact_id,
            artifact_sha256=artifact.sha256,
            hunt_plan_sha256=plan_digest,
            requested_by=requested_by,
            signing_key=signing_key,
        )
        spool.enqueue(job)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        MobileStaticSpoolError,
        MobileStaticWorkerError,
        WorkerSpoolError,
    ) as exc:
        return _activation_failure(
            plan=plan,
            category="dependency_unavailable",
            reason_code=f"activation_{type(exc).__name__.casefold()}",
            message=(
                "Static APK analysis could not start because its protected worker "
                "dependencies failed preflight."
            ),
            operator_action=(
                "Inspect the worker policy, private signing key, spool permissions and "
                "registered tools."
            ),
            safe_retry=True,
        )
    _remember_job(request, job_id=job.job_id, requested_by=requested_by)
    return {
        "state": "queued",
        "job_id": job.job_id,
        "artifact_id": attachment.artifact_id,
        "worker_id": policy.worker_id,
        "tools": list(policy.active_tools()),
        "network_isolation": policy.network_isolation,
        "reused": False,
    }


def mobile_static_status(
    request: HttpRequest,
    *,
    job_id: str,
    requested_by: str,
) -> dict[str, object] | None:
    try:
        root = _spool_root()
        spool = MobileStaticSpool(root)
        signing_key = load_worker_signing_key(_signing_key_path())
        job = spool.existing_job(job_id, key=signing_key)
        if job is None or job.requested_by != requested_by:
            return None
        status = spool.status(job_id)
        if status is None:
            return None
        _remember_job(request, job_id=job_id, requested_by=requested_by)
        progress = MobileStaticProgressStore(root).read(job_id=job_id, key=signing_key)
        if progress is not None:
            status["progress"] = progress.model_dump(mode="json", exclude={"signature"})
            if status.get("state") == "running":
                status["state"] = progress.state
        return status
    except (
        OSError,
        ValueError,
        MobileStaticProgressError,
        MobileStaticSpoolError,
        WorkerSpoolError,
    ) as exc:
        return execution_failure(
            state="failed",
            job_id=job_id,
            failure=mobile_failure(
                category="storage_failure",
                stage="worker_status",
                reason_code=f"status_{type(exc).__name__.casefold()}",
                message="The latest worker status could not be verified safely.",
                operation_id=job_id,
                operator_action=(
                    "Inspect the signed spool and progress store, then retry this status read."
                ),
                safe_retry=True,
                retry_scope="worker_status",
                preserved=(
                    "artifact",
                    "assessment",
                    "plan",
                    "approval",
                    "previous_receipts",
                ),
            ),
        )
