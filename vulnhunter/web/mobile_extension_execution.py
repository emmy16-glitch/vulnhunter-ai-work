"""Chat-facing exact approval and status helpers for MobSF and runtime jobs."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.http import HttpRequest

from vulnhunter.mobile.extension_spool import (
    MobileExtensionSpool,
    MobileExtensionSpoolError,
    SignedMobileExtensionJob,
)
from vulnhunter.mobile.runtime import (
    MobileRuntimeError,
    MobileRuntimePolicy,
    SignedMobileRuntimeApproval,
)
from vulnhunter.security_tools.worker_spool import WorkerSpoolError, load_worker_signing_key
from vulnhunter.web.mobile_infrastructure import mobile_infrastructure_status

_SESSION_EXTENSION_JOBS = "vulnhunter_mobile_extension_jobs"
_MAX_SESSION_JOBS = 16


def _path(name: str, fallback: str) -> Path:
    return Path(
        os.environ.get(
            name,
            str(Path(settings.BASE_DIR) / ".codespaces" / "runtime" / fallback),
        )
    )


def _spool_root() -> Path:
    return Path(
        os.environ.get(
            "VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT",
            str(Path(settings.BASE_DIR) / ".local" / "mobile-extension-spool"),
        )
    )


def _extension_key() -> bytes:
    return load_worker_signing_key(
        _path(
            "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE",
            "mobile-extension-worker.key",
        )
    )


def _runtime_approval_key() -> bytes:
    return load_worker_signing_key(
        _path(
            "VULNHUNTER_MOBILE_RUNTIME_APPROVAL_KEY_FILE",
            "mobile-runtime-approval.key",
        )
    )


def _remember_job(
    request: HttpRequest,
    *,
    job_id: str,
    requested_by: str,
) -> None:
    raw = request.session.get(_SESSION_EXTENSION_JOBS, {})
    jobs = dict(raw) if isinstance(raw, dict) else {}
    jobs[job_id] = requested_by
    request.session[_SESSION_EXTENSION_JOBS] = dict(list(jobs.items())[-_MAX_SESSION_JOBS:])
    request.session.modified = True


def _planned_tool(plan: dict[str, object], *, kind: str) -> dict[str, object] | None:
    deferred = plan.get("deferred_tools")
    if not isinstance(deferred, list):
        return None
    accepted = {"mobsf"} if kind == "mobsf" else {"adb", "frida"}
    return next(
        (
            item
            for item in deferred
            if isinstance(item, dict) and str(item.get("tool_id")) in accepted
        ),
        None,
    )


def _already_active(plan: dict[str, object], *, kind: str, spool: MobileExtensionSpool) -> bool:
    jobs = plan.get("extension_jobs")
    if not isinstance(jobs, list):
        return False
    for item in reversed(jobs):
        if not isinstance(item, dict) or item.get("kind") != kind:
            continue
        job_id = str(item.get("job_id") or "")
        if not job_id:
            continue
        try:
            status = spool.status(job_id)
        except (OSError, ValueError, MobileExtensionSpoolError):
            return True
        if isinstance(status, dict) and status.get("state") in {"queued", "running"}:
            return True
    return False


def enqueue_mobile_extension(
    request: HttpRequest,
    *,
    plan: dict[str, object],
    kind: str,
    package_name: str | None,
    reason: str,
    requested_by: str,
) -> dict[str, object]:
    """Create a signed exact approval and enqueue one separate extension job."""

    if kind not in {"mobsf", "runtime"}:
        return {"state": "gated", "reason": "Unknown mobile extension tool."}
    safe_reason = " ".join(reason.split())
    if len(safe_reason) < 8 or len(safe_reason) > 500:
        return {
            "state": "gated",
            "reason": "Extension approval requires a reason between 8 and 500 characters.",
        }
    artifact = plan.get("artifact")
    if not isinstance(artifact, dict):
        return {"state": "gated", "reason": "Mobile artifact identity is unavailable."}
    if _planned_tool(plan, kind=kind) is None:
        return {
            "state": "gated",
            "reason": "The requested extension was not part of this immutable mobile plan.",
        }

    now = datetime.now(UTC)
    readiness_key = "mobsf" if kind == "mobsf" else "adb"
    readiness = mobile_infrastructure_status(now=now).get(readiness_key, {})
    if readiness.get("state") != "approval_required":
        return {
            "state": "gated",
            "reason": str(
                readiness.get("reason")
                or "The requested extension infrastructure is not currently ready."
            ),
        }

    try:
        spool = MobileExtensionSpool(_spool_root())
        if _already_active(plan, kind=kind, spool=spool):
            return {
                "state": "gated",
                "reason": "An exact job for this extension is already queued or running.",
            }

        runtime_approval: dict[str, object] | None = None
        if kind == "runtime":
            if not package_name:
                return {
                    "state": "gated",
                    "reason": "Runtime approval requires the exact Android package name.",
                }
            policy = MobileRuntimePolicy.from_path(
                _path(
                    "VULNHUNTER_MOBILE_RUNTIME_POLICY",
                    "mobile-runtime.json",
                )
            )
            approval = SignedMobileRuntimeApproval.create(
                approval_id=f"approval-{uuid4().hex[:20]}",
                plan_sha256=str(plan["plan_digest"]),
                artifact_sha256=str(artifact["artifact_sha256"]),
                package_name=package_name,
                runtime_id=policy.runtime_id,
                adb_serial=policy.adb_serial,
                frida_device_id=policy.frida_device_id,
                approved_by=requested_by,
                approved_at=now,
                expires_at=min(now + timedelta(minutes=30), policy.expires_at),
                key=_runtime_approval_key(),
            )
            runtime_approval = approval.model_dump(mode="json")

        job = SignedMobileExtensionJob.create(
            job_id=f"mobile-{kind}-{uuid4().hex[:20]}",
            kind=kind,
            artifact_id=str(artifact["artifact_id"]),
            artifact_sha256=str(artifact["artifact_sha256"]),
            plan_sha256=str(plan["plan_digest"]),
            requested_by=requested_by,
            approval_reason=safe_reason,
            package_name=package_name,
            runtime_approval=runtime_approval,
            created_at=now,
            expires_at=now + timedelta(hours=2),
            key=_extension_key(),
        )
        spool.enqueue(job)
    except (
        KeyError,
        OSError,
        ValueError,
        MobileExtensionSpoolError,
        MobileRuntimeError,
        WorkerSpoolError,
    ) as exc:
        return {
            "state": "gated",
            "reason": f"Extension approval failed closed: {type(exc).__name__}.",
        }

    _remember_job(request, job_id=job.job_id, requested_by=requested_by)
    return {
        "state": "queued",
        "job_id": job.job_id,
        "kind": job.kind,
        "package_name": job.package_name,
        "plan_sha256": job.plan_sha256,
        "artifact_sha256": job.artifact_sha256,
        "approved_by": requested_by,
        "expires_at": job.expires_at.isoformat(),
    }


def mobile_extension_status(
    request: HttpRequest,
    *,
    job_id: str,
    requested_by: str,
) -> dict[str, object] | None:
    raw = request.session.get(_SESSION_EXTENSION_JOBS, {})
    if not isinstance(raw, dict) or raw.get(job_id) != requested_by:
        return None
    try:
        return MobileExtensionSpool(_spool_root()).status(job_id)
    except (OSError, ValueError, MobileExtensionSpoolError):
        return {
            "job_id": job_id,
            "state": "failed",
            "reason": "Extension status failed closed.",
        }


__all__ = [
    "enqueue_mobile_extension",
    "mobile_extension_status",
]
