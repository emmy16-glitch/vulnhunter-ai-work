"""Chat-facing activation and status helpers for the mobile static worker."""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest

from vulnhunter.mobile.models import MobileArtifactRecord
from vulnhunter.mobile.static_service import create_mobile_static_job
from vulnhunter.mobile.static_spool import MobileStaticSpool, MobileStaticSpoolError
from vulnhunter.mobile.static_worker import MobileStaticWorkerError, MobileStaticWorkerPolicy
from vulnhunter.security_tools.worker_spool import WorkerSpoolError, load_worker_signing_key
from vulnhunter.web.conversation_attachments import ConversationAttachment

_SESSION_MOBILE_JOBS = "vulnhunter_conversation_mobile_jobs"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


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


def _remember_job(request: HttpRequest, *, job_id: str, requested_by: str) -> None:
    raw = request.session.get(_SESSION_MOBILE_JOBS, {})
    jobs = dict(raw) if isinstance(raw, dict) else {}
    jobs[job_id] = requested_by
    request.session[_SESSION_MOBILE_JOBS] = jobs
    request.session.modified = True


def enqueue_mobile_static_if_ready(
    request: HttpRequest,
    *,
    plan: dict[str, object],
    attachment: ConversationAttachment,
    artifact: MobileArtifactRecord,
    requested_by: str,
) -> dict[str, object]:
    """Enqueue only when deployment policy, key and worker tools are activated."""

    if not _env_bool("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED"):
        return {
            "state": "gated",
            "reason": "The networkless mobile static worker is not activated in this deployment.",
        }
    policy_path = Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
    try:
        policy = MobileStaticWorkerPolicy.from_path(policy_path)
        if not policy.enabled:
            return {
                "state": "gated",
                "reason": "The mobile static worker policy is present but disabled.",
            }
        signing_key = load_worker_signing_key(_signing_key_path())
        spool = MobileStaticSpool(_spool_root())
        run_id = str(plan["run_id"])
        job = create_mobile_static_job(
            run_id=run_id,
            artifact_id=artifact.artifact_id,
            artifact_sha256=artifact.sha256,
            hunt_plan_sha256=str(plan["plan_digest"]),
            requested_by=requested_by,
            signing_key=signing_key,
        )
        spool.enqueue(job)
    except (
        KeyError,
        OSError,
        ValueError,
        MobileStaticSpoolError,
        MobileStaticWorkerError,
        WorkerSpoolError,
    ) as exc:
        return {
            "state": "gated",
            "reason": f"Mobile worker activation failed closed: {type(exc).__name__}.",
        }
    _remember_job(request, job_id=job.job_id, requested_by=requested_by)
    return {
        "state": "queued",
        "job_id": job.job_id,
        "artifact_id": attachment.artifact_id,
        "worker_id": policy.worker_id,
        "tools": [
            name
            for name, path in (
                ("aapt2", policy.aapt2_executable),
                ("apksigner", policy.apksigner_executable),
                ("apkid", policy.apkid_executable),
            )
            if path is not None
        ],
    }


def mobile_static_status(
    request: HttpRequest,
    *,
    job_id: str,
    requested_by: str,
) -> dict[str, object] | None:
    raw = request.session.get(_SESSION_MOBILE_JOBS, {})
    if not isinstance(raw, dict) or raw.get(job_id) != requested_by:
        return None
    try:
        return MobileStaticSpool(_spool_root()).status(job_id)
    except (OSError, ValueError, MobileStaticSpoolError):
        return {
            "job_id": job_id,
            "state": "failed",
            "reason": "The mobile worker status store failed closed.",
        }
