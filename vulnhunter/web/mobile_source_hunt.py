"""Governed APK-to-Source-Hunt handoff helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from django.conf import settings

from vulnhunter.mobile.static_worker import MobileStaticWorkerPolicy
from vulnhunter.source_hunt import MobileSourceHuntEngine, MobileSourceHuntStore


class MobileSourceHuntHandoffError(RuntimeError):
    """Raised when an APK Source Hunt handoff cannot be proven safe and exact."""


def _report_root() -> Path:
    return Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_MOBILE_REPORT_ROOT",
            str(Path(settings.BASE_DIR) / ".local" / "source-hunt-mobile-reports"),
        )
    )


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _exact_source_root(*, policy: MobileStaticWorkerPolicy, artifact_id: str, job_id: str) -> Path:
    workspace_root = policy.workspace_root.expanduser().resolve(strict=True)
    source_root = (workspace_root / artifact_id / job_id / "jadx-output" / "sources").resolve(
        strict=True
    )
    try:
        source_root.relative_to(workspace_root)
    except ValueError as exc:
        raise MobileSourceHuntHandoffError(
            "The retained APK source workspace is outside the configured worker boundary."
        ) from exc
    if not source_root.is_dir():
        raise MobileSourceHuntHandoffError(
            "The completed APK receipt does not retain a Source Hunt-readable JADX source tree."
        )
    return source_root


def _report_payload(report, *, selected_seed_id: str | None) -> dict[str, object]:
    matching = [
        item
        for item in report.results
        if selected_seed_id and item.seed.seed_id == selected_seed_id
    ]
    selected = matching[0] if matching else None
    return {
        "report_id": report.report_id,
        "state": "completed",
        "artifact_id": report.artifact_id,
        "artifact_sha256": report.artifact_sha256,
        "source_identity": report.source_identity,
        "analysis_run_id": report.analysis_run_id,
        "coverage": report.coverage.model_dump(mode="json"),
        "seeds_examined": report.seeds_examined,
        "verified_finding_count": report.verified_finding_count,
        "rejected_count": report.rejected_count,
        "inconclusive_count": report.inconclusive_count,
        "evidence_required_count": report.evidence_required_count,
        "blocked_count": report.blocked_count,
        "graph": report.graph.model_dump(mode="json"),
        "selected_seed_id": selected_seed_id,
        "selected_result": selected.model_dump(mode="json") if selected else None,
        "results": [item.model_dump(mode="json") for item in report.results],
    }


def run_mobile_source_hunt_handoff(
    *,
    plan: Mapping[str, object],
    requested_by: str,
    selected_seed_id: str | None = None,
    selected_record_id: str | None = None,
) -> dict[str, object]:
    """Run Source Hunt only from the exact persisted APK worker receipt."""

    execution = _mapping(plan.get("execution"))
    if str(execution.get("state") or "").casefold() != "completed":
        raise MobileSourceHuntHandoffError(
            "Source Hunt requires a completed APK static evidence receipt."
        )
    job_id = str(execution.get("job_id") or plan.get("run_id") or "").strip()
    artifact = _mapping(plan.get("artifact"))
    artifact_id = str(artifact.get("artifact_id") or "").strip()
    artifact_sha256 = str(artifact.get("artifact_sha256") or "").strip()
    if not job_id or not artifact_id or not artifact_sha256:
        raise MobileSourceHuntHandoffError(
            "The APK assessment is missing its exact job or artifact identity."
        )
    receipt = _mapping(execution.get("receipt"))
    intelligence = _mapping(receipt.get("intelligence"))
    if not intelligence:
        raise MobileSourceHuntHandoffError(
            "The completed APK receipt does not contain normalized intelligence for Source Hunt."
        )
    if str(intelligence.get("artifact_sha256") or "") != artifact_sha256:
        raise MobileSourceHuntHandoffError(
            "The APK intelligence receipt does not match the selected artifact digest."
        )
    policy_path = Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
    try:
        policy = MobileStaticWorkerPolicy.from_path(policy_path)
    except (OSError, TypeError, ValueError) as exc:
        raise MobileSourceHuntHandoffError(
            "The mobile worker policy could not be verified for Source Hunt handoff."
        ) from exc
    source_root = _exact_source_root(policy=policy, artifact_id=artifact_id, job_id=job_id)
    report = MobileSourceHuntEngine(
        source_root=source_root,
        intelligence={**intelligence, "artifact_id": artifact_id},
        analysis_run_id=f"source-hunt-{job_id}",
    ).run()
    selected_seed_ids = {item.seed.seed_id for item in report.results}
    if selected_seed_id and selected_seed_id not in selected_seed_ids:
        raise MobileSourceHuntHandoffError(
            "The requested Source Hunt seed is not present in the persisted APK intelligence."
        )
    resolved_seed_id = selected_seed_id
    if selected_record_id and resolved_seed_id is None:
        resolved_seed_id = next(
            (
                item.seed.seed_id
                for item in report.results
                if item.seed.source_intelligence_record_id == selected_record_id
            ),
            None,
        )
        if resolved_seed_id is None:
            raise MobileSourceHuntHandoffError(
                "The selected APK intelligence record has no persisted Source Hunt seed."
            )
    report_path = MobileSourceHuntStore(_report_root()).save(report)
    return {
        "report": _report_payload(report, selected_seed_id=resolved_seed_id),
        "report_path": str(report_path),
        "requested_by": requested_by,
        "selected_seed_id": resolved_seed_id,
    }


__all__ = ["MobileSourceHuntHandoffError", "run_mobile_source_hunt_handoff"]
