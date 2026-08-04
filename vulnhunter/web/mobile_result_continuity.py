"""Authoritative result continuity for one persisted APK assessment."""

from __future__ import annotations

from collections.abc import Mapping


class MobileResultContinuityError(ValueError):
    """Raised when persisted mobile result state contradicts itself."""


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _rows(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, Mapping))


def _candidate(item: Mapping[str, object]) -> dict[str, object] | None:
    candidate_id = _text(item.get("candidate_id"))
    title = _text(item.get("title"))
    state = _text(item.get("state"))
    if candidate_id is None or title is None or state is None:
        return None
    evidence = item.get("evidence_receipts")
    judge = item.get("judge_receipts")
    return {
        "candidate_id": candidate_id,
        "weakness_id": _text(item.get("weakness_id")),
        "title": title,
        "severity": _text(item.get("severity")) or "unknown",
        "state": state,
        "component": _text(item.get("component")),
        "disposition_reason": _text(item.get("disposition_reason")),
        "evidence_receipts": [
            text
            for raw in (evidence if isinstance(evidence, list) else [])
            if (text := _text(raw))
        ],
        "judge_receipts": [
            text
            for raw in (judge if isinstance(judge, list) else [])
            if (text := _text(raw))
        ],
    }


def project_mobile_result_continuity(
    plan: Mapping[str, object] | None,
) -> dict[str, object]:
    """Project only persisted judge/verification state; never infer a finding."""

    execution = _map((plan or {}).get("execution"))
    progress = _map(execution.get("progress"))
    result_summary = _map(progress.get("result_summary"))
    hunt = _map(result_summary.get("hunt"))
    if not hunt:
        return {
            "verification": {
                "status": "unavailable",
                "receipt_sha256": None,
                "verified_count": 0,
                "evidence_required_count": 0,
                "rejected_count": 0,
                "stop_reason": None,
            },
            "candidates": [],
        }

    candidates = [
        projected
        for item in _rows(hunt.get("candidates"))
        if (projected := _candidate(item)) is not None
    ]
    derived = {
        "verified_count": sum(item["state"] == "verified" for item in candidates),
        "evidence_required_count": sum(
            item["state"] == "evidence_required" for item in candidates
        ),
        "rejected_count": sum(item["state"] == "rejected" for item in candidates),
    }
    for field, count in derived.items():
        persisted = _integer(hunt.get(field))
        if persisted is None or persisted != count:
            raise MobileResultContinuityError(
                f"Persisted mobile hunt {field} contradicts its candidate dispositions."
            )

    receipt_sha256 = _text(hunt.get("receipt_sha256"))
    if receipt_sha256 is None or len(receipt_sha256) != 64:
        raise MobileResultContinuityError(
            "Persisted mobile verification requires a bounded receipt digest."
        )
    status = "completed"
    if derived["evidence_required_count"]:
        status = "evidence_required"
    return {
        "verification": {
            "status": status,
            "receipt_sha256": receipt_sha256,
            **derived,
            "stop_reason": _text(hunt.get("stop_reason")),
        },
        "candidates": candidates,
    }


def mobile_result_summary(plan: Mapping[str, object] | None) -> str | None:
    """Return ordinary-language result copy from the persisted disposition receipt."""

    result = project_mobile_result_continuity(plan)
    verification = _map(result.get("verification"))
    if verification.get("status") == "unavailable":
        return None
    verified = _integer(verification.get("verified_count")) or 0
    evidence_required = _integer(verification.get("evidence_required_count")) or 0
    rejected = _integer(verification.get("rejected_count")) or 0
    if verified == 0 and evidence_required == 0 and rejected == 0:
        return (
            "Static inspection completed. The deterministic judge recorded no candidate "
            "dispositions from the active tools."
        )
    return (
        "Static inspection completed with "
        f"{verified} evidence-verified candidate(s), "
        f"{evidence_required} candidate(s) requiring more evidence, and "
        f"{rejected} rejected operational or unsupported candidate(s). "
        "Only the persisted judge and verification receipts determine these states."
    )


__all__ = [
    "MobileResultContinuityError",
    "mobile_result_summary",
    "project_mobile_result_continuity",
]
