"""Canonical hashing for controlled pilot evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vulnhunter.pilot.models import PilotPlan


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def pilot_plan_sha256(plan: PilotPlan) -> str:
    """Return the canonical SHA-256 of a validated pilot plan."""
    return hashlib.sha256(_canonical_json(plan.model_dump(mode="json"))).hexdigest()


def pilot_report_sha256(report_data: dict[str, object]) -> str:
    """Hash a report payload while excluding its own hash field."""
    payload = {key: value for key, value in report_data.items() if key != "report_sha256"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()
