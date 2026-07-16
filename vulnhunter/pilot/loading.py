"""Read-only loading for controlled pilot plans."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.pilot.models import PilotPlan


class PilotPlanLoadError(ValueError):
    """Raised when a pilot plan cannot be loaded or structurally validated."""


def load_pilot_plan(path: Path) -> PilotPlan:
    """Load one UTF-8 JSON pilot plan without mutating any state."""
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise PilotPlanLoadError(f"Pilot plan does not exist: {resolved}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PilotPlanLoadError(f"Unable to read pilot plan {resolved}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PilotPlanLoadError(f"Pilot plan is not valid JSON: {exc.msg}") from exc
    try:
        return PilotPlan.model_validate(payload)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}" for item in exc.errors()
        )
        raise PilotPlanLoadError(f"Pilot plan failed schema validation: {details}") from exc
