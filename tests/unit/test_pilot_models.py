"""Model and loading tests for controlled pilot plans."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunter.pilot import PilotPlan, load_pilot_plan

EXAMPLE = Path("config/pilot/example-plan.json")


def test_example_plan_loads_and_is_local_lab_only() -> None:
    plan = load_pilot_plan(EXAMPLE)
    assert plan.local_lab_only is True
    assert plan.connector_policy == "disabled"
    assert plan.model_training_during_collection is False
    assert len(plan.assignments.primary_reviewer_ids) == 2


def test_unknown_fields_are_rejected() -> None:
    payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        PilotPlan.model_validate(payload)


def test_unknown_schema_version_is_rejected() -> None:
    payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    payload["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        PilotPlan.model_validate(payload)
