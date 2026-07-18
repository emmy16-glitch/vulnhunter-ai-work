"""Controlled adversary-emulation laboratory for synthetic private-range validation."""

from vulnhunter.adversary_lab.models import (
    LabPlan,
    LabRecord,
    LabScenario,
    LabState,
    LabTrialResult,
    TrialOutcome,
)
from vulnhunter.adversary_lab.registry import get_scenario, list_scenarios
from vulnhunter.adversary_lab.runner import LabWorkerPolicy, SyntheticScenarioRunner
from vulnhunter.adversary_lab.service import AdversaryLabService
from vulnhunter.adversary_lab.store import AdversaryLabStore

__all__ = [
    "AdversaryLabService",
    "AdversaryLabStore",
    "LabPlan",
    "LabRecord",
    "LabScenario",
    "LabState",
    "LabTrialResult",
    "LabWorkerPolicy",
    "SyntheticScenarioRunner",
    "TrialOutcome",
    "get_scenario",
    "list_scenarios",
]
