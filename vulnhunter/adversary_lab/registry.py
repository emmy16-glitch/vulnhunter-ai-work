"""Reviewed synthetic scenarios for the controlled adversary-emulation lab."""

from __future__ import annotations

from vulnhunter.adversary_lab.models import LabScenario

_COMMON_PROHIBITED = (
    "arbitrary-shell",
    "arbitrary-code",
    "credential-dumping",
    "persistence",
    "lateral-movement-outside-lab",
    "public-internet-targeting",
    "customer-data-access",
    "destructive-payloads",
)

_SCENARIOS = (
    LabScenario(
        scenario_id="synthetic-file-impact",
        version="1.0.0",
        title="Synthetic file-impact simulation",
        summary=(
            "Modify generated test files inside a disposable workspace, verify evidence, "
            "restore the clean snapshot, and repeat with bounded variations."
        ),
        risk_label="controlled",
        tool_ids=("snapshot-controller", "synthetic-file-simulator", "evidence-hasher"),
        variations=(
            "five-generated-files",
            "ten-generated-files",
            "fifteen-generated-files",
            "twenty-generated-files",
            "alternate-test-directory",
            "reduced-rate-repeat",
            "detection-marker-check",
            "containment-marker-check",
            "evidence-consistency-check",
            "final-confirmation",
        ),
        expected_evidence=(
            "trial summary",
            "generated-file manifest",
            "snapshot restoration confirmation",
        ),
        prohibited_operations=_COMMON_PROHIBITED,
    ),
    LabScenario(
        scenario_id="synthetic-auth-detection",
        version="1.0.0",
        title="Synthetic authentication detection",
        summary=(
            "Generate fake authentication events for planted test accounts and measure whether "
            "the lab detection marker observes the approved pattern."
        ),
        risk_label="controlled",
        tool_ids=("snapshot-controller", "synthetic-auth-generator", "detection-marker"),
        variations=(
            "single-test-account",
            "second-test-account",
            "failed-login-sequence",
            "successful-login-sequence",
            "low-rate-repeat",
            "detection-marker-check",
            "containment-marker-check",
            "alternate-lab-host",
            "evidence-consistency-check",
            "final-confirmation",
        ),
        expected_evidence=("synthetic auth log", "detection result", "snapshot restoration"),
        prohibited_operations=_COMMON_PROHIBITED,
    ),
    LabScenario(
        scenario_id="internal-transfer-observation",
        version="1.0.0",
        title="Internal synthetic-data transfer",
        summary=(
            "Move generated records between two directories inside the disposable range and "
            "measure the approved internal transfer control."
        ),
        risk_label="controlled",
        tool_ids=("snapshot-controller", "synthetic-transfer-simulator", "evidence-hasher"),
        variations=(
            "ten-record-transfer",
            "twenty-record-transfer",
            "alternate-sink",
            "reduced-rate-repeat",
            "detection-marker-check",
            "containment-marker-check",
            "source-integrity-check",
            "sink-integrity-check",
            "evidence-consistency-check",
            "final-confirmation",
        ),
        expected_evidence=("transfer manifest", "integrity hashes", "snapshot restoration"),
        prohibited_operations=_COMMON_PROHIBITED,
    ),
    LabScenario(
        scenario_id="service-control-observation",
        version="1.0.0",
        title="Disposable service-control simulation",
        summary=(
            "Change a generated service-state record inside the disposable workspace, collect "
            "the control evidence, and restore the baseline before every retry."
        ),
        risk_label="controlled",
        tool_ids=("snapshot-controller", "service-state-simulator", "detection-marker"),
        variations=(
            "stop-state-marker",
            "restart-state-marker",
            "alternate-service-record",
            "low-rate-repeat",
            "detection-marker-check",
            "containment-marker-check",
            "state-integrity-check",
            "alternate-lab-host",
            "evidence-consistency-check",
            "final-confirmation",
        ),
        expected_evidence=("service state record", "detection result", "snapshot restoration"),
        prohibited_operations=_COMMON_PROHIBITED,
    ),
)

_BY_ID = {scenario.scenario_id: scenario for scenario in _SCENARIOS}


def list_scenarios() -> tuple[LabScenario, ...]:
    """Return the immutable reviewed scenario catalogue."""

    return _SCENARIOS


def get_scenario(scenario_id: str) -> LabScenario:
    """Resolve one reviewed scenario or fail closed."""

    try:
        return _BY_ID[scenario_id]
    except KeyError as exc:
        raise ValueError(f"unknown adversary-lab scenario: {scenario_id}") from exc
