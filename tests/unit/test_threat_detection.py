from datetime import UTC, datetime, timedelta

from vulnhunter.threat_detection import (
    AgentActionEvent,
    ContainmentDecision,
    ThreatAssessmentStore,
    ThreatDetector,
    ThreatPolicy,
    ThreatSignalKind,
)


def _event(index: int, action: str, **kwargs):
    return AgentActionEvent(
        event_id=f"event-{index:02d}",
        execution_id="execution-01",
        actor_id="worker-01",
        action=action,
        created_at=datetime(2026, 7, 15, 10, 0, tzinfo=UTC) + timedelta(seconds=index),
        **kwargs,
    )


def test_threat_detector_kills_critical_sequences():
    assessment = ThreatDetector(
        ThreatPolicy(outbound_allowlist=("approved.example",), secret_access_threshold=2)
    ).assess(
        (
            _event(1, "secret.read"),
            _event(2, "credential.read"),
            _event(
                3,
                "http.request",
                target="https://evil.example/upload",
                source_trust="untrusted",
                metadata={"instruction_followed": True},
            ),
        )
    )
    kinds = {signal.kind for signal in assessment.signals}
    assert ThreatSignalKind.REPEATED_SECRET_ACCESS in kinds
    assert ThreatSignalKind.UNEXPECTED_OUTBOUND_CONNECTION in kinds
    assert ThreatSignalKind.UNTRUSTED_INSTRUCTION_FOLLOWING in kinds
    assert assessment.decision == ContainmentDecision.KILL
    assert assessment.notify_human is True


def test_threat_detector_allows_bounded_normal_activity():
    assessment = ThreatDetector(ThreatPolicy(outbound_allowlist=("approved.example",))).assess(
        (_event(1, "http.request", target="https://api.approved.example/v1"),)
    )
    assert assessment.signals == ()
    assert assessment.decision == ContainmentDecision.CONTINUE


def test_threat_assessment_store_hash_chain(tmp_path):
    detector = ThreatDetector()
    store = ThreatAssessmentStore(tmp_path / "threats.sqlite3")
    assessment = detector.assess((_event(1, "scope.expand"),))
    digest = store.append(assessment)
    assert store.verify("execution-01") == digest
