import pytest
from pydantic import ValidationError

from vulnhunter.ai_routing import AiRoute, PrivacyClass, RoutingRequest, decide_route
from vulnhunter.analyst_feedback import AnalystFeedback, AnalystOutcome, summarize_feedback
from vulnhunter.attack_paths import AttackPath, AttackPathNode, AttackPathState, AttackPathStep
from vulnhunter.improvements import ImprovementProposal
from vulnhunter.reports import ReportArtifact, ReportKind, build_report_artifact
from vulnhunter.repository_coverage import CoverageExclusion, build_inventory

DIGEST = "a" * 64


def test_attack_path_cannot_be_confirmed_with_unverified_steps():
    nodes = (
        AttackPathNode(node_id="entry", node_type="entry", label="Entry"),
        AttackPathNode(node_id="impact", node_type="impact", label="Impact"),
    )
    steps = (
        AttackPathStep(
            from_node="entry",
            to_node="impact",
            precondition="network access",
            weakness="missing control",
            confidence="medium",
            verified=False,
        ),
    )
    with pytest.raises(ValidationError, match="every step"):
        AttackPath(
            path_id="path-01",
            campaign_id="campaign-01",
            target_reference="target-01",
            nodes=nodes,
            steps=steps,
            state=AttackPathState.CONFIRMED,
        )


def test_repository_coverage_inventory_uses_real_counts_and_auditable_exclusions(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# Notes\n", encoding="utf-8")

    inventory = build_inventory(
        tmp_path,
        exclusions=(CoverageExclusion(path="notes.md", reason="documentation-only"),),
    )

    assert inventory.metrics()["files_discovered"] == 2
    assert inventory.metrics()["files_excluded"] == 1
    assert inventory.metrics()["files_eligible"] == 1
    assert inventory.inventory_hash()


def test_repository_coverage_root_hash_is_path_and_state_sensitive(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    (first_root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (second_root / "renamed.py").write_text("print('ok')\n", encoding="utf-8")

    first = build_inventory(first_root)
    first_repeat = build_inventory(first_root)
    renamed = build_inventory(second_root)
    (first_root / "app.py").write_text("print('changed')\n", encoding="utf-8")
    changed = build_inventory(first_root)
    excluded = build_inventory(
        first_root,
        exclusions=(CoverageExclusion(path="app.py", reason="reviewed elsewhere"),),
    )

    assert first.root_sha256 == first_repeat.root_sha256
    assert first.root_sha256 != renamed.root_sha256
    assert first.root_sha256 != changed.root_sha256
    assert changed.root_sha256 != excluded.root_sha256


def test_ai_router_fails_closed_and_keeps_model_output_untrusted():
    unknown = decide_route(
        RoutingRequest(
            task_id="task-01",
            task_type="triage",
            input_sha256=DIGEST,
            privacy_class=PrivacyClass.UNKNOWN,
            deterministic_sufficient=False,
        )
    )
    assert unknown.route == AiRoute.DENIED

    deterministic = decide_route(
        RoutingRequest(
            task_id="task-02",
            task_type="inventory",
            input_sha256=DIGEST,
            privacy_class=PrivacyClass.INTERNAL,
            deterministic_sufficient=True,
        )
    )
    assert deterministic.route == AiRoute.DETERMINISTIC
    assert deterministic.output_trusted is False

    private_cloud = decide_route(
        RoutingRequest(
            task_id="task-03",
            task_type="current_reference",
            input_sha256=DIGEST,
            privacy_class=PrivacyClass.CUSTOMER_PRIVATE,
            deterministic_sufficient=False,
            public_freshness_required=True,
        )
    )
    assert private_cloud.route == AiRoute.DENIED


def test_feedback_metrics_use_only_actual_records():
    records = (
        AnalystFeedback(
            feedback_id="feedback-01",
            finding_id="finding-01",
            analyst_id="analyst-01",
            outcome=AnalystOutcome.ACCEPT,
            notes="Accepted with evidence.",
        ),
        AnalystFeedback(
            feedback_id="feedback-02",
            finding_id="finding-02",
            analyst_id="analyst-01",
            outcome=AnalystOutcome.ORACLE_DISAGREEMENT,
            notes="Oracle disagreed.",
        ),
    )
    metrics = summarize_feedback(records)
    assert metrics.records == 2
    assert metrics.accepted == 1
    assert metrics.oracle_disagreements == 1


def test_improvement_proposal_cannot_activate_production_configuration():
    with pytest.raises(ValidationError, match="activate production"):
        ImprovementProposal(
            proposal_id="proposal-01",
            component="ai-routing",
            risk="medium",
            affected_files=("vulnhunter/ai_routing/service.py",),
            rationale="Adjust routing policy.",
            rollback_plan="Restore previous routing policy.",
            activates_production_configuration=True,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"finding": {"token": "do-not-export"}},
        {"items": [{"API-Key": "do-not-export"}]},
        {"headers": {"Cookie": "do-not-export"}},
        {"headers": {"Set-Cookie": "do-not-export"}},
        {"headers": {"Authorization": "do-not-export"}},
        {"nested": {"access token": "do-not-export"}},
        {"nested": {"private key": "do-not-export"}},
    ],
)
def test_report_builder_rejects_nested_protected_fields(payload):
    with pytest.raises(ValueError, match="protected") as error:
        build_report_artifact(
            report_id="report-01",
            kind=ReportKind.ORACLE_VERDICTS,
            payload=payload,
            provenance=("oracle-response",),
        )
    assert "do-not-export" not in str(error.value)


def test_report_builder_accepts_safe_nested_payload_and_uses_instance_timestamp():
    payload = {"finding": {"title": "safe"}, "items": [{"severity": "low"}]}

    first = build_report_artifact(
        report_id="report-01",
        kind=ReportKind.ORACLE_VERDICTS,
        payload=payload,
        provenance=("oracle-response",),
    )
    second = build_report_artifact(
        report_id="report-02",
        kind=ReportKind.ORACLE_VERDICTS,
        payload=payload,
        provenance=("oracle-response",),
    )

    assert first.payload_sha256 == second.payload_sha256
    assert first.created_at.tzinfo is not None
    assert first.created_at <= second.created_at
    assert ReportArtifact.model_fields["created_at"].default_factory is not None


def test_report_builder_rejects_cyclic_payload():
    payload: dict[str, object] = {"safe": "value"}
    payload["cycle"] = payload

    with pytest.raises(ValueError, match="cyclic"):
        build_report_artifact(
            report_id="report-03",
            kind=ReportKind.ORACLE_VERDICTS,
            payload=payload,
            provenance=("oracle-response",),
        )
