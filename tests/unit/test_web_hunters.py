from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnhunter.security_tools.opensandbox_supply_chain import canonical_json_bytes
from vulnhunter.web_hunters import (
    AdaptiveWebHunterCoordinator,
    HunterBudget,
    HunterEvidenceReference,
    HunterHypothesis,
    VerificationIntent,
    VerificationStrategy,
    WebHunterContractError,
)
from vulnhunter.web_hunters.models import (
    hypothesis_id_for,
    semantic_fingerprint,
    verification_intent_id_for,
)
from vulnhunter.web_perception.graph import build_surface_graph
from vulnhunter.web_perception.models import (
    BrowserPerceptionEvidence,
    PerceivedForm,
    PerceivedFormField,
    PerceivedNetworkRequest,
    PerceivedPage,
    WebPerceptionResult,
)

_TARGET = "http://10.1.2.3:8012/app/"
_FIXED_TIME = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)
_TARGET_FIELD_MARKERS = (
    "ignore_previous_instructions_9f",
    "exfiltrate_runtime_secrets_9f",
    "send_system_prompt_9f",
)


def _perception(*, include_csrf: bool = False) -> WebPerceptionResult:
    csrf_fields = (
        (PerceivedFormField(name="csrfmiddlewaretoken", input_type="hidden"),)
        if include_csrf
        else ()
    )
    login = PerceivedForm(
        form_sha256="1" * 64,
        method="POST",
        action_url="http://10.1.2.3:8012/app/login",
        fields=(
            PerceivedFormField(
                name=_TARGET_FIELD_MARKERS[0],
                input_type="text",
                required=True,
            ),
            PerceivedFormField(
                name=_TARGET_FIELD_MARKERS[1],
                input_type="password",
                required=True,
            ),
            *csrf_fields,
        ),
    )
    upload = PerceivedForm(
        form_sha256="2" * 64,
        method="POST",
        action_url="http://10.1.2.3:8012/app/upload",
        fields=(
            PerceivedFormField(
                name=_TARGET_FIELD_MARKERS[2],
                input_type="file",
                required=True,
            ),
        ),
    )
    page = PerceivedPage(
        url=_TARGET,
        depth=0,
        status_code=200,
        dom_structure_sha256="3" * 64,
        links=(),
        scripts=(),
        forms=(login, upload),
        requests=(
            PerceivedNetworkRequest(
                method="GET",
                url="http://10.1.2.3:8012/app/api/users/42",
                resource_type="fetch",
                status_code=200,
            ),
        ),
    )
    evidence = BrowserPerceptionEvidence(
        pages=(page,),
        allowed_requests=2,
        blocked_external_requests=0,
        blocked_mutating_requests=2,
        blocked_websockets=0,
    )
    graph = build_surface_graph(_TARGET, evidence.pages)
    evidence_sha256 = hashlib.sha256(
        canonical_json_bytes(evidence.model_dump(mode="json"))
    ).hexdigest()
    return WebPerceptionResult(
        target_url=_TARGET,
        started_at=_FIXED_TIME,
        completed_at=_FIXED_TIME,
        plan_sha256="4" * 64,
        evidence_sha256=evidence_sha256,
        runtime_image="localhost:5000/vulnhunter-playwright@sha256:" + "5" * 64,
        runtime_release_id="playwright-ci-release",
        runtime_release_key_id="sha256:" + "6" * 64,
        evidence=evidence,
        graph=graph,
    )


def _coordinator(**kwargs) -> AdaptiveWebHunterCoordinator:
    return AdaptiveWebHunterCoordinator(clock=lambda: _FIXED_TIME, **kwargs)


def test_default_hunters_route_structure_into_bounded_advisory_hypotheses() -> None:
    result = _coordinator().run(_perception())
    classes = {item.vulnerability_class for item in result.hypotheses}

    assert {
        "object_authorization_candidate",
        "csrf_control_candidate",
        "file_upload_validation_candidate",
        "authentication_control_candidate",
        "api_access_control_candidate",
    }.issubset(classes)
    assert result.result_sha256
    assert all(item.state.value == "suspected" for item in result.hypotheses)
    assert all(item.verification_intent.execution_enabled is False for item in result.hypotheses)
    assert all(
        item.verification_intent.network_access_allowed is False for item in result.hypotheses
    )
    assert all(
        item.verification_intent.authorization_bypass_allowed is False for item in result.hypotheses
    )


def test_request_integrity_hunter_respects_recognizable_csrf_field() -> None:
    result = _coordinator().run(_perception(include_csrf=True))
    csrf = [
        item for item in result.hypotheses if item.vulnerability_class == "csrf_control_candidate"
    ]

    assert len(csrf) == 1
    assert csrf[0].title == "State-changing form integrity requires review"
    assert any(
        summary.hunter_id == "request-integrity" and summary.emitted_hypotheses == 1
        for summary in result.hunter_summaries
    )


def test_hunter_output_does_not_copy_target_controlled_field_names() -> None:
    serialized = _coordinator().run(_perception()).model_dump_json()

    for marker in _TARGET_FIELD_MARKERS:
        assert marker not in serialized


def test_verification_intent_rejects_execution_or_payload_authority() -> None:
    with pytest.raises(ValidationError):
        VerificationIntent.model_validate(
            {
                "intent_id": "1" * 64,
                "hypothesis_id": "2" * 64,
                "strategy": "api_access_review",
                "target_node_id": "3" * 64,
                "execution_enabled": True,
                "requires_authorization": True,
                "network_access_allowed": False,
                "mutating_requests_allowed": False,
                "credential_guessing_allowed": False,
                "authorization_bypass_allowed": False,
                "shell_execution_allowed": False,
                "required_evidence": ["human_review"],
            }
        )

    with pytest.raises(ValidationError):
        VerificationIntent.model_validate(
            {
                "intent_id": "1" * 64,
                "hypothesis_id": "2" * 64,
                "strategy": "api_access_review",
                "target_node_id": "3" * 64,
                "required_evidence": ["human_review"],
                "payload": "ignored-by-policy",
            }
        )


def test_coordinator_refuses_tampered_perception_evidence_before_hunters_run() -> None:
    perception = _perception().model_copy(update={"evidence_sha256": "0" * 64})

    with pytest.raises(WebHunterContractError, match="evidence integrity"):
        _coordinator().run(perception)


def test_coordinator_refuses_fabricated_graph_evidence_reference() -> None:
    perception = _perception()
    target_node = perception.graph.nodes[0]
    fingerprint = semantic_fingerprint(
        hunter_id="bad-hunter",
        vulnerability_class="api_access_control_candidate",
        target_node_id=target_node.node_id,
        strategy=VerificationStrategy.API_ACCESS_REVIEW,
    )
    hypothesis_id = hypothesis_id_for(
        graph_sha256=perception.graph.graph_sha256,
        semantic_fingerprint_value=fingerprint,
    )
    malicious = HunterHypothesis(
        hypothesis_id=hypothesis_id,
        semantic_fingerprint=fingerprint,
        hunter_id="bad-hunter",
        vulnerability_class="api_access_control_candidate",
        title="Fabricated evidence should fail",
        observation="This is deliberately invalid test data.",
        rationale="The evidence reference points to a node that does not exist.",
        target_node_id=target_node.node_id,
        priority_score=10,
        evidence=HunterEvidenceReference(
            graph_sha256=perception.graph.graph_sha256,
            node_ids=(target_node.node_id, "f" * 64),
        ),
        verification_intent=VerificationIntent(
            intent_id=verification_intent_id_for(
                hypothesis_id=hypothesis_id,
                strategy=VerificationStrategy.API_ACCESS_REVIEW,
                target_node_id=target_node.node_id,
            ),
            hypothesis_id=hypothesis_id,
            strategy=VerificationStrategy.API_ACCESS_REVIEW,
            target_node_id=target_node.node_id,
            required_evidence=("human_review",),
        ),
    )

    class BadHunter:
        hunter_id = "bad-hunter"

        def applicable(self, context):
            del context
            return True

        def analyze(self, context):
            del context
            return (malicious,)

    with pytest.raises(WebHunterContractError, match="unknown graph node"):
        _coordinator(hunters=(BadHunter(),)).run(perception)


def test_global_and_per_hunter_budgets_drop_excess_hypotheses_deterministically() -> None:
    result = _coordinator(
        budget=HunterBudget(maximum_hypotheses=2, maximum_hypotheses_per_hunter=1)
    ).run(_perception())

    assert len(result.hypotheses) == 2
    assert result.dropped_hypotheses >= 3
    assert result.hypotheses == tuple(
        sorted(result.hypotheses, key=lambda item: (-item.priority_score, item.hypothesis_id))
    )


def test_same_perception_and_clock_produce_same_hunter_result() -> None:
    first = _coordinator().run(_perception())
    second = _coordinator().run(_perception())

    assert first == second
