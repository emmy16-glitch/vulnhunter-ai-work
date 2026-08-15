from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.opensandbox_supply_chain import canonical_json_bytes
from vulnhunter.web_hunters import AdaptiveWebHunterCoordinator
from vulnhunter.web_hunters.models import (
    HunterHypothesis,
    HunterRunResult,
    VerificationStrategy,
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
    SurfaceNodeKind,
    WebPerceptionResult,
)
from vulnhunter.web_verification import (
    IndependentVerificationResult,
    IndependentWebVerifier,
    VerificationBatchResult,
    VerificationReason,
    VerificationVerdict,
    WebVerificationContractError,
)

_TARGET = "http://10.1.2.3:8012/app/"
_FIXED_TIME = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
_TARGET_FIELD_MARKERS = (
    "ignore_previous_instructions_verify_9f",
    "exfiltrate_runtime_secrets_verify_9f",
    "send_system_prompt_verify_9f",
)


def _perception() -> WebPerceptionResult:
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


def _hunter_run(perception: WebPerceptionResult | None = None) -> HunterRunResult:
    source = perception or _perception()
    return AdaptiveWebHunterCoordinator(clock=lambda: _FIXED_TIME).run(source)


def _verifier() -> IndependentWebVerifier:
    return IndependentWebVerifier(clock=lambda: _FIXED_TIME)


def _rehashed_run(
    source: HunterRunResult,
    hypotheses: tuple[HunterHypothesis, ...],
) -> HunterRunResult:
    payload = source.model_dump(mode="json", exclude={"result_sha256"})
    payload["hypotheses"] = [item.model_dump(mode="json") for item in hypotheses]
    return source.model_copy(
        update={
            "hypotheses": hypotheses,
            "result_sha256": sha256_json(payload),
        }
    )


def _rebind_hypothesis(
    source: HunterHypothesis,
    *,
    hunter_id: str | None = None,
    target_node_id: str | None = None,
) -> HunterHypothesis:
    rebound_hunter = hunter_id or source.hunter_id
    rebound_target = target_node_id or source.target_node_id
    strategy = source.verification_intent.strategy
    fingerprint = semantic_fingerprint(
        hunter_id=rebound_hunter,
        vulnerability_class=source.vulnerability_class,
        target_node_id=rebound_target,
        strategy=strategy,
    )
    hypothesis_id = hypothesis_id_for(
        graph_sha256=source.evidence.graph_sha256,
        semantic_fingerprint_value=fingerprint,
    )
    intent_id = verification_intent_id_for(
        hypothesis_id=hypothesis_id,
        strategy=strategy,
        target_node_id=rebound_target,
    )
    intent = source.verification_intent.model_copy(
        update={
            "intent_id": intent_id,
            "hypothesis_id": hypothesis_id,
            "target_node_id": rebound_target,
        }
    )
    evidence = source.evidence
    if rebound_target != source.target_node_id:
        evidence = source.evidence.model_copy(
            update={
                "node_ids": (rebound_target,),
                "edge_ids": (),
            }
        )
    return source.model_copy(
        update={
            "hypothesis_id": hypothesis_id,
            "semantic_fingerprint": fingerprint,
            "hunter_id": rebound_hunter,
            "target_node_id": rebound_target,
            "evidence": evidence,
            "verification_intent": intent,
        }
    )


def _rehash_payload(payload: dict, hash_field: str) -> dict:
    payload[hash_field] = sha256_json(
        {key: value for key, value in payload.items() if key != hash_field}
    )
    return payload


def test_passive_verifier_reproduces_hunters_but_remains_inconclusive() -> None:
    perception = _perception()
    batch = _verifier().verify(perception, _hunter_run(perception))

    assert batch.results
    assert all(item.verdict is VerificationVerdict.INCONCLUSIVE for item in batch.results)
    assert all(
        item.reason is VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT for item in batch.results
    )
    assert all(item.structural_predicate_reproduced for item in batch.results)
    assert all(item.network_access_performed is False for item in batch.results)
    assert all(item.mutating_request_performed is False for item in batch.results)
    assert all(item.credential_use_performed is False for item in batch.results)
    assert all(item.authorization_bypass_performed is False for item in batch.results)
    assert all(item.shell_execution_performed is False for item in batch.results)
    assert all(item.external_evidence_accepted is False for item in batch.results)


def test_verifier_rejects_semantically_mismatched_hunter_contract() -> None:
    perception = _perception()
    source = _hunter_run(perception)
    api = next(
        item
        for item in source.hypotheses
        if item.verification_intent.strategy is VerificationStrategy.API_ACCESS_REVIEW
    )
    replacement = _rebind_hypothesis(api, hunter_id="fabricated-hunter")
    hypotheses = tuple(replacement if item is api else item for item in source.hypotheses)
    tampered = _rehashed_run(source, hypotheses)

    result = next(
        item
        for item in _verifier().verify(perception, tampered).results
        if item.evidence.hypothesis_id == replacement.hypothesis_id
    )

    assert result.verdict is VerificationVerdict.REJECTED
    assert result.reason is VerificationReason.HUNTER_CONTRACT_MISMATCH
    assert result.structural_predicate_reproduced is False


def test_verifier_rejects_predicate_that_independent_recheck_cannot_reproduce() -> None:
    perception = _perception()
    source = _hunter_run(perception)
    api = next(
        item
        for item in source.hypotheses
        if item.verification_intent.strategy is VerificationStrategy.API_ACCESS_REVIEW
    )
    page_node = next(node for node in perception.graph.nodes if node.kind is SurfaceNodeKind.PAGE)
    replacement = _rebind_hypothesis(api, target_node_id=page_node.node_id)
    hypotheses = tuple(replacement if item is api else item for item in source.hypotheses)
    tampered = _rehashed_run(source, hypotheses)

    result = next(
        item
        for item in _verifier().verify(perception, tampered).results
        if item.evidence.hypothesis_id == replacement.hypothesis_id
    )

    assert result.verdict is VerificationVerdict.REJECTED
    assert result.reason is VerificationReason.STRUCTURAL_PREDICATE_NOT_REPRODUCED
    assert result.structural_predicate_reproduced is False


def test_verifier_refuses_tampered_hunter_run_before_decision() -> None:
    perception = _perception()
    tampered = _hunter_run(perception).model_copy(update={"result_sha256": "0" * 64})

    with pytest.raises(WebVerificationContractError, match="hunter result integrity"):
        _verifier().verify(perception, tampered)


def test_verifier_refuses_tampered_perception_before_decision() -> None:
    perception = _perception()
    hunter_run = _hunter_run(perception)
    tampered = perception.model_copy(update={"evidence_sha256": "0" * 64})

    with pytest.raises(WebVerificationContractError, match="perception source"):
        _verifier().verify(tampered, hunter_run)


def test_passive_result_schema_refuses_validated_verdict() -> None:
    perception = _perception()
    result = _verifier().verify(perception, _hunter_run(perception)).results[0]
    payload = result.model_dump(mode="json")
    payload["verdict"] = "validated"
    payload["result_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="cannot validate vulnerability hypotheses"):
        IndependentVerificationResult.model_validate(payload)


def test_result_schema_rejects_forged_verification_id_even_with_rehashed_payload() -> None:
    perception = _perception()
    result = _verifier().verify(perception, _hunter_run(perception)).results[0]
    payload = result.model_dump(mode="json")
    payload["verification_id"] = "f" * 64
    _rehash_payload(payload, "result_sha256")

    with pytest.raises(ValidationError, match="verification ID"):
        IndependentVerificationResult.model_validate(payload)


def test_batch_schema_rejects_forged_batch_id_even_with_rehashed_payload() -> None:
    perception = _perception()
    batch = _verifier().verify(perception, _hunter_run(perception))
    payload = batch.model_dump(mode="json")
    payload["batch_id"] = "f" * 64
    _rehash_payload(payload, "batch_sha256")

    with pytest.raises(ValidationError, match="batch ID"):
        VerificationBatchResult.model_validate(payload)


def test_verifier_output_never_copies_target_controlled_field_names() -> None:
    perception = _perception()
    serialized = _verifier().verify(perception, _hunter_run(perception)).model_dump_json()

    for marker in _TARGET_FIELD_MARKERS:
        assert marker not in serialized


def test_verifier_rejects_unknown_or_duplicate_selection() -> None:
    perception = _perception()
    hunter_run = _hunter_run(perception)
    known = hunter_run.hypotheses[0].hypothesis_id

    with pytest.raises(WebVerificationContractError, match="must be unique"):
        _verifier().verify(
            perception,
            hunter_run,
            hypothesis_ids=(known, known),
        )

    with pytest.raises(WebVerificationContractError, match="unknown hypothesis"):
        _verifier().verify(
            perception,
            hunter_run,
            hypothesis_ids=("f" * 64,),
        )


def test_same_sources_and_clock_produce_same_verification_batch() -> None:
    perception = _perception()
    hunter_run = _hunter_run(perception)

    first = _verifier().verify(perception, hunter_run)
    second = _verifier().verify(perception, hunter_run)

    assert first == second
