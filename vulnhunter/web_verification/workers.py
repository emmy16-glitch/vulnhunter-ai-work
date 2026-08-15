"""Safe capability registry and immutable plans for broader verification evidence workers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vulnhunter.actions.models import sha256_json
from vulnhunter.authorization.models import AuthorizationRecord
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification.errors import WebVerificationContractError
from vulnhunter.web_verification.external_evidence import TrustedExternalEvidenceCollector
from vulnhunter.web_verification.external_models import ExternalEvidenceClass
from vulnhunter.web_verification.lifecycle import (
    authorization_reference_sha256,
    target_reference_sha256,
)
from vulnhunter.web_verification.lifecycle_models import (
    VerificationCollectionPlan,
    VerificationWorkerCapability,
)
from vulnhunter.web_verification.models import IndependentVerificationResult


class VerificationWorkerRegistry:
    """Registry of non-shell, offline/read-only evidence collection capabilities."""

    def __init__(self, capabilities: tuple[VerificationWorkerCapability, ...]) -> None:
        if not capabilities:
            raise WebVerificationContractError(
                "at least one verification worker capability is required"
            )
        self._capabilities: dict[str, VerificationWorkerCapability] = {}
        for capability in capabilities:
            if capability.worker_id in self._capabilities:
                raise WebVerificationContractError("verification worker IDs must be unique")
            self._capabilities[capability.worker_id] = capability

    def get(self, worker_id: str) -> VerificationWorkerCapability:
        try:
            return self._capabilities[worker_id]
        except KeyError as exc:
            raise WebVerificationContractError("verification worker is not registered") from exc

    def compatible_workers(
        self, strategy: VerificationStrategy
    ) -> tuple[VerificationWorkerCapability, ...]:
        return tuple(
            sorted(
                (item for item in self._capabilities.values() if strategy in item.strategies),
                key=lambda item: item.worker_id,
            )
        )

    def build_plan(
        self,
        *,
        worker_id: str,
        collector: TrustedExternalEvidenceCollector,
        authorization: AuthorizationRecord,
        passive_result: IndependentVerificationResult,
        now: datetime,
        expires_in: timedelta = timedelta(minutes=10),
    ) -> VerificationCollectionPlan:
        capability = self.get(worker_id)
        instant = now.astimezone(UTC)
        if authorization.status != "active" or not (
            authorization.valid_from <= instant < authorization.expires_at
        ):
            raise WebVerificationContractError(
                "verification collection authorization is not active"
            )
        if passive_result.strategy not in capability.strategies:
            raise WebVerificationContractError("verification worker does not support this strategy")
        if passive_result.strategy not in collector.policy.allowed_strategies:
            raise WebVerificationContractError(
                "collector policy does not allow this verification strategy"
            )
        if capability.network_access_allowed and not collector.policy.allow_read_only_network:
            raise WebVerificationContractError(
                "collector is not trusted for read-only network evidence"
            )
        if capability.maximum_evidence_bytes > collector.policy.maximum_evidence_bytes:
            raise WebVerificationContractError(
                "worker evidence ceiling exceeds collector trust policy"
            )
        expected_target = target_reference_sha256(authorization.target_url)
        if passive_result.evidence.target_reference_sha256 != expected_target:
            raise WebVerificationContractError(
                "verification worker plan target does not match authorization"
            )
        expiry = min(authorization.expires_at, instant + expires_in)
        if expiry <= instant:
            raise WebVerificationContractError(
                "verification collection plan has no usable lifetime"
            )
        plan_id = sha256_json(
            {
                "worker_id": capability.worker_id,
                "capability_sha256": capability.capability_sha256,
                "passive_verification_result_sha256": passive_result.result_sha256,
                "authorization_snapshot_sha256": authorization.record_sha256,
                "strategy": passive_result.strategy.value,
                "evidence_class": capability.evidence_class.value,
            }
        )
        payload = {
            "schema_version": 1,
            "plan_id": plan_id,
            "worker_id": capability.worker_id,
            "worker_runtime_sha256": capability.runtime_sha256,
            "capability_sha256": capability.capability_sha256,
            "collector_id": collector.policy.collector_id,
            "collector_key_id": collector.policy.collector_key_id,
            "passive_verification_id": passive_result.verification_id,
            "passive_verification_result_sha256": passive_result.result_sha256,
            "authorization_id": authorization.authorization_id,
            "authorization_reference_sha256": authorization_reference_sha256(
                authorization.authorization_id
            ),
            "authorization_snapshot_sha256": authorization.record_sha256,
            "target_reference_sha256": expected_target,
            "strategy": passive_result.strategy,
            "evidence_class": capability.evidence_class,
            "network_access_allowed": capability.network_access_allowed,
            "network_methods": capability.network_methods,
            "maximum_evidence_bytes": capability.maximum_evidence_bytes,
            "expires_at": expiry,
            "execution_command_included": False,
            "mutating_requests_allowed": False,
            "credential_use_allowed": False,
            "authorization_bypass_allowed": False,
            "shell_execution_allowed": False,
            "payload_execution_allowed": False,
        }
        provisional = VerificationCollectionPlan.model_construct(**payload, plan_sha256="0" * 64)
        return VerificationCollectionPlan.model_validate(
            {
                **payload,
                "plan_sha256": sha256_json(
                    provisional.model_dump(mode="json", exclude={"plan_sha256"})
                ),
            }
        )


def build_worker_capability(
    *,
    worker_id: str,
    runtime_sha256: str,
    evidence_class: ExternalEvidenceClass,
    strategies: tuple[VerificationStrategy, ...],
    network_access_allowed: bool = False,
    network_methods: tuple[str, ...] = (),
    maximum_evidence_bytes: int = 5_000_000,
) -> VerificationWorkerCapability:
    canonical_strategies = tuple(sorted(strategies, key=lambda item: item.value))
    canonical_methods = tuple(sorted(network_methods))
    payload = {
        "schema_version": 1,
        "worker_id": worker_id,
        "runtime_sha256": runtime_sha256,
        "evidence_class": evidence_class,
        "strategies": canonical_strategies,
        "network_access_allowed": network_access_allowed,
        "network_methods": canonical_methods,
        "maximum_evidence_bytes": maximum_evidence_bytes,
        "mutating_requests_allowed": False,
        "credential_use_allowed": False,
        "authorization_bypass_allowed": False,
        "shell_execution_allowed": False,
        "payload_execution_allowed": False,
    }
    provisional = VerificationWorkerCapability.model_construct(
        **payload, capability_sha256="0" * 64
    )
    return VerificationWorkerCapability.model_validate(
        {
            **payload,
            "capability_sha256": sha256_json(
                provisional.model_dump(mode="json", exclude={"capability_sha256"})
            ),
        }
    )


def default_verification_worker_capabilities() -> tuple[VerificationWorkerCapability, ...]:
    """Return safe evidence-worker families; none contain executable commands or write authority."""
    all_strategies = tuple(sorted(VerificationStrategy, key=lambda item: item.value))
    return (
        build_worker_capability(
            worker_id="offline-artifact-verifier-v1",
            runtime_sha256="1" * 64,
            evidence_class=ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
            strategies=all_strategies,
            maximum_evidence_bytes=4096,
        ),
        build_worker_capability(
            worker_id="read-only-browser-verifier-v1",
            runtime_sha256="2" * 64,
            evidence_class=ExternalEvidenceClass.READ_ONLY_BROWSER_METADATA,
            strategies=tuple(
                sorted(
                    (
                        VerificationStrategy.REQUEST_INTEGRITY_REVIEW,
                        VerificationStrategy.FILE_UPLOAD_REVIEW,
                        VerificationStrategy.AUTHENTICATION_REVIEW,
                        VerificationStrategy.API_ACCESS_REVIEW,
                    ),
                    key=lambda item: item.value,
                )
            ),
            network_access_allowed=True,
            network_methods=("GET", "HEAD"),
            maximum_evidence_bytes=4096,
        ),
        build_worker_capability(
            worker_id="read-only-http-verifier-v1",
            runtime_sha256="3" * 64,
            evidence_class=ExternalEvidenceClass.READ_ONLY_HTTP_METADATA,
            strategies=tuple(
                sorted(
                    (
                        VerificationStrategy.REQUEST_INTEGRITY_REVIEW,
                        VerificationStrategy.API_ACCESS_REVIEW,
                    ),
                    key=lambda item: item.value,
                )
            ),
            network_access_allowed=True,
            network_methods=("GET", "HEAD"),
            maximum_evidence_bytes=4096,
        ),
    )
