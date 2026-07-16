"""Authoritative approval-condition evaluation over canonical execution inputs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import ActionManifest, sha256_json
from vulnhunter.approvals.models import ApprovalRequest


class ApprovalConditionError(RuntimeError):
    pass


class ApprovalConditionFacts(BaseModel):
    """Facts derived by the trusted evaluator, never supplied to consumption."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_requests: int = Field(ge=1)
    maximum_runtime_seconds: int = Field(ge=1)
    maximum_output_bytes: int = Field(ge=1)
    target_identifiers: tuple[str, ...] = Field(min_length=1)
    filesystem_paths: tuple[Path, ...] = ()
    network_destinations: tuple[str, ...] = ()
    selected_tool: str
    selected_profile: str
    credential_attempts: bool
    destructive_checks: bool
    adapter_identity: str

    @field_validator("selected_tool", "selected_profile", "adapter_identity")
    @classmethod
    def validate_nonempty_identity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("execution identity fields must not be blank")
        return value


class CanonicalApprovalExecutionPlan(BaseModel):
    """Immutable plan produced after governed planning and adapter selection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str
    action_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_identifiers: tuple[str, ...] = Field(min_length=1)
    selected_tool: str
    selected_profile: str
    request_budget: int = Field(ge=1)
    runtime_budget_seconds: int = Field(ge=1)
    output_budget_bytes: int = Field(ge=1)
    credential_attempts: bool = False
    destructive_checks: bool = False
    filesystem_paths: tuple[Path, ...] = ()
    network_destinations: tuple[str, ...] = ()
    adapter_identity: str

    @field_validator("execution_id", "selected_tool", "selected_profile", "adapter_identity")
    @classmethod
    def validate_nonempty_identity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("canonical plan identity fields must not be blank")
        return value

    @field_validator("target_identifiers", "network_destinations")
    @classmethod
    def validate_nonempty_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("canonical plan values must not be blank")
        if len(values) != len(set(values)):
            raise ValueError("canonical plan values must be unique")
        return values

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ApprovalConditionEvaluation(BaseModel):
    """Short-lived evaluation bound to one approval, manifest, plan, and execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_request_id: str
    action_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_id: str
    execution_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluated_facts: ApprovalConditionFacts
    evaluator_identity: str
    evaluator_version: str
    evaluated_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_lifetime(self):
        if self.expires_at <= self.evaluated_at:
            raise ValueError("condition evaluation expiry must follow evaluation time")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ApprovalConditionEvaluator:
    """Concrete evaluator intended for trusted composition-root construction."""

    def __init__(
        self,
        *,
        evaluator_identity: str = "approval-condition-evaluator",
        evaluator_version: str = "1.0",
        validity_seconds: int = 30,
    ) -> None:
        if not evaluator_identity.strip() or not evaluator_version.strip():
            raise ValueError("condition evaluator identity and version are required")
        if validity_seconds < 1 or validity_seconds > 300:
            raise ValueError("condition evaluation validity must be between 1 and 300 seconds")
        self.evaluator_identity = evaluator_identity
        self.evaluator_version = evaluator_version
        self.validity_seconds = validity_seconds

    def evaluate(
        self,
        *,
        approval: ApprovalRequest,
        manifest: ActionManifest,
        execution_plan: CanonicalApprovalExecutionPlan,
        execution_id: str,
        now: datetime,
    ) -> ApprovalConditionEvaluation:
        manifest_sha256 = manifest.fingerprint()
        if approval.action_manifest_sha256 != manifest_sha256:
            raise ApprovalConditionError("approval is bound to another action manifest")
        if execution_plan.action_manifest_sha256 != manifest_sha256:
            raise ApprovalConditionError("execution plan is bound to another action manifest")
        if execution_plan.execution_id != execution_id:
            raise ApprovalConditionError("execution plan is bound to another execution")
        if execution_plan.selected_tool != manifest.tool_id:
            raise ApprovalConditionError("execution plan selected a different tool")
        if execution_plan.target_identifiers != manifest.target_references:
            raise ApprovalConditionError("execution plan target binding does not match manifest")
        if execution_plan.request_budget > manifest.limits.maximum_requests:
            raise ApprovalConditionError("execution plan request budget exceeds manifest")
        if execution_plan.runtime_budget_seconds > manifest.limits.timeout_seconds:
            raise ApprovalConditionError("execution plan runtime budget exceeds manifest")
        if execution_plan.output_budget_bytes > manifest.limits.maximum_output_bytes:
            raise ApprovalConditionError("execution plan output budget exceeds manifest")

        facts = ApprovalConditionFacts(
            maximum_requests=execution_plan.request_budget,
            maximum_runtime_seconds=execution_plan.runtime_budget_seconds,
            maximum_output_bytes=execution_plan.output_budget_bytes,
            target_identifiers=execution_plan.target_identifiers,
            filesystem_paths=execution_plan.filesystem_paths,
            network_destinations=execution_plan.network_destinations,
            selected_tool=execution_plan.selected_tool,
            selected_profile=execution_plan.selected_profile,
            credential_attempts=execution_plan.credential_attempts,
            destructive_checks=execution_plan.destructive_checks,
            adapter_identity=execution_plan.adapter_identity,
        )
        expiry = min(
            approval.expires_at,
            now + timedelta(seconds=self.validity_seconds),
        )
        return ApprovalConditionEvaluation(
            approval_request_id=approval.request_id,
            action_manifest_sha256=manifest_sha256,
            execution_id=execution_id,
            execution_plan_sha256=execution_plan.fingerprint(),
            evaluated_facts=facts,
            evaluator_identity=self.evaluator_identity,
            evaluator_version=self.evaluator_version,
            evaluated_at=now,
            expires_at=expiry,
        )


def validate_authoritative_evaluation(
    *,
    approval: ApprovalRequest,
    manifest: ActionManifest,
    execution_plan: CanonicalApprovalExecutionPlan,
    execution_id: str,
    evaluation: ApprovalConditionEvaluation,
    evaluator: ApprovalConditionEvaluator,
    now: datetime | None = None,
) -> None:
    """Validate evaluator output independently before approval consumption."""
    instant = now or datetime.now(UTC)
    expected_facts = ApprovalConditionFacts(
        maximum_requests=execution_plan.request_budget,
        maximum_runtime_seconds=execution_plan.runtime_budget_seconds,
        maximum_output_bytes=execution_plan.output_budget_bytes,
        target_identifiers=execution_plan.target_identifiers,
        filesystem_paths=execution_plan.filesystem_paths,
        network_destinations=execution_plan.network_destinations,
        selected_tool=execution_plan.selected_tool,
        selected_profile=execution_plan.selected_profile,
        credential_attempts=execution_plan.credential_attempts,
        destructive_checks=execution_plan.destructive_checks,
        adapter_identity=execution_plan.adapter_identity,
    )
    bindings = (
        evaluation.approval_request_id == approval.request_id,
        evaluation.action_manifest_sha256 == manifest.fingerprint(),
        evaluation.execution_id == execution_id,
        evaluation.execution_plan_sha256 == execution_plan.fingerprint(),
        evaluation.evaluated_facts == expected_facts,
        evaluation.evaluator_identity == evaluator.evaluator_identity,
        evaluation.evaluator_version == evaluator.evaluator_version,
    )
    if not all(bindings):
        raise ApprovalConditionError("condition evaluation binding is invalid")
    if evaluation.evaluated_at > instant:
        raise ApprovalConditionError("condition evaluation timestamp is in the future")
    if evaluation.expires_at > approval.expires_at or instant >= evaluation.expires_at:
        raise ApprovalConditionError("condition evaluation is stale")
    if instant - evaluation.evaluated_at > timedelta(seconds=evaluator.validity_seconds):
        raise ApprovalConditionError("condition evaluation is stale")
    validate_approval_conditions(approval, evaluation.evaluated_facts)


def validate_approval_conditions(
    approval: ApprovalRequest,
    facts: ApprovalConditionFacts,
) -> None:
    """Evaluate supported conditions against authoritative derived facts."""
    for condition in approval.conditions:
        key, separator, raw_value = condition.partition("=")
        if not separator:
            raise ApprovalConditionError("approval condition is not typed")
        key = key.strip()
        value = raw_value.strip()
        if key == "maximum_requests":
            _require_int_limit(key, value, facts.maximum_requests)
        elif key == "maximum_runtime_seconds":
            _require_int_limit(key, value, facts.maximum_runtime_seconds)
        elif key == "maximum_output_bytes":
            _require_int_limit(key, value, facts.maximum_output_bytes)
        elif key == "permitted_target_id":
            if value not in facts.target_identifiers:
                raise ApprovalConditionError("target condition is not satisfied")
        elif key == "permitted_tool":
            if value != facts.selected_tool:
                raise ApprovalConditionError("tool condition is not satisfied")
        elif key == "permitted_profile":
            if value != facts.selected_profile:
                raise ApprovalConditionError("profile condition is not satisfied")
        elif key == "no_credential_attempts":
            if value.lower() != "true" or facts.credential_attempts:
                raise ApprovalConditionError("credential-attempt condition is not satisfied")
        elif key == "no_destructive_checks":
            if value.lower() != "true" or facts.destructive_checks:
                raise ApprovalConditionError("destructive-check condition is not satisfied")
        elif key == "permitted_filesystem_path":
            if not _all_paths_allowed(value, facts.filesystem_paths):
                raise ApprovalConditionError("filesystem-path condition is not satisfied")
        elif key == "permitted_network_destination":
            if any(destination != value for destination in facts.network_destinations):
                raise ApprovalConditionError("network-destination condition is not satisfied")
        elif key == "permitted_adapter":
            if value != facts.adapter_identity:
                raise ApprovalConditionError("adapter condition is not satisfied")
        else:
            raise ApprovalConditionError(f"unsupported approval condition: {key}")


def _require_int_limit(key: str, value: str, actual: int) -> None:
    try:
        expected = int(value)
    except ValueError as exc:
        raise ApprovalConditionError(f"{key} condition is malformed") from exc
    if actual > expected:
        raise ApprovalConditionError(f"{key} condition is not satisfied")


def _all_paths_allowed(value: str, paths: tuple[Path, ...]) -> bool:
    root = Path(value).expanduser().resolve()
    for candidate_path in paths:
        candidate = candidate_path.expanduser().resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
    return True
