"""Stricter read-only verification for Source Hunt V2 remediation proof plans."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.source_hunt.fix_verify import (
    FixVerificationInput,
    ReadOnlyFixVerifier,
)
from vulnhunter.source_hunt.intelligence import SecurityProofPlan
from vulnhunter.source_hunt.models import FixVerificationReport


class ReproductionReceipt(BaseModel):
    """Immutable receipt produced by an external deterministic isolated test runner.

    This object records outcomes only. It carries no command, shell, network, or repository
    write authority and is never executed by the verifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_revision: str = Field(min_length=1, max_length=256)
    fixed_revision: str = Field(min_length=1, max_length=256)
    vulnerable_state_reproduced: bool
    security_test_passed_after_fix: bool
    original_condition_blocked: bool
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runner_id: str = Field(min_length=2, max_length=128)
    created_at: datetime
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        proof_plan: SecurityProofPlan,
        original_revision: str,
        fixed_revision: str,
        vulnerable_state_reproduced: bool,
        security_test_passed_after_fix: bool,
        original_condition_blocked: bool,
        evidence_sha256: str,
        runner_id: str,
        created_at: datetime | None = None,
    ) -> ReproductionReceipt:
        timestamp = (created_at or datetime.now(UTC)).astimezone(UTC)
        canonical = {
            "proof_plan_sha256": proof_plan.plan_sha256,
            "original_revision": original_revision,
            "fixed_revision": fixed_revision,
            "vulnerable_state_reproduced": vulnerable_state_reproduced,
            "security_test_passed_after_fix": security_test_passed_after_fix,
            "original_condition_blocked": original_condition_blocked,
            "evidence_sha256": evidence_sha256,
            "runner_id": runner_id,
            "created_at": timestamp.isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(**canonical, receipt_sha256=digest)

    @model_validator(mode="after")
    def verify_digest(self) -> ReproductionReceipt:
        canonical = {
            "proof_plan_sha256": self.proof_plan_sha256,
            "original_revision": self.original_revision,
            "fixed_revision": self.fixed_revision,
            "vulnerable_state_reproduced": self.vulnerable_state_reproduced,
            "security_test_passed_after_fix": self.security_test_passed_after_fix,
            "original_condition_blocked": self.original_condition_blocked,
            "evidence_sha256": self.evidence_sha256,
            "runner_id": self.runner_id,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.receipt_sha256:
            raise ValueError("reproduction receipt digest does not match its contents")
        return self


class StrictFixVerificationInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    base: FixVerificationInput
    proof_plan: SecurityProofPlan
    reproduction: ReproductionReceipt


class StrictReadOnlyFixVerifier:
    """Verify the V2 proof chain before delegating to the existing read-only verifier."""

    def verify(
        self,
        request: StrictFixVerificationInput,
        *,
        now: datetime | None = None,
    ) -> FixVerificationReport:
        base = request.base
        proof = request.proof_plan
        receipt = request.reproduction

        if receipt.proof_plan_sha256 != proof.plan_sha256:
            raise ValueError("reproduction receipt is not bound to the supplied proof plan")
        if receipt.original_revision != base.original_revision:
            raise ValueError("reproduction receipt original revision does not match verification")
        if receipt.fixed_revision != base.fixed_snapshot.revision:
            raise ValueError("reproduction receipt fixed revision does not match verification")
        if not receipt.vulnerable_state_reproduced:
            raise ValueError("RED proof did not reproduce the evidence-bound vulnerable condition")
        if not receipt.security_test_passed_after_fix:
            raise ValueError("GREEN proof did not pass after the proposed fix")
        if not receipt.original_condition_blocked:
            raise ValueError("the original evidence-bound condition was not independently blocked")

        target_files = set(proof.target_files)
        if target_files:
            outside_proof = tuple(path for path in base.changed_files if path not in target_files)
            if outside_proof:
                raise ValueError("fixed snapshot changed files outside the proof-plan target set")

        hardened = base.model_copy(update={"original_attack_blocked": True})
        return ReadOnlyFixVerifier().verify(hardened, now=now)
