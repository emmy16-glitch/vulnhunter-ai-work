from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}")
    return text.replace(old, new)


models_path = Path("vulnhunter/findings/models.py")
models = models_path.read_text(encoding="utf-8")
models = replace_once(
    models,
    '    AWAITING_REMEDIATION_REVIEW = "awaiting_remediation_review"\n    REMEDIATED = "remediated"\n',
    '    AWAITING_REMEDIATION_REVIEW = "awaiting_remediation_review"\n    READY_FOR_REPORT = "ready_for_report"\n    REMEDIATED = "remediated"\n',
    label="finding report-ready status",
)
models = replace_once(
    models,
    '    AWAITING_REVIEW = "awaiting_review"\n    CANCELLED = "cancelled"\n',
    '    AWAITING_REVIEW = "awaiting_review"\n    REVIEW_NEEDS_REWORK = "review_needs_rework"\n    REVIEW_APPROVED = "review_approved"\n    CANCELLED = "cancelled"\n',
    label="remediation review states",
)
models = replace_once(
    models,
    '''class RetestOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANNOT_VERIFY = "cannot_verify"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class EvidenceReference(BaseModel):
''',
    '''class RetestOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANNOT_VERIFY = "cannot_verify"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class RemediationReviewOutcome(StrEnum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    CANNOT_VERIFY = "cannot_verify"
    BLOCKED = "blocked"


class RemediationReviewChecklist(BaseModel):
    """Evidence-based review checklist; unknown values force abstention."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_lineage_complete: bool | None
    fixed_revision_matches: bool | None
    approved_scope_respected: bool | None
    security_claim_supported: bool | None
    regressions_acceptable: bool | None


class EvidenceReference(BaseModel):
''',
    label="review outcome and checklist",
)
review_models = '''

class RemediationReviewPlanRecord(BaseModel):
    """Immutable identity-bound review plan for one exact passed retest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    review_id: str
    reviewer_id: str
    reviewer_identity_sha256: str
    source_finding_revision: int = Field(ge=0)
    source_finding_fingerprint: str
    remediation_id: str
    fix_verification_receipt_id: str
    retest_receipt_id: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    evidence_references: tuple[str, ...] = Field(min_length=1, max_length=500)
    plan_sha256: str
    created_at: datetime
    expires_at: datetime

    @field_validator(
        "review_id",
        "reviewer_id",
        "remediation_id",
        "fix_verification_receipt_id",
        "retest_receipt_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation review identifiers must be stable lowercase values")
        return value

    @field_validator(
        "reviewer_identity_sha256",
        "source_finding_fingerprint",
        "plan_sha256",
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("remediation review digest fields must be SHA-256 values")
        return value

    @field_validator("evidence_references")
    @classmethod
    def validate_evidence_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("remediation review evidence references must be unique")
        if any(_IDENTIFIER.fullmatch(value) is None for value in values):
            raise ValueError("remediation review evidence references must be stable")
        return values

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        for value in (self.created_at, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("remediation review timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("remediation review expiry must follow creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        finding_fingerprint: str,
        remediation_id: str,
        reviewer_id: str,
        reviewer_identity_sha256: str,
        fix_verification_receipt_id: str,
        retest_receipt_id: str,
        fixed_revision: str,
        evidence_references: tuple[str, ...],
        created_at: datetime,
        expires_at: datetime,
    ) -> RemediationReviewPlanRecord:
        canonical = {
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "finding_fingerprint": finding_fingerprint,
            "remediation_id": remediation_id,
            "reviewer_id": reviewer_id,
            "reviewer_identity_sha256": reviewer_identity_sha256,
            "fix_verification_receipt_id": fix_verification_receipt_id,
            "retest_receipt_id": retest_receipt_id,
            "fixed_revision": fixed_revision,
            "evidence_references": list(evidence_references),
            "created_at": created_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            review_id=f"review-{digest[:32]}",
            reviewer_id=reviewer_id,
            reviewer_identity_sha256=reviewer_identity_sha256,
            source_finding_revision=finding_revision,
            source_finding_fingerprint=finding_fingerprint,
            remediation_id=remediation_id,
            fix_verification_receipt_id=fix_verification_receipt_id,
            retest_receipt_id=retest_receipt_id,
            fixed_revision=fixed_revision,
            evidence_references=evidence_references,
            plan_sha256=digest,
            created_at=created_at,
            expires_at=expires_at,
        )


class RemediationReviewReference(BaseModel):
    """Integrity pointer to one signed independent remediation review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    review_id: str
    sha256: str
    outcome: RemediationReviewOutcome
    reviewer_id: str
    reviewer_identity_sha256: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    retest_receipt_id: str
    created_at: datetime

    @field_validator("receipt_id", "review_id", "reviewer_id", "retest_receipt_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation review references require stable identifiers")
        return value

    @field_validator("sha256", "reviewer_identity_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("remediation review reference requires SHA-256 values")
        return value

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("remediation review receipt time must be timezone-aware")
        return self
'''
models = replace_once(
    models,
    '''    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("retest receipt time must be timezone-aware")
        return self


class RemediationRecord(BaseModel):
''',
    '''    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("retest receipt time must be timezone-aware")
        return self
''' + review_models + '''

class RemediationRecord(BaseModel):
''',
    label="review plan and reference models",
)
models = replace_once(
    models,
    '    retest_history: tuple[RetestReceiptReference, ...] = ()\n    created_at: datetime | None = None\n',
    '    retest_history: tuple[RetestReceiptReference, ...] = ()\n    review_history: tuple[RemediationReviewReference, ...] = ()\n    created_at: datetime | None = None\n',
    label="remediation review history field",
)
models = replace_once(
    models,
    '                self.retest_history,\n                self.created_at,\n',
    '                self.retest_history,\n                self.review_history,\n                self.created_at,\n',
    label="legacy governed review fields",
)
models = replace_once(
    models,
    '        latest_retest = self.retest_history[-1] if self.retest_history else None\n',
    '        latest_retest = self.retest_history[-1] if self.retest_history else None\n        latest_review = self.review_history[-1] if self.review_history else None\n',
    label="latest review reference",
)
models = replace_once(
    models,
    '''        elif self.state == RemediationState.AWAITING_REVIEW:
            if latest_retest is None or latest_retest.outcome != RetestOutcome.PASSED:
                raise ValueError("awaiting-review remediation requires a passed retest receipt")

        if self.state == RemediationState.CANCELLED:
''',
    '''        elif self.state == RemediationState.AWAITING_REVIEW:
            if latest_retest is None or latest_retest.outcome != RetestOutcome.PASSED:
                raise ValueError("awaiting-review remediation requires a passed retest receipt")
            if latest_review is not None and latest_review.outcome == RemediationReviewOutcome.APPROVED:
                raise ValueError("approved remediation cannot remain awaiting review")
        elif self.state == RemediationState.REVIEW_NEEDS_REWORK:
            if latest_review is None or latest_review.outcome not in {
                RemediationReviewOutcome.CHANGES_REQUESTED,
                RemediationReviewOutcome.CANNOT_VERIFY,
                RemediationReviewOutcome.BLOCKED,
            }:
                raise ValueError("review-needs-rework requires a non-approved review receipt")
        elif self.state == RemediationState.REVIEW_APPROVED:
            if latest_review is None or latest_review.outcome != RemediationReviewOutcome.APPROVED:
                raise ValueError("review-approved remediation requires an approved review receipt")

        if self.state == RemediationState.CANCELLED:
''',
    label="review state validation",
)
models = replace_once(
    models,
    '''        if self.state not in {
            RemediationState.READY_FOR_IMPLEMENTATION,
            RemediationState.NEEDS_REWORK,
        }:
''',
    '''        if self.state not in {
            RemediationState.READY_FOR_IMPLEMENTATION,
            RemediationState.NEEDS_REWORK,
            RemediationState.REVIEW_NEEDS_REWORK,
        }:
''',
    label="review rework verification acceptance",
)
record_review = '''

    def record_review(self, reference: RemediationReviewReference) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot record governed review")
        if self.state != RemediationState.AWAITING_REVIEW:
            raise ValueError("the remediation plan is not accepting an independent review")
        if any(item.receipt_id == reference.receipt_id for item in self.review_history):
            raise ValueError("the remediation review receipt is already recorded")
        latest_verification = self.verification_history[-1] if self.verification_history else None
        latest_retest = self.retest_history[-1] if self.retest_history else None
        if latest_verification is None or latest_retest is None:
            raise ValueError("remediation review requires fixed-verification and retest history")
        if latest_verification.fixed_revision != reference.fixed_revision:
            raise ValueError("remediation review is bound to another fixed revision")
        if latest_retest.receipt_id != reference.retest_receipt_id:
            raise ValueError("remediation review is bound to another retest receipt")
        state = (
            RemediationState.REVIEW_APPROVED
            if reference.outcome == RemediationReviewOutcome.APPROVED
            else RemediationState.REVIEW_NEEDS_REWORK
        )
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "review_history": self.review_history + (reference,),
                }
            ).model_dump()
        )
'''
models = replace_once(
    models,
    '''        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "retest_history": self.retest_history + (reference,),
                }
            ).model_dump()
        )

    def cancel(self, *, cancelled_at: datetime, reason: str) -> RemediationRecord:
''',
    '''        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "retest_history": self.retest_history + (reference,),
                }
            ).model_dump()
        )
''' + record_review + '''

    def cancel(self, *, cancelled_at: datetime, reason: str) -> RemediationRecord:
''',
    label="record remediation review method",
)
models = replace_once(
    models,
    '            RemediationState.AWAITING_REVIEW,\n        }:\n',
    '            RemediationState.AWAITING_REVIEW,\n            RemediationState.REVIEW_NEEDS_REWORK,\n            RemediationState.REVIEW_APPROVED,\n        }:\n',
    label="review cancellation terminal states",
)
models = replace_once(
    models,
    '''                    RemediationState.RETEST_NEEDS_REWORK,
                }
''',
    '''                    RemediationState.RETEST_NEEDS_REWORK,
                    RemediationState.REVIEW_NEEDS_REWORK,
                }
''',
    label="finding in-remediation review state",
)
models = replace_once(
    models,
    '''        if self.status == FindingStatus.REMEDIATED:
            if not self.retests or self.retests[-1].outcome != "passed":
                raise ValueError("remediated findings require a passed legacy retest")
''',
    '''        if self.status == FindingStatus.READY_FOR_REPORT:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.REVIEW_APPROVED
            ):
                raise ValueError("report-ready findings require approved remediation review")
        if self.status == FindingStatus.REMEDIATED:
            if not self.retests or self.retests[-1].outcome != "passed":
                raise ValueError("remediated findings require a passed legacy retest")
''',
    label="finding report-ready validation",
)
models = replace_once(
    models,
    '''            if tuple(self.remediation.retest_history) != self.retest_results:
                raise ValueError("finding and remediation retest histories must match")
''',
    '''            if tuple(self.remediation.retest_history) != self.retest_results:
                raise ValueError("finding and remediation retest histories must match")
''',
    label="finding remediation history anchor",
)
models = replace_once(
    models,
    '''            if (
                new_remediation.retest_history[: len(old_remediation.retest_history)]
                != old_remediation.retest_history
            ):
                raise ValueError("remediation retest history is append-only")
''',
    '''            if (
                new_remediation.retest_history[: len(old_remediation.retest_history)]
                != old_remediation.retest_history
            ):
                raise ValueError("remediation retest history is append-only")
            if (
                new_remediation.review_history[: len(old_remediation.review_history)]
                != old_remediation.review_history
            ):
                raise ValueError("remediation review history is append-only")
''',
    label="append-only remediation reviews",
)
models_path.write_text(models, encoding="utf-8")


service_path = Path("vulnhunter/findings/service.py")
service = service_path.read_text(encoding="utf-8")
service = replace_once(
    service,
    '    RemediationRecord,\n    RemediationState,\n',
    '    RemediationRecord,\n    RemediationReviewOutcome,\n    RemediationReviewReference,\n    RemediationState,\n',
    label="review service imports",
)
service = replace_once(
    service,
    '            not in {RemediationState.READY_FOR_IMPLEMENTATION, RemediationState.NEEDS_REWORK}\n',
    '            not in {\n                RemediationState.READY_FOR_IMPLEMENTATION,\n                RemediationState.NEEDS_REWORK,\n                RemediationState.REVIEW_NEEDS_REWORK,\n            }\n',
    label="fix verification after review rework",
)
review_transition = '''

    def record_remediation_review(
        self,
        finding_id: str,
        *,
        review: RemediationReviewReference,
        evidence: EvidenceReference,
        expected_revision: int,
        now: datetime | None = None,
    ) -> Finding:
        """Atomically append one signed independent review without closing the finding."""

        finding = self.store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        remediation = finding.remediation
        if (
            finding.status != FindingStatus.AWAITING_REMEDIATION_REVIEW
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.AWAITING_REVIEW
        ):
            raise FindingLifecycleError(
                "independent remediation review requires a passed governed retest"
            )
        if any(item.evidence_id == review.receipt_id for item in finding.evidence):
            raise FindingLifecycleError("the remediation review receipt is already linked")
        if evidence.evidence_id != review.receipt_id or evidence.sha256 != review.sha256:
            raise FindingLifecycleError("review evidence must match the immutable signed receipt")

        recorded_at = (now or datetime.now(UTC)).astimezone(UTC)
        if recorded_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "review timestamp cannot predate the current finding revision"
            )
        if review.created_at.astimezone(UTC) != recorded_at:
            raise FindingLifecycleError(
                "review reference and finding transition must share one timestamp"
            )
        updated_remediation = remediation.record_review(review)
        status = (
            FindingStatus.READY_FOR_REPORT
            if review.outcome == RemediationReviewOutcome.APPROVED
            else FindingStatus.IN_REMEDIATION
        )
        updated = Finding.model_validate(
            finding.model_copy(
                update={
                    "status": status,
                    "remediation": updated_remediation,
                    "evidence": finding.evidence + (evidence,),
                    "revision": finding.revision + 1,
                    "updated_at": recorded_at,
                }
            ).model_dump()
        )
        self.store.save(updated, expected_revision=expected_revision)
        return updated
'''
service = replace_once(
    service,
    '\n    def cancel_remediation(\n',
    review_transition + '\n    def cancel_remediation(\n',
    label="review transition method",
)
service_path.write_text(service, encoding="utf-8")


init_path = Path("vulnhunter/findings/__init__.py")
init = init_path.read_text(encoding="utf-8")
init = replace_once(
    init,
    '    RemediationRecord,\n    RemediationState,\n',
    '    RemediationRecord,\n    RemediationReviewChecklist,\n    RemediationReviewOutcome,\n    RemediationReviewPlanRecord,\n    RemediationReviewReference,\n    RemediationState,\n',
    label="review model exports imports",
)
init = replace_once(
    init,
    'from vulnhunter.findings.retest import (\n',
    'from vulnhunter.findings.remediation_review import (\n    RemediationReviewBundle,\n    RemediationReviewError,\n    RemediationReviewReceiptStore,\n    RemediationReviewService,\n)\nfrom vulnhunter.findings.retest import (\n',
    label="review service export imports",
)
init = replace_once(
    init,
    '    "RemediationRecord",\n    "RemediationState",\n',
    '    "RemediationRecord",\n    "RemediationReviewBundle",\n    "RemediationReviewChecklist",\n    "RemediationReviewError",\n    "RemediationReviewOutcome",\n    "RemediationReviewPlanRecord",\n    "RemediationReviewReceiptStore",\n    "RemediationReviewReference",\n    "RemediationReviewService",\n    "RemediationState",\n',
    label="review public exports",
)
init_path.write_text(init, encoding="utf-8")


graph_path = Path("vulnhunter/assessment_graph/remediation.py")
graph = graph_path.read_text(encoding="utf-8")
graph = replace_once(
    graph,
    '_RETEST_PREFIX = "Governed retest result: "\n',
    '_RETEST_PREFIX = "Governed retest result: "\n_REVIEW_PREFIX = "Independent remediation review: "\n',
    label="review graph marker",
)
graph = replace_once(
    graph,
    '''                if stage
                in {
                    AssessmentStage.EXECUTION,
                    AssessmentStage.EVIDENCE,
                    AssessmentStage.VERIFICATION,
                }
                else 1
''',
    '''                if stage
                in {
                    AssessmentStage.EXECUTION,
                    AssessmentStage.EVIDENCE,
                    AssessmentStage.VERIFICATION,
                    AssessmentStage.REVIEW,
                }
                else 1
''',
    label="review graph attempts",
)
graph = replace_once(
    graph,
    '''            "retest_needs_rework",
            "awaiting_review",
        }:
''',
    '''            "retest_needs_rework",
            "awaiting_review",
            "review_needs_rework",
            "review_approved",
        }:
''',
    label="review graph states",
)
graph = replace_once(
    graph,
    '''        if normalized == "passed":
            if review.status == NodeStatus.READY:
                return True
            if review.status != NodeStatus.PENDING:
                raise AssessmentGraphError("terminal remediation review cannot be reopened")
            self.core._transition(
                graph,
                node_id=review.node_id,
                status=NodeStatus.READY,
                last_error=None,
            )
            return True
''',
    '''        if normalized == "passed":
            if review.status == NodeStatus.READY:
                if str(review.last_error or "").startswith(_REVIEW_PREFIX):
                    graph = self.core._transition(
                        graph,
                        node_id=review.node_id,
                        status=NodeStatus.RUNNING,
                        last_error=None,
                    )
                    review = self.core._stage_node(graph, AssessmentStage.REVIEW)
                    self.core._transition(
                        graph,
                        node_id=review.node_id,
                        status=NodeStatus.READY,
                        last_error=None,
                    )
                return True
            if review.status != NodeStatus.PENDING:
                raise AssessmentGraphError("terminal remediation review cannot be reopened")
            self.core._transition(
                graph,
                node_id=review.node_id,
                status=NodeStatus.READY,
                last_error=None,
            )
            return True
''',
    label="clear prior review rework",
)
review_projection = '''

    def project_review_decision(
        self,
        remediation_id: str,
        *,
        receipt_id: str,
        outcome: str,
        reason: str | None = None,
    ) -> bool:
        """Project one signed human review while keeping report generation separate."""

        graph = self.core._load_optional(remediation_id)
        if graph is None:
            return False
        normalized = outcome.strip().casefold()
        review = self.core._stage_node(graph, AssessmentStage.REVIEW)
        report = self.core._stage_node(graph, AssessmentStage.REPORT)
        marker = f"{_REVIEW_PREFIX}{normalized}; receipt={receipt_id}"
        if normalized == "approved":
            if review.status == NodeStatus.COMPLETED and review.last_error == marker:
                return True
            if review.status != NodeStatus.READY:
                raise AssessmentGraphError("remediation review is not ready for approval")
            graph = self.core._transition(
                graph,
                node_id=review.node_id,
                status=NodeStatus.RUNNING,
                last_error=None,
            )
            review = self.core._stage_node(graph, AssessmentStage.REVIEW)
            graph = self.core._transition(
                graph,
                node_id=review.node_id,
                status=NodeStatus.COMPLETED,
                last_error=marker,
            )
            report = self.core._stage_node(graph, AssessmentStage.REPORT)
            if report.status == NodeStatus.PENDING:
                self.core._transition(
                    graph,
                    node_id=report.node_id,
                    status=NodeStatus.READY,
                    last_error=None,
                )
            return True
        if review.status == NodeStatus.READY and review.last_error == marker:
            return True
        if review.status != NodeStatus.READY:
            raise AssessmentGraphError("remediation review is not accepting another decision")
        graph = self.core._transition(
            graph,
            node_id=review.node_id,
            status=NodeStatus.RUNNING,
            last_error=None,
        )
        review = self.core._stage_node(graph, AssessmentStage.REVIEW)
        self.core._transition(
            graph,
            node_id=review.node_id,
            status=NodeStatus.READY,
            last_error=marker if reason is None else f"{marker}; reason={reason[:1_000]}",
        )
        if report.status != NodeStatus.PENDING:
            raise AssessmentGraphError("report stage changed before review approval")
        return True
'''
graph = replace_once(
    graph,
    '\n    def _complete_attempt_stage(\n',
    review_projection + '\n    def _complete_attempt_stage(\n',
    label="review graph projection method",
)
graph = replace_once(
    graph,
    '''        review = str(review_node.get("status")) if isinstance(review_node, dict) else None
        review_error = (
''',
    '''        review = str(review_node.get("status")) if isinstance(review_node, dict) else None
        report_node = by_stage.get(AssessmentStage.REPORT.value)
        report = str(report_node.get("status")) if isinstance(report_node, dict) else None
        review_error = (
''',
    label="report status payload",
)
graph = replace_once(
    graph,
    '''        if review == NodeStatus.READY.value:
            payload["chat_stage"] = "retest_passed_awaiting_independent_review"
            payload["report_state"] = "blocked_pending_independent_review"
''',
    '''        if review == NodeStatus.COMPLETED.value and report == NodeStatus.READY.value:
            payload["chat_stage"] = "remediation_review_approved_ready_for_report"
            payload["report_state"] = "ready_for_generation"
        elif review == NodeStatus.READY.value and review_error.startswith(_REVIEW_PREFIX):
            if "changes_requested" in review_error:
                payload["chat_stage"] = "remediation_review_requires_rework"
                payload["report_state"] = "blocked_review_rework"
            elif "cannot_verify" in review_error:
                payload["chat_stage"] = "remediation_review_cannot_verify"
                payload["report_state"] = "blocked_review_uncertain"
            else:
                payload["chat_stage"] = "remediation_review_blocked"
                payload["report_state"] = "blocked_review_unavailable"
        elif review == NodeStatus.READY.value:
            payload["chat_stage"] = "retest_passed_awaiting_independent_review"
            payload["report_state"] = "blocked_pending_independent_review"
''',
    label="review graph chat states",
)
graph = replace_once(
    graph,
    '''        elif normalized == "awaiting_review":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
            ):
                statuses[stage] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REVIEW] = NodeStatus.READY
''',
    '''        elif normalized == "awaiting_review":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
            ):
                statuses[stage] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REVIEW] = NodeStatus.READY
        elif normalized == "review_needs_rework":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
            ):
                statuses[stage] = NodeStatus.READY
        elif normalized == "review_approved":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
            ):
                statuses[stage] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REPORT] = NodeStatus.READY
''',
    label="initial review states",
)
graph_path.write_text(graph, encoding="utf-8")


web_graph_path = Path("vulnhunter/web/remediation_assessment_graph.py")
web_graph = web_graph_path.read_text(encoding="utf-8")
web_graph = replace_once(
    web_graph,
    '''    if remediation.retest_history:
        latest_retest = remediation.retest_history[-1]
        service.project_retest_outcome(
            remediation.remediation_id,
            receipt_id=latest_retest.receipt_id,
            outcome=latest_retest.outcome.value,
        )
    return service.status_payload(remediation.remediation_id)
''',
    '''    if remediation.retest_history:
        latest_retest = remediation.retest_history[-1]
        service.project_retest_outcome(
            remediation.remediation_id,
            receipt_id=latest_retest.receipt_id,
            outcome=latest_retest.outcome.value,
        )
    if remediation.review_history:
        latest_review = remediation.review_history[-1]
        service.project_review_decision(
            remediation.remediation_id,
            receipt_id=latest_review.receipt_id,
            outcome=latest_review.outcome.value,
        )
    return service.status_payload(remediation.remediation_id)
''',
    label="web review graph projection",
)
web_graph_path.write_text(web_graph, encoding="utf-8")
