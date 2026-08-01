from pathlib import Path

path = Path("vulnhunter/findings/models.py")
text = path.read_text(encoding="utf-8")
old = '''        elif self.state == RemediationState.READY_FOR_RETEST:
            if latest_verification is None or latest_verification.verdict != "fixed":
                raise ValueError("ready-for-retest plans require a fixed verification receipt")
            if latest_retest is not None and latest_retest.outcome != RetestOutcome.CANCELLED:
                raise ValueError("ready-for-retest allows only a cancelled prior retest")
        elif self.state == RemediationState.RETEST_NEEDS_REWORK:
            if latest_retest is None or latest_retest.outcome not in {
                RetestOutcome.FAILED,
                RetestOutcome.PARTIAL,
                RetestOutcome.CANNOT_VERIFY,
                RetestOutcome.BLOCKED,
            }:
                raise ValueError("retest-needs-rework requires a non-passing retest receipt")
        elif self.state == RemediationState.AWAITING_REVIEW:
            if latest_retest is None or latest_retest.outcome != RetestOutcome.PASSED:
                raise ValueError("awaiting-review remediation requires a passed retest receipt")
            if (
                latest_review is not None
                and latest_review.outcome == RemediationReviewOutcome.APPROVED
            ):
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
'''
new = '''        elif self.state == RemediationState.READY_FOR_RETEST:
            if latest_verification is None or latest_verification.verdict != "fixed":
                raise ValueError("ready-for-retest plans require a fixed verification receipt")
            if (
                latest_retest is not None
                and latest_retest.fixed_revision == latest_verification.fixed_revision
                and latest_retest.outcome != RetestOutcome.CANCELLED
            ):
                raise ValueError(
                    "ready-for-retest requires no completed retest for the latest fixed revision"
                )
        elif self.state == RemediationState.RETEST_NEEDS_REWORK:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_retest.fixed_revision != latest_verification.fixed_revision
                or latest_retest.outcome
                not in {
                    RetestOutcome.FAILED,
                    RetestOutcome.PARTIAL,
                    RetestOutcome.CANNOT_VERIFY,
                    RetestOutcome.BLOCKED,
                }
            ):
                raise ValueError(
                    "retest-needs-rework requires a non-passing retest of the latest fixed revision"
                )
        elif self.state == RemediationState.AWAITING_REVIEW:
            if (
                latest_verification is None
                or latest_verification.verdict != "fixed"
                or latest_retest is None
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_retest.fixed_revision != latest_verification.fixed_revision
            ):
                raise ValueError(
                    "awaiting-review remediation requires a passed retest of the latest fixed revision"
                )
            if (
                latest_review is not None
                and latest_review.retest_receipt_id == latest_retest.receipt_id
            ):
                raise ValueError(
                    "a reviewed retest cannot remain in the awaiting-review state"
                )
        elif self.state == RemediationState.REVIEW_NEEDS_REWORK:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_review is None
                or latest_review.outcome
                not in {
                    RemediationReviewOutcome.CHANGES_REQUESTED,
                    RemediationReviewOutcome.CANNOT_VERIFY,
                    RemediationReviewOutcome.BLOCKED,
                }
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_retest.fixed_revision != latest_verification.fixed_revision
                or latest_review.fixed_revision != latest_verification.fixed_revision
                or latest_review.retest_receipt_id != latest_retest.receipt_id
            ):
                raise ValueError(
                    "review-needs-rework requires a non-approved review of the latest passed retest"
                )
        elif self.state == RemediationState.REVIEW_APPROVED:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_review is None
                or latest_review.outcome != RemediationReviewOutcome.APPROVED
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_retest.fixed_revision != latest_verification.fixed_revision
                or latest_review.fixed_revision != latest_verification.fixed_revision
                or latest_review.retest_receipt_id != latest_retest.receipt_id
            ):
                raise ValueError(
                    "review-approved remediation requires approval of the latest passed retest"
                )
'''
if text.count(old) != 1:
    raise SystemExit(f"Expected one remediation state validation block, found {text.count(old)}")
text = text.replace(old, new)
old = '''        if latest_verification.fixed_revision != reference.fixed_revision:
            raise ValueError("remediation review is bound to another fixed revision")
        if latest_retest.receipt_id != reference.retest_receipt_id:
            raise ValueError("remediation review is bound to another retest receipt")
'''
new = '''        if latest_verification.fixed_revision != reference.fixed_revision:
            raise ValueError("remediation review is bound to another fixed revision")
        if latest_retest.fixed_revision != reference.fixed_revision:
            raise ValueError("remediation review retest is bound to another fixed revision")
        if latest_retest.receipt_id != reference.retest_receipt_id:
            raise ValueError("remediation review is bound to another retest receipt")
'''
if text.count(old) != 1:
    raise SystemExit(f"Expected one remediation review binding block, found {text.count(old)}")
path.write_text(text.replace(old, new), encoding="utf-8")
