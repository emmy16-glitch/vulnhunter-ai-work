"""Feedback evaluation helpers using only actual reviewed records."""

from __future__ import annotations

from vulnhunter.analyst_feedback.models import AnalystFeedback, AnalystOutcome, FeedbackMetrics


def summarize_feedback(records: tuple[AnalystFeedback, ...]) -> FeedbackMetrics:
    return FeedbackMetrics(
        records=len(records),
        accepted=sum(item.outcome == AnalystOutcome.ACCEPT for item in records),
        rejected=sum(item.outcome == AnalystOutcome.REJECT for item in records),
        false_positives=sum(item.outcome == AnalystOutcome.FALSE_POSITIVE for item in records),
        oracle_agreements=sum(item.outcome == AnalystOutcome.ORACLE_AGREEMENT for item in records),
        oracle_disagreements=sum(
            item.outcome == AnalystOutcome.ORACLE_DISAGREEMENT for item in records
        ),
        retest_passed=sum(item.outcome == AnalystOutcome.RETEST_PASSED for item in records),
        retest_failed=sum(item.outcome == AnalystOutcome.RETEST_FAILED for item in records),
    )
