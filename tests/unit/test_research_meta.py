"""Tests for bounded, non-executable outer-loop analysis."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.unit.test_research_models import valid_spec
from vulnhunter.research.boundaries import default_evaluator_policy, policy_sha256
from vulnhunter.research.meta import analyze_search, default_search_policy
from vulnhunter.research.models import (
    DecisionOutcome,
    ExperimentManifest,
)


def _manifest(identifier: str, strategy: str, decision: DecisionOutcome):
    now = datetime.now(UTC)
    spec = valid_spec().model_copy(
        update={
            "strategy_family": strategy,
            "hypothesis": "Repeat the same bounded feature hypothesis for diagnostics.",
        }
    )
    return ExperimentManifest(
        experiment_id=identifier,
        spec=spec,
        creator_id="creator.one",
        builder_id="builder.one",
        repository_root="/tmp/repo",
        store_root="/tmp/store",
        baseline_commit="a" * 40,
        baseline_tree="b" * 40,
        policy_sha256=policy_sha256(default_evaluator_policy()),
        protected_snapshot_sha256="c" * 64,
        created_at=now,
        updated_at=now,
        decision=decision,
    )


def test_meta_analysis_detects_repetition_and_requires_human_approval() -> None:
    manifests = tuple(
        _manifest(
            f"exp-20260709-meta{i:04d}",
            "feature_engineering",
            DecisionOutcome.REJECT,
        )
        for i in range(5)
    )

    analysis = analyze_search(manifests, current_policy=default_search_policy())

    assert analysis.stagnation_detected is True
    assert analysis.repeated_hypotheses
    assert analysis.overused_strategies == ("feature_engineering",)
    assert analysis.requires_human_approval is True
    assert analysis.proposed_policy.approved_by is None
