"""Non-executable outer-loop analysis for search diversity and stagnation."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import UTC, datetime

from vulnhunter.research.models import (
    DecisionOutcome,
    ExperimentManifest,
    MetaAnalysis,
    SearchPolicy,
)

_DEFAULT_STRATEGIES = (
    "feature_engineering",
    "estimator_selection",
    "threshold_calibration",
    "data_quality",
    "error_analysis",
    "architecture",
)


def default_search_policy() -> SearchPolicy:
    """Return the conservative generation-zero search policy."""
    return SearchPolicy(
        generation=0,
        strategy_weights={name: 1.0 for name in _DEFAULT_STRATEGIES},
        maximum_same_strategy_streak=2,
        novelty_floor=0.35,
        stagnation_window=5,
    )


def hypothesis_fingerprint(text: str) -> str:
    """Create a stable semantic-light fingerprint without storing raw secrets."""
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    tokens = tuple(sorted(set(normalized.split())))
    return hashlib.sha256(" ".join(tokens).encode("utf-8")).hexdigest()


def analyze_search(
    manifests: tuple[ExperimentManifest, ...],
    *,
    current_policy: SearchPolicy | None = None,
) -> MetaAnalysis:
    """Detect repetitive search patterns without generating executable code."""
    policy = current_policy or default_search_policy()
    window = tuple(manifests[: policy.stagnation_window])
    fingerprints = [hypothesis_fingerprint(item.spec.hypothesis) for item in window]
    repeated = tuple(
        fingerprint for fingerprint, count in Counter(fingerprints).items() if count > 1
    )
    strategies = [item.spec.strategy_family for item in window]
    strategy_counts = Counter(strategies)
    overused = tuple(
        strategy
        for strategy, count in strategy_counts.items()
        if count > policy.maximum_same_strategy_streak
    )
    known = set(policy.strategy_weights)
    underused = tuple(sorted(known - set(strategies)))
    decided = [item for item in window if item.decision is not None]
    rejected = [
        item
        for item in decided
        if item.decision in {DecisionOutcome.REJECT, DecisionOutcome.INCONCLUSIVE}
    ]
    rejection_rate = len(rejected) / len(decided) if decided else 0.0
    accepted = [item for item in decided if item.decision is DecisionOutcome.ACCEPT]
    stagnation = bool(
        window
        and (repeated or overused or (len(window) >= policy.stagnation_window and not accepted))
    )

    weights = dict(policy.strategy_weights)
    for strategy in overused:
        weights[strategy] = max(0.1, weights.get(strategy, 1.0) * 0.5)
    for strategy in underused:
        weights[strategy] = weights.get(strategy, 1.0) * 1.5

    recommendations: list[str] = []
    if repeated:
        recommendations.append(
            "Avoid repeating hypotheses with the listed fingerprints until new evidence appears."
        )
    if overused:
        recommendations.append(
            "Reduce reliance on overused strategy families and require a different family next."
        )
    if underused:
        recommendations.append(
            "Prefer an underused strategy family for the next bounded hypothesis."
        )
    if rejection_rate >= 0.8 and decided:
        recommendations.append(
            "Pause candidate generation and revisit assumptions, measurements, or feature evidence."
        )
    if not recommendations:
        recommendations.append(
            "Search diversity is acceptable; continue one bounded hypothesis at a time."
        )

    proposed = policy.model_copy(
        update={
            "generation": policy.generation + 1,
            "strategy_weights": weights,
            "approved_by": None,
            "approved_at": None,
        }
    )
    return MetaAnalysis(
        created_at=datetime.now(UTC),
        source_experiment_ids=tuple(item.experiment_id for item in window),
        repeated_hypotheses=repeated,
        overused_strategies=overused,
        underused_strategies=underused,
        rejection_rate=rejection_rate,
        stagnation_detected=stagnation,
        recommendations=tuple(recommendations),
        proposed_policy=proposed,
        requires_human_approval=True,
    )
