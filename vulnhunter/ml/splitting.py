"""Leakage-resistant dataset splitting by complete scan groups."""

from __future__ import annotations

import itertools
import random
from collections import Counter, defaultdict

from vulnhunter.exceptions import InsufficientTrainingDataError
from vulnhunter.ml.models import TrainingExample, TrainingLabel


def _has_both_labels(examples: list[TrainingExample]) -> bool:
    return {example.label for example in examples} == {
        "confirmed",
        "false_positive",
    }


def _candidate_subsets(
    scan_ids: tuple[int, ...],
    *,
    random_seed: int,
    maximum_random_candidates: int = 5_000,
):
    """Yield deterministic holdout scan subsets without unbounded enumeration."""
    if len(scan_ids) <= 14:
        for size in range(1, len(scan_ids)):
            yield from itertools.combinations(scan_ids, size)
        return

    rng = random.Random(random_seed)
    seen: set[tuple[int, ...]] = set()

    for scan_id in scan_ids:
        candidate = (scan_id,)
        seen.add(candidate)
        yield candidate

    for offset in range(8):
        shuffled = list(scan_ids)
        random.Random(random_seed + offset).shuffle(shuffled)
        for size in range(1, len(shuffled)):
            candidate = tuple(sorted(shuffled[:size]))
            if candidate in seen:
                continue
            seen.add(candidate)
            yield candidate

    for _ in range(maximum_random_candidates):
        size = rng.randint(1, len(scan_ids) - 1)
        candidate = tuple(sorted(rng.sample(scan_ids, size)))
        if candidate in seen:
            continue
        seen.add(candidate)
        yield candidate


def split_by_scan_groups(
    examples: tuple[TrainingExample, ...],
    *,
    test_fraction: float,
    random_seed: int,
) -> tuple[tuple[TrainingExample, ...], tuple[TrainingExample, ...]]:
    """Split entire scans while retaining both classes in both partitions."""
    if test_fraction <= 0 or test_fraction >= 0.5:
        raise ValueError("test_fraction must be greater than 0 and less than 0.5.")

    grouped: dict[int, list[TrainingExample]] = defaultdict(list)
    for example in examples:
        grouped[example.scan_id].append(example)

    scan_ids = tuple(sorted(grouped))
    if len(scan_ids) < 2:
        raise InsufficientTrainingDataError(
            "At least two distinct scan groups are required for leakage-safe evaluation."
        )

    total_counts: Counter[TrainingLabel] = Counter(example.label for example in examples)
    target_total = len(examples) * test_fraction
    target_confirmed = total_counts["confirmed"] * test_fraction
    target_false_positive = total_counts["false_positive"] * test_fraction

    best: tuple[tuple[float, float, int, tuple[int, ...]], tuple[int, ...]] | None = None

    for candidate in _candidate_subsets(scan_ids, random_seed=random_seed):
        holdout_ids = set(candidate)
        holdout = [example for example in examples if example.scan_id in holdout_ids]
        train = [example for example in examples if example.scan_id not in holdout_ids]

        if not train or not holdout:
            continue

        if not _has_both_labels(train) or not _has_both_labels(holdout):
            continue

        holdout_counts: Counter[TrainingLabel] = Counter(example.label for example in holdout)
        size_error = abs(len(holdout) - target_total) / max(1, len(examples))
        class_error = abs(holdout_counts["confirmed"] - target_confirmed) / max(
            1, total_counts["confirmed"]
        ) + abs(holdout_counts["false_positive"] - target_false_positive) / max(
            1, total_counts["false_positive"]
        )
        score = (
            size_error + class_error,
            class_error,
            size_error,
            len(candidate),
            candidate,
        )

        if best is None or score < best[0]:
            best = (score, candidate)

    if best is None:
        raise InsufficientTrainingDataError(
            "No leakage-safe scan-group split can keep both labels in training and "
            "holdout data. Collect reviewed examples across more independent scans."
        )

    holdout_scan_ids = set(best[1])
    train_examples = tuple(
        sorted(
            (example for example in examples if example.scan_id not in holdout_scan_ids),
            key=lambda item: item.observation_id,
        )
    )
    holdout_examples = tuple(
        sorted(
            (example for example in examples if example.scan_id in holdout_scan_ids),
            key=lambda item: item.observation_id,
        )
    )
    return train_examples, holdout_examples
