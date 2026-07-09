"""Tests for reproducible, read-only holdout diagnostics."""

from __future__ import annotations

import pytest

from tests.unit.test_model_selection import make_examples
from vulnhunter.exceptions import ModelArtifactError
from vulnhunter.ml import diagnose_holdout, train_tuned


def test_diagnostics_reproduce_artifact_metrics_and_slices() -> None:
    examples = make_examples()
    artifact = train_tuned(examples)

    report = diagnose_holdout(examples, artifact)

    assert report.metrics == artifact.evaluation
    assert report.false_negatives == ()
    assert report.false_positives == ()
    assert {item.key for item in report.by_scan} == {
        str(scan_id) for scan_id in artifact.holdout_scan_ids
    }
    assert {item.key for item in report.by_category}


def test_diagnostics_reject_changed_dataset() -> None:
    examples = make_examples()
    artifact = train_tuned(examples)
    changed = list(examples)
    changed[0] = changed[0].model_copy(update={"title": "Changed after training"})

    with pytest.raises(ModelArtifactError, match="no longer matches"):
        diagnose_holdout(tuple(changed), artifact)


def test_diagnostics_do_not_mutate_examples() -> None:
    examples = make_examples()
    artifact = train_tuned(examples)
    before = tuple(item.model_dump() for item in examples)

    diagnose_holdout(examples, artifact)

    assert tuple(item.model_dump() for item in examples) == before
