"""Tests for evaluator-resource access classification and snapshots."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.unit.test_research_models import valid_spec
from vulnhunter.exceptions import ResearchBoundaryError
from vulnhunter.research.boundaries import (
    build_protected_snapshot,
    classify_path,
    default_evaluator_policy,
    validate_candidate_paths,
    validate_editable_patterns,
    verify_protected_snapshot,
)
from vulnhunter.research.models import ResourceAccess


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "Test User")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "vulnhunter/ml").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "vulnhunter/ml/features.py").write_text("VALUE = 1\n")
    (root / "tests/test_guard.py").write_text("def test_guard():\n    assert True\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    return root


def test_default_policy_uses_most_restrictive_match() -> None:
    policy = default_evaluator_policy()

    assert classify_path(policy, "vulnhunter/ml/features.py") is ResourceAccess.EDITABLE
    assert classify_path(policy, "tests/test_guard.py") is ResourceAccess.READ_ONLY
    assert classify_path(policy, "nested/.env.local") is ResourceAccess.INACCESSIBLE


def test_spec_cannot_claim_evaluator_files_as_editable() -> None:
    policy = default_evaluator_policy()
    spec = valid_spec().model_copy(update={"editable_paths": ("tests/**",)})

    with pytest.raises(ResearchBoundaryError, match="read_only"):
        validate_editable_patterns(spec, policy)


def test_candidate_change_outside_spec_is_reported() -> None:
    violations = validate_candidate_paths(
        ("vulnhunter/ml/features.py", "vulnhunter/ml/training.py"),
        valid_spec(),
        default_evaluator_policy(),
    )

    assert violations == ("vulnhunter/ml/training.py: outside experiment editable paths",)


def test_protected_snapshot_detects_changed_test(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    policy = default_evaluator_policy()
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    snapshot = build_protected_snapshot(root, policy, repository_commit=commit)

    (root / "tests/test_guard.py").write_text("def test_guard():\n    assert False\n")

    assert verify_protected_snapshot(root, snapshot) == (
        "changed protected resource: tests/test_guard.py",
    )


def test_broad_editable_pattern_cannot_cover_protected_subtree() -> None:
    policy = default_evaluator_policy()
    spec = valid_spec().model_copy(update={"editable_paths": ("vulnhunter/**",)})

    with pytest.raises(ResearchBoundaryError, match="overlaps protected rule"):
        validate_editable_patterns(spec, policy)


def test_snapshot_rejects_tracked_inaccessible_resources(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Test User")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "candidate.py").write_text("VALUE = 1\n")
    (repository / "secrets").mkdir()
    (repository / "secrets/token.txt").write_text("do-not-expose\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "baseline")

    with pytest.raises(ResearchBoundaryError, match="must not be tracked"):
        build_protected_snapshot(
            repository,
            default_evaluator_policy(),
            repository_commit=_git(repository, "rev-parse", "HEAD"),
        )
