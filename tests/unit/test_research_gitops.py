"""Tests for isolated Git worktrees and guarded promotion."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulnhunter.exceptions import ResearchGitError
from vulnhunter.research.gitops import (
    candidate_commit,
    changed_files,
    current_commit,
    prepare_worktree,
    promote_candidate,
    remove_worktree,
)


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
    (root / "candidate.py").write_text("VALUE = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    return root


def test_prepare_and_remove_isolated_worktree(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    baseline = current_commit(root)
    worktree, branch = prepare_worktree(
        root,
        experiment_id="exp-test-1234",
        baseline_commit=baseline,
        worktree_root=tmp_path / "worktrees",
    )

    assert worktree.is_dir()
    assert current_commit(worktree) == baseline

    remove_worktree(root, worktree, branch, force=True)

    assert not worktree.exists()


def test_candidate_requires_exactly_one_clean_commit(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    baseline = current_commit(root)
    worktree, branch = prepare_worktree(
        root,
        experiment_id="exp-test-5678",
        baseline_commit=baseline,
        worktree_root=tmp_path / "worktrees",
    )
    (worktree / "candidate.py").write_text("VALUE = 2\n")

    with pytest.raises(ResearchGitError, match="Commit the bounded candidate"):
        candidate_commit(worktree, baseline_commit=baseline)

    _git(worktree, "add", "candidate.py")
    _git(worktree, "commit", "-m", "candidate")
    commit, _ = candidate_commit(worktree, baseline_commit=baseline)

    assert changed_files(
        worktree,
        baseline_commit=baseline,
        candidate=commit,
    ) == ("candidate.py",)
    remove_worktree(root, worktree, branch, force=True)


def test_promote_cherry_picks_accepted_candidate(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    baseline = current_commit(root)
    worktree, branch = prepare_worktree(
        root,
        experiment_id="exp-test-9012",
        baseline_commit=baseline,
        worktree_root=tmp_path / "worktrees",
    )
    (worktree / "candidate.py").write_text("VALUE = 3\n")
    _git(worktree, "add", "candidate.py")
    _git(worktree, "commit", "-m", "candidate")
    candidate, _ = candidate_commit(worktree, baseline_commit=baseline)

    promoted = promote_candidate(
        root,
        baseline_commit=baseline,
        candidate=candidate,
    )

    assert promoted != baseline
    assert (root / "candidate.py").read_text() == "VALUE = 3\n"
    remove_worktree(root, worktree, branch, force=True)
