"""Shell-free transactional Git operations for isolated experiments."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from vulnhunter.exceptions import ResearchGitError


def repository_root(start: Path) -> Path:
    """Resolve the governing Git repository root."""
    return Path(_git_text(start, "rev-parse", "--show-toplevel")).resolve()


def current_commit(repository: Path) -> str:
    """Return the checked-out commit."""
    return _git_text(repository, "rev-parse", "HEAD")


def current_tree(repository: Path) -> str:
    """Return the checked-out tree object."""
    return _git_text(repository, "rev-parse", "HEAD^{tree}")


def working_tree_is_clean(repository: Path) -> bool:
    """Return whether tracked and untracked changes are absent."""
    return not bool(_git_text(repository, "status", "--porcelain"))


def prepare_worktree(
    repository: Path,
    *,
    experiment_id: str,
    baseline_commit: str,
    worktree_root: Path,
) -> tuple[Path, str]:
    """Create a dedicated branch and worktree from the exact baseline commit."""
    root = repository_root(repository)
    destination = (worktree_root.expanduser().resolve() / experiment_id).resolve()
    branch = f"vulnhunter-exp/{experiment_id}"

    if destination.exists():
        raise ResearchGitError(f"Experiment worktree already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    _git(root, "worktree", "add", "-b", branch, str(destination), baseline_commit)
    try:
        if current_commit(destination) != baseline_commit:
            raise ResearchGitError("The experiment worktree did not start at the baseline.")
        if not working_tree_is_clean(destination):
            raise ResearchGitError("The new experiment worktree is unexpectedly dirty.")
    except Exception:
        remove_worktree(root, destination, branch, force=True)
        raise
    return destination, branch


def candidate_commit(
    worktree: Path,
    *,
    baseline_commit: str,
) -> tuple[str, str]:
    """Validate one clean candidate commit directly above the baseline."""
    root = repository_root(worktree)
    if not working_tree_is_clean(root):
        raise ResearchGitError(
            "Commit the bounded candidate in the experiment worktree before evaluation."
        )

    count_text = _git_text(root, "rev-list", "--count", f"{baseline_commit}..HEAD")
    if int(count_text) != 1:
        raise ResearchGitError(
            "Each experiment must contain exactly one candidate commit above the baseline."
        )
    parent = _git_text(root, "rev-parse", "HEAD^")
    if parent != baseline_commit:
        raise ResearchGitError("The candidate commit must be directly based on the baseline.")
    commit = current_commit(root)
    tree = current_tree(root)
    return commit, tree


def changed_files(
    worktree: Path,
    *,
    baseline_commit: str,
    candidate: str,
) -> tuple[str, ...]:
    """Return changed paths between baseline and candidate."""
    output = _git_text(
        worktree,
        "diff",
        "--name-only",
        "--diff-filter=ACMRDTUXB",
        f"{baseline_commit}..{candidate}",
    )
    return tuple(line for line in output.splitlines() if line)


def diff_bytes(
    worktree: Path,
    *,
    baseline_commit: str,
    candidate: str,
) -> bytes:
    """Return the binary-safe candidate patch."""
    return _git_bytes(
        worktree,
        "diff",
        "--binary",
        f"{baseline_commit}..{candidate}",
    )


def remove_worktree(
    repository: Path,
    worktree: Path,
    branch: str | None,
    *,
    force: bool = False,
) -> None:
    """Remove an isolated worktree and its experiment branch."""
    root = repository_root(repository)
    arguments = ["worktree", "remove"]
    if force:
        arguments.append("--force")
    arguments.append(str(worktree.resolve()))

    if worktree.exists():
        _git(root, *arguments)
    _git(root, "worktree", "prune")

    if branch and _branch_exists(root, branch):
        delete_flag = "-D" if force else "-d"
        _git(root, "branch", delete_flag, branch)


def promote_candidate(
    repository: Path,
    *,
    baseline_commit: str,
    candidate: str,
) -> str:
    """Cherry-pick one accepted commit or abort cleanly on any conflict."""
    root = repository_root(repository)
    if not working_tree_is_clean(root):
        raise ResearchGitError("Promotion requires a clean primary working tree.")
    if current_commit(root) != baseline_commit:
        raise ResearchGitError(
            "The primary branch moved after the experiment began; rebase through a new experiment."
        )

    try:
        _git(root, "cherry-pick", candidate)
    except ResearchGitError as exc:
        _git(root, "cherry-pick", "--abort", check=False)
        if not working_tree_is_clean(root):
            raise ResearchGitError(
                "Promotion conflicted and automatic abort did not restore a clean tree."
            ) from exc
        raise
    return current_commit(root)


def environment_fingerprint(repository: Path) -> dict[str, str]:
    """Return deterministic local-environment provenance without secrets."""
    root = repository_root(repository)
    values = {
        "git_version": _git_text(root, "--version"),
        "repository_root": str(root),
        "head": current_commit(root),
    }
    python = os.environ.get("VIRTUAL_ENV")
    values["virtual_environment_active"] = "yes" if python else "no"
    return values


def _branch_exists(repository: Path, branch: str) -> bool:
    completed = _git(
        repository,
        "show-ref",
        "--verify",
        "--quiet",
        f"refs/heads/{branch}",
        check=False,
    )
    return completed.returncode == 0


def _git_text(repository: Path, *arguments: str) -> str:
    return _git(repository, *arguments).stdout.strip()


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        message = ""
        if isinstance(exc, subprocess.CalledProcessError):
            message = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ResearchGitError(message or f"Git command failed: {' '.join(arguments)}") from exc
    return completed.stdout


def _git(
    repository: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=check,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        message = ""
        if isinstance(exc, subprocess.CalledProcessError):
            message = exc.stderr.strip()
        raise ResearchGitError(message or f"Git command failed: {' '.join(arguments)}") from exc
    return completed
