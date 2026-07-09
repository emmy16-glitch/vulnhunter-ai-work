#!/usr/bin/env python3
"""Generate a local repository and architecture audit for VulnHunter AI."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED_INTELLIGENCE_FILES = (
    "AGENTS.md",
    "docs/intelligence/README.md",
    "docs/intelligence/CURRENT_STATE.md",
    "docs/intelligence/PRODUCT_DEFINITION.md",
    "docs/intelligence/SYSTEM_ARCHITECTURE.md",
    "docs/intelligence/SECURITY_BOUNDARIES.md",
    "docs/intelligence/TARGET_AUTHORIZATION.md",
    "docs/intelligence/DATA_AND_REVIEW.md",
    "docs/intelligence/INDEPENDENT_REVIEW.md",
    "docs/intelligence/ML_GOVERNANCE.md",
    "docs/intelligence/TESTING_STRATEGY.md",
    "docs/intelligence/KNOWN_FAILURES.md",
    "docs/intelligence/EXPERIMENT_LOG.md",
    "docs/intelligence/ROADMAP.md",
    "docs/intelligence/TECHNICAL_DEBT.md",
    "docs/intelligence/ORCHESTRATION_LOOP.md",
    "docs/intelligence/AUTORESEARCH_ENGINE.md",
    "docs/intelligence/UNATTENDED_OPERATIONS.md",
    "docs/intelligence/CONNECTION_PINNING.md",
    "docs/intelligence/GOVERNED_COLLECTION_AND_REVIEW.md",
    "docs/adr/0013-governed-collection-and-authenticated-review.md",
    "docs/adr/0012-connection-bound-dns-scope-enforcement.md",
    ".github/workflows/quality.yml",
    "docs/adr/README.md",
)

EXPECTED_PACKAGES = (
    "scope",
    "authorization",
    "security",
    "scanner",
    "mapping",
    "observations",
    "review",
    "governance",
    "orchestration",
    "research",
    "unattended",
    "ml",
    "benchmark",
)

IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "artifacts",
}


@dataclass(frozen=True)
class AuditResult:
    generated_at: str
    repository_root: str
    git_commit: str
    git_branch: str
    working_tree_clean: bool
    python_file_count: int
    test_file_count: int
    markdown_file_count: int
    package_presence: dict[str, bool]
    required_intelligence_presence: dict[str, bool]
    tracked_sensitive_name_hits: tuple[str, ...]
    tracked_generated_artifact_hits: tuple[str, ...]
    largest_tracked_files: tuple[dict[str, Any], ...]
    repository_tree_sha256: str
    warnings: tuple[str, ...]


def run_git(root: Path, *arguments: str) -> str:
    """Run Git and return stripped text output."""
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def repository_root(start: Path) -> Path:
    """Resolve the Git repository root."""
    try:
        value = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Run the audit inside the VulnHunter Git repository.") from exc

    return Path(value).resolve()


def tracked_files(root: Path) -> tuple[Path, ...]:
    """Return tracked regular files."""
    output = run_git(root, "ls-files", "-z")
    paths: list[Path] = []

    for item in output.split("\0"):
        if not item:
            continue
        path = root / item
        if path.is_file():
            paths.append(path)

    return tuple(sorted(paths))


def tree_hash(root: Path, files: tuple[Path, ...]) -> str:
    """Hash tracked paths and contents deterministically."""
    digest = hashlib.sha256()

    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())

    return digest.hexdigest()


def audit(root: Path) -> AuditResult:
    """Build the project audit result."""
    files = tracked_files(root)
    relative_names = tuple(path.relative_to(root).as_posix() for path in files)

    python_files = tuple(name for name in relative_names if name.endswith(".py"))
    test_files = tuple(
        name for name in relative_names if name.startswith("tests/") and name.endswith(".py")
    )
    markdown_files = tuple(name for name in relative_names if name.endswith(".md"))

    package_presence = {
        package: (root / "vulnhunter" / package / "__init__.py").is_file()
        for package in EXPECTED_PACKAGES
    }

    required_presence = {path: (root / path).is_file() for path in REQUIRED_INTELLIGENCE_FILES}

    sensitive_fragments = (
        ".env",
        "credential",
        "credentials",
        "secret",
        "private_key",
        "id_rsa",
        "token.txt",
    )
    sensitive_hits = tuple(
        name
        for name in relative_names
        if any(fragment in name.lower() for fragment in sensitive_fragments)
    )

    generated_suffixes = (".db", ".sqlite", ".sqlite3", ".joblib", ".pkl")
    generated_hits = tuple(
        name
        for name in relative_names
        if name.endswith(generated_suffixes) or name.startswith("artifacts/")
    )

    sized = sorted(
        (
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
            }
            for path in files
        ),
        key=lambda item: int(item["bytes"]),
        reverse=True,
    )

    status = run_git(root, "status", "--porcelain")
    commit = run_git(root, "rev-parse", "HEAD")
    branch = run_git(root, "branch", "--show-current") or "(detached)"

    warnings: list[str] = []

    missing_packages = [name for name, present in package_presence.items() if not present]
    if missing_packages:
        warnings.append("Missing expected packages: " + ", ".join(missing_packages))

    missing_intelligence = [name for name, present in required_presence.items() if not present]
    if missing_intelligence:
        warnings.append("Missing intelligence files: " + ", ".join(missing_intelligence))

    if sensitive_hits:
        warnings.append("Review tracked sensitive-looking filenames.")

    if generated_hits:
        warnings.append("Generated databases/models/artifacts appear to be tracked.")

    if status:
        warnings.append("Working tree is not clean.")

    return AuditResult(
        generated_at=datetime.now(UTC).isoformat(),
        repository_root=str(root),
        git_commit=commit,
        git_branch=branch,
        working_tree_clean=not bool(status),
        python_file_count=len(python_files),
        test_file_count=len(test_files),
        markdown_file_count=len(markdown_files),
        package_presence=package_presence,
        required_intelligence_presence=required_presence,
        tracked_sensitive_name_hits=sensitive_hits,
        tracked_generated_artifact_hits=generated_hits,
        largest_tracked_files=tuple(sized[:15]),
        repository_tree_sha256=tree_hash(root, files),
        warnings=tuple(warnings),
    )


def render_markdown(result: AuditResult) -> str:
    """Render an audit as Markdown."""
    clean = "yes" if result.working_tree_clean else "no"
    lines = [
        "# VulnHunter Repository Audit",
        "",
        f"- Generated: `{result.generated_at}`",
        f"- Branch: `{result.git_branch}`",
        f"- Commit: `{result.git_commit}`",
        f"- Working tree clean: `{clean}`",
        f"- Tracked-tree SHA-256: `{result.repository_tree_sha256}`",
        "",
        "## Inventory",
        "",
        f"- Python files: `{result.python_file_count}`",
        f"- Test files: `{result.test_file_count}`",
        f"- Markdown files: `{result.markdown_file_count}`",
        "",
        "## Expected packages",
        "",
    ]

    for name, present in result.package_presence.items():
        lines.append(f"- [{'x' if present else ' '}] `{name}`")

    lines.extend(["", "## Project intelligence files", ""])

    for name, present in result.required_intelligence_presence.items():
        lines.append(f"- [{'x' if present else ' '}] `{name}`")

    lines.extend(["", "## Sensitive/generated-file checks", ""])

    if result.tracked_sensitive_name_hits:
        lines.append("- Sensitive-looking tracked paths:")
        lines.extend(f"  - `{name}`" for name in result.tracked_sensitive_name_hits)
    else:
        lines.append("- No sensitive-looking tracked filenames detected.")

    if result.tracked_generated_artifact_hits:
        lines.append("- Generated artifact paths appear tracked:")
        lines.extend(f"  - `{name}`" for name in result.tracked_generated_artifact_hits)
    else:
        lines.append("- No tracked database/model artifact paths detected.")

    lines.extend(["", "## Largest tracked files", ""])
    for item in result.largest_tracked_files:
        lines.append(f"- `{item['path']}` — `{item['bytes']}` bytes")

    lines.extend(["", "## Warnings", ""])
    if result.warnings:
        lines.extend(f"- {warning}" for warning in result.warnings)
    else:
        lines.append("- None.")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/project-audit"),
        help="Directory for audit.json and AUDIT.md.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when warnings exist.",
    )
    arguments = parser.parse_args()

    root = repository_root(Path.cwd())
    result = audit(root)

    output = arguments.output
    if not output.is_absolute():
        output = root / output
    output.mkdir(parents=True, exist_ok=True)

    json_path = output / "audit.json"
    markdown_path = output / "AUDIT.md"

    json_path.write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")

    print(f"Audit JSON: {json_path}")
    print(f"Audit report: {markdown_path}")
    print(f"Warnings: {len(result.warnings)}")

    if arguments.strict and result.warnings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
