"""Immutable evaluator boundaries and protected-resource inventories."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from vulnhunter.exceptions import ResearchBoundaryError, ResearchIntegrityError
from vulnhunter.research.models import (
    EvaluatorPolicy,
    ExperimentSpec,
    PathRule,
    ProtectedFileRecord,
    ProtectedSnapshot,
    ResourceAccess,
)

_ACCESS_PRIORITY = {
    ResourceAccess.EDITABLE: 1,
    ResourceAccess.READ_ONLY: 2,
    ResourceAccess.INACCESSIBLE: 3,
}


def default_evaluator_policy() -> EvaluatorPolicy:
    """Return the built-in policy that experiment specs cannot weaken."""
    return EvaluatorPolicy(
        name="VulnHunter immutable evaluator boundary v1",
        rules=(
            PathRule(
                pattern="**",
                access=ResourceAccess.EDITABLE,
                rationale=(
                    "Unclassified tracked source is editable only when the experiment "
                    "spec also allows it."
                ),
            ),
            PathRule(
                pattern="tests/**",
                access=ResourceAccess.READ_ONLY,
                rationale=(
                    "Tests are evaluator resources and cannot be changed to make a candidate pass."
                ),
            ),
            PathRule(
                pattern="AGENTS.md",
                access=ResourceAccess.READ_ONLY,
                rationale="The permanent operating manual is outside candidate write authority.",
            ),
            PathRule(
                pattern="docs/adr/**",
                access=ResourceAccess.READ_ONLY,
                rationale=(
                    "Accepted architecture decisions cannot be weakened inside an experiment."
                ),
            ),
            PathRule(
                pattern="scripts/project_audit.py",
                access=ResourceAccess.READ_ONLY,
                rationale="The repository audit is an evaluator resource.",
            ),
            PathRule(
                pattern=".github/workflows/**",
                access=ResourceAccess.READ_ONLY,
                rationale="CI gates are evaluator policy and cannot be edited by a candidate.",
            ),
            PathRule(
                pattern="vulnhunter/scope/**",
                access=ResourceAccess.READ_ONLY,
                rationale="Laboratory scope enforcement is a security invariant.",
            ),
            PathRule(
                pattern="vulnhunter/security/**",
                access=ResourceAccess.READ_ONLY,
                rationale="Redaction and sensitive-data handling are security invariants.",
            ),
            PathRule(
                pattern="vulnhunter/authorization/**",
                access=ResourceAccess.READ_ONLY,
                rationale="Authorization rules are outside experiment control.",
            ),
            PathRule(
                pattern="vulnhunter/orchestration/**",
                access=ResourceAccess.READ_ONLY,
                rationale="The proof and human-approval harness cannot grade itself.",
            ),
            PathRule(
                pattern="vulnhunter/research/**",
                access=ResourceAccess.READ_ONLY,
                rationale=(
                    "The autoresearch engine cannot alter its own gates during an experiment."
                ),
            ),
            PathRule(
                pattern="vulnhunter/benchmark/catalog.py",
                access=ResourceAccess.READ_ONLY,
                rationale=(
                    "Controlled benchmark labels and scenario definitions are evaluator resources."
                ),
            ),
            PathRule(
                pattern="vulnhunter/benchmark/manifest.py",
                access=ResourceAccess.READ_ONLY,
                rationale="Benchmark provenance validation is an evaluator resource.",
            ),
            PathRule(
                pattern="artifacts/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale=(
                    "Local evidence, holdouts, authorizations, models, and experiment "
                    "state are not candidate inputs."
                ),
            ),
            PathRule(
                pattern=".env*",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Environment secrets are never available to candidates.",
            ),
            PathRule(
                pattern="**/.env*",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Nested environment secrets are never available to candidates.",
            ),
            PathRule(
                pattern="**/*.pem",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Private key material is inaccessible.",
            ),
            PathRule(
                pattern="**/*.key",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Private key material is inaccessible.",
            ),
            PathRule(
                pattern="secrets/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Secret stores are inaccessible.",
            ),
            PathRule(
                pattern="credentials/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Credentials are inaccessible.",
            ),
            PathRule(
                pattern="production-data/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Production and customer data are outside laboratory experiments.",
            ),
            PathRule(
                pattern="customer-data/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Production and customer data are outside laboratory experiments.",
            ),
            PathRule(
                pattern="private-targets/**",
                access=ResourceAccess.INACCESSIBLE,
                rationale="Private target inventories are outside candidate access.",
            ),
        ),
        fixed_verifiers=(
            "ruff_check",
            "compileall",
            "pytest",
            "ruff_format_check",
            "git_diff_check",
        ),
        safety_invariants=(
            "laboratory_scope_enforced",
            "authorization_required",
            "redaction_preserved",
            "human_labels_authoritative",
            "scan_group_isolation_preserved",
            "evaluator_resources_unchanged",
        ),
        protected_labels=(
            "approved human labels",
            "holdout manifests",
            "benchmark scenario expectations",
            "authorization records",
            "scope and safety policies",
            "accepted baseline results",
        ),
    )


def canonical_policy_bytes(policy: EvaluatorPolicy) -> bytes:
    """Serialize a policy deterministically for provenance."""
    payload = policy.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def policy_sha256(policy: EvaluatorPolicy) -> str:
    """Return the deterministic policy hash."""
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def classify_path(policy: EvaluatorPolicy, path: str) -> ResourceAccess:
    """Classify a path using the most restrictive matching rule."""
    normalized = _normalize_relative_path(path)
    matches = [rule.access for rule in policy.rules if _matches(normalized, rule.pattern)]
    if not matches:
        raise ResearchBoundaryError(f"No evaluator boundary rule classifies {normalized}.")
    return max(matches, key=_ACCESS_PRIORITY.__getitem__)


def validate_editable_patterns(
    spec: ExperimentSpec,
    policy: EvaluatorPolicy,
) -> None:
    """Reject specs that attempt to declare protected paths editable."""
    for pattern in spec.editable_paths:
        representative = _representative_path(pattern)
        access = classify_path(policy, representative)
        if access is not ResourceAccess.EDITABLE:
            raise ResearchBoundaryError(
                f"Editable pattern {pattern!r} intersects a {access.value} resource boundary."
            )
        for rule in policy.rules:
            if rule.access is ResourceAccess.EDITABLE:
                continue
            protected_example = _representative_path(rule.pattern)
            if _matches(protected_example, pattern) or _matches(representative, rule.pattern):
                raise ResearchBoundaryError(
                    f"Editable pattern {pattern!r} overlaps protected rule {rule.pattern!r} "
                    f"({rule.access.value})."
                )


def validate_candidate_paths(
    changed_paths: tuple[str, ...],
    spec: ExperimentSpec,
    policy: EvaluatorPolicy,
) -> tuple[str, ...]:
    """Return candidate paths that violate the spec or immutable policy."""
    violations: list[str] = []
    for path in changed_paths:
        normalized = _normalize_relative_path(path)
        access = classify_path(policy, normalized)
        allowed_by_spec = any(_matches(normalized, pattern) for pattern in spec.editable_paths)
        if access is not ResourceAccess.EDITABLE:
            violations.append(f"{normalized}: policy={access.value}")
        elif not allowed_by_spec:
            violations.append(f"{normalized}: outside experiment editable paths")
    return tuple(violations)


def build_protected_snapshot(
    repository: Path,
    policy: EvaluatorPolicy,
    *,
    repository_commit: str,
) -> ProtectedSnapshot:
    """Hash tracked read-only/inaccessible files from the trusted baseline."""
    root = repository.resolve()
    files: list[ProtectedFileRecord] = []
    for relative in _tracked_files(root):
        access = classify_path(policy, relative)
        if access is ResourceAccess.EDITABLE:
            continue
        if access is ResourceAccess.INACCESSIBLE:
            raise ResearchBoundaryError(
                "Inaccessible resources must not be tracked in the experiment baseline: "
                f"{relative}. Move the data outside the repository and remove it from "
                "reachable Git history before running autonomous experiments."
            )
        path = root / relative
        if not path.is_file():
            continue
        files.append(
            ProtectedFileRecord(
                path=relative,
                access=access,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )

    files.sort(key=lambda item: item.path)
    snapshot_payload = {
        "repository_commit": repository_commit,
        "policy_sha256": policy_sha256(policy),
        "files": [item.model_dump(mode="json") for item in files],
    }
    snapshot_digest = hashlib.sha256(
        json.dumps(snapshot_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ProtectedSnapshot(
        created_at=datetime.now(UTC),
        repository_commit=repository_commit,
        policy_sha256=policy_sha256(policy),
        files=tuple(files),
        snapshot_sha256=snapshot_digest,
    )


def protected_snapshot_sha256(snapshot: ProtectedSnapshot) -> str:
    """Recompute the trusted snapshot digest without trusting its stored hash."""
    payload = {
        "repository_commit": snapshot.repository_commit,
        "policy_sha256": snapshot.policy_sha256,
        "files": [item.model_dump(mode="json") for item in snapshot.files],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_protected_snapshot(
    candidate_repository: Path,
    snapshot: ProtectedSnapshot,
) -> tuple[str, ...]:
    """Return protected resources missing or changed in a candidate worktree."""
    root = candidate_repository.resolve()
    violations: list[str] = []
    for record in snapshot.files:
        path = root / record.path
        if not path.is_file():
            violations.append(f"missing protected resource: {record.path}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != record.sha256:
            violations.append(f"changed protected resource: {record.path}")
    return tuple(violations)


def _tracked_files(root: Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ResearchIntegrityError("Unable to inventory tracked evaluator resources.") from exc
    return tuple(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def _normalize_relative_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    parsed = PurePosixPath(normalized)
    if not normalized or parsed.is_absolute() or ".." in parsed.parts:
        raise ResearchBoundaryError("Resource paths must be repository-relative.")
    return normalized


def _matches(path: str, pattern: str) -> bool:
    normalized_pattern = pattern.replace("\\", "/")
    if fnmatch.fnmatchcase(path, normalized_pattern):
        return True
    if normalized_pattern.endswith("/**"):
        prefix = normalized_pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    return False


def _representative_path(pattern: str) -> str:
    """Produce a deterministic path for early broad-policy rejection."""
    parts: list[str] = []
    for part in PurePosixPath(pattern).parts:
        if part == "**":
            parts.extend(("candidate", "file.py"))
        elif any(character in part for character in "*?["):
            suffix = ".py" if ".py" in part else "candidate"
            parts.append(suffix)
        else:
            parts.append(part)
    return "/".join(parts) or "candidate.py"
