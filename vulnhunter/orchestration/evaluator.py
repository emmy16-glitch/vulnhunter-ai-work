"""Deterministic proof collection and security-policy verification."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.exceptions import LoopEvaluationError, LoopPolicyError
from vulnhunter.orchestration.models import (
    CommandEvidence,
    EvaluationEvidence,
    LoopManifest,
    SecurityEvidence,
    VerifierKind,
    normalize_actor_id,
)
from vulnhunter.security import redact_text

_OUTPUT_LIMIT = 16_000


@dataclass(frozen=True)
class VerifierDefinition:
    """One fixed command template in the safe verifier registry."""

    argv: tuple[str, ...]


def verifier_registry() -> dict[VerifierKind, VerifierDefinition]:
    """Return commands that may be executed without a shell."""
    python = sys.executable
    return {
        VerifierKind.RUFF_CHECK: VerifierDefinition((python, "-m", "ruff", "check", ".")),
        VerifierKind.COMPILEALL: VerifierDefinition(
            (python, "-m", "compileall", "-q", "vulnhunter", "scripts")
        ),
        VerifierKind.PYTEST: VerifierDefinition((python, "-m", "pytest", "-q")),
        VerifierKind.RUFF_FORMAT_CHECK: VerifierDefinition(
            (python, "-m", "ruff", "format", "--check", ".")
        ),
        VerifierKind.GIT_DIFF_CHECK: VerifierDefinition(("git", "diff", "--check")),
        VerifierKind.MYPY: VerifierDefinition((python, "-m", "mypy", "vulnhunter")),
        VerifierKind.BUILD: VerifierDefinition((python, "-m", "build", "--no-isolation")),
        VerifierKind.BENCHMARK_FIXTURES: VerifierDefinition(
            (
                python,
                "-m",
                "pytest",
                "-q",
                "tests/unit/test_benchmark_server.py",
                "tests/unit/test_benchmark_workflow.py",
            )
        ),
    }


def repository_root(start: Path) -> Path:
    """Resolve the enclosing Git repository root."""
    completed = _git(start, "rev-parse", "--show-toplevel")
    return Path(completed.stdout.strip()).resolve()


def current_commit(root: Path) -> str:
    """Return the current commit SHA."""
    return _git(root, "rev-parse", "HEAD").stdout.strip()


def current_tree(root: Path) -> str:
    """Return the current commit tree SHA."""
    return _git(root, "rev-parse", "HEAD^{tree}").stdout.strip()


def working_tree_is_clean(root: Path) -> bool:
    """Return whether tracked and untracked state is clean."""
    return not bool(_git(root, "status", "--porcelain").stdout.strip())


def changed_files(root: Path, baseline_commit: str) -> tuple[str, ...]:
    """Return tracked and untracked paths changed since the loop baseline."""
    tracked = _git(
        root,
        "diff",
        "--name-only",
        "-z",
        baseline_commit,
        "--",
    ).stdout.split("\0")
    untracked = _git(
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    ).stdout.split("\0")
    paths = {item for item in (*tracked, *untracked) if item}
    return tuple(sorted(paths))


def path_is_allowed(path: str, patterns: tuple[str, ...]) -> bool:
    """Check one repository-relative path against explicit patterns."""
    normalized = path.replace("\\", "/")
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if fnmatch.fnmatchcase(normalized, pattern):
            return True
        if pattern.endswith("/") and (normalized == clean or normalized.startswith(clean + "/")):
            return True
    return False


def collect_change_evidence(
    root: Path,
    manifest: LoopManifest,
) -> tuple[tuple[str, ...], int, str, str, tuple[str, ...]]:
    """Collect path, size, and fingerprint evidence without persisting raw diff."""
    paths = changed_files(root, manifest.baseline_commit)
    out_of_scope = tuple(
        path for path in paths if not path_is_allowed(path, manifest.spec.allowed_paths)
    )

    diff = _git_bytes(
        root,
        "diff",
        "--binary",
        manifest.baseline_commit,
        "--",
    )
    diff_digest = hashlib.sha256(diff)
    change_digest = hashlib.sha256(diff)
    total_bytes = len(diff)
    untracked = _untracked_files(root)

    for relative in paths:
        candidate = root / relative
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise LoopPolicyError(
                f"Changed path or symbolic-link target escapes repository root: {relative}"
            ) from exc

        change_digest.update(relative.encode("utf-8"))
        change_digest.update(b"\0")
        if candidate.is_symlink():
            target = os.readlink(candidate)
            encoded_target = target.encode("utf-8", errors="replace")
            change_digest.update(b"symlink\0" + encoded_target)
            if relative in untracked:
                diff_digest.update(relative.encode("utf-8") + b"\0" + encoded_target)
                total_bytes += len(encoded_target)
        elif candidate.is_file() and relative in untracked:
            content = candidate.read_bytes()
            content_hash = hashlib.sha256(content).digest()
            change_digest.update(content_hash)
            diff_digest.update(relative.encode("utf-8") + b"\0" + content_hash)
            total_bytes += len(content)
        elif not candidate.exists():
            change_digest.update(b"deleted")

    return (
        paths,
        total_bytes,
        diff_digest.hexdigest(),
        change_digest.hexdigest(),
        out_of_scope,
    )


def run_evaluation(
    root: Path,
    manifest: LoopManifest,
    *,
    runner_id: str,
    tokens_used: int = 0,
    cost_usd: float = 0,
) -> EvaluationEvidence:
    """Execute the fixed verifier suite and return proof-based evidence."""
    runner = normalize_actor_id(runner_id)
    controls = manifest.spec.stop_controls

    checks: list[CommandEvidence] = []
    registry = verifier_registry()
    for verifier in manifest.spec.verifiers:
        definition = registry[verifier]
        argv = definition.argv
        if verifier == VerifierKind.GIT_DIFF_CHECK:
            argv = ("git", "diff", "--check", manifest.baseline_commit, "--")
        checks.append(
            _run_command(
                root,
                verifier,
                argv,
                timeout_seconds=controls.per_check_timeout_seconds,
            )
        )

    # Collect after verifier execution so any generated or modified files become
    # part of the same proof bundle instead of escaping the boundary check.
    paths, diff_bytes, diff_sha, fingerprint, out_of_scope = collect_change_evidence(root, manifest)
    structural_failures: list[str] = []
    if not paths:
        structural_failures.append("No repository changes were detected.")
    if out_of_scope:
        structural_failures.append("Changed files exceed allowed path boundaries.")
    if len(paths) > controls.maximum_changed_files:
        structural_failures.append("Changed-file ceiling exceeded.")
    if diff_bytes > controls.maximum_diff_bytes:
        structural_failures.append("Diff-size ceiling exceeded.")

    passed = not structural_failures and all(item.passed for item in checks)
    failure_parts = list(structural_failures)
    failure_parts.extend(
        f"{item.verifier.value}:{item.exit_code}:{item.output_sha256}"
        for item in checks
        if not item.passed
    )
    failure_signature = (
        hashlib.sha256("\n".join(failure_parts).encode("utf-8")).hexdigest()
        if failure_parts
        else None
    )

    return EvaluationEvidence(
        iteration=manifest.iteration_count + 1,
        runner_id=runner,
        created_at=datetime.now(UTC),
        changed_files=paths,
        changed_files_count=len(paths),
        diff_bytes=diff_bytes,
        diff_sha256=diff_sha,
        change_fingerprint=fingerprint,
        out_of_scope_paths=out_of_scope,
        checks=tuple(checks),
        passed=passed,
        failure_signature=failure_signature,
        tokens_used=tokens_used,
        cost_usd=cost_usd,
    )


_SECURITY_PATTERNS = (
    (
        re.compile(r"^\+.*\bfollow_redirects\s*=\s*True", re.IGNORECASE),
        "Automatic redirect following was enabled.",
    ),
    (
        re.compile(r"^\+.*\btrust_env\s*=\s*True", re.IGNORECASE),
        "Environment proxy inheritance was enabled.",
    ),
    (
        re.compile(r"^\+.*\bverify\s*=\s*False", re.IGNORECASE),
        "TLS certificate verification was disabled.",
    ),
    (
        re.compile(r"^\+.*\bshell\s*=\s*True", re.IGNORECASE),
        "Shell command execution was introduced.",
    ),
    (
        re.compile(
            r"^\+.*(?:api[_-]?key|secret|password|access[_-]?token)\s*=\s*['\"][^'\"]+",
            re.IGNORECASE,
        ),
        "A possible hard-coded secret was added.",
    ),
)

_GENERATED_SUFFIXES = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pkl",
    ".pickle",
    ".joblib",
)


def run_security_verification(
    root: Path,
    manifest: LoopManifest,
    *,
    verifier_id: str,
) -> SecurityEvidence:
    """Run deterministic policy checks independently of functional tests."""
    verifier = normalize_actor_id(verifier_id)
    paths, _, diff_sha, _, out_of_scope = collect_change_evidence(root, manifest)
    findings: list[str] = []

    if out_of_scope:
        findings.append("Out-of-scope changed paths: " + ", ".join(out_of_scope))

    for path in paths:
        lowered = path.lower()
        absolute = root / path
        if absolute.is_symlink():
            findings.append(f"Changed symbolic link requires human escalation: {path}")
        if lowered.startswith("artifacts/") or lowered.endswith(_GENERATED_SUFFIXES):
            findings.append(f"Generated or database artifact changed: {path}")
        if any(
            fragment in lowered for fragment in (".env", "private_key", "id_rsa", "credentials")
        ):
            findings.append(f"Sensitive-looking path changed: {path}")

    diff_text = _git_bytes(
        root,
        "diff",
        "--unified=0",
        manifest.baseline_commit,
        "--",
    ).decode("utf-8", errors="replace")
    untracked_text: list[str] = []
    untracked = _untracked_files(root)
    for relative in paths:
        if relative not in untracked:
            continue
        absolute = root / relative
        if absolute.is_file() and absolute.stat().st_size <= 1_000_000:
            try:
                content = absolute.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            untracked_text.extend("+" + line for line in content.splitlines())

    for line in (*diff_text.splitlines(), *untracked_text):
        if line.startswith("+++"):
            continue
        for pattern, message in _SECURITY_PATTERNS:
            if pattern.search(line):
                findings.append(message)

    critical_prefixes = (
        "vulnhunter/scope/",
        "vulnhunter/authorization/",
        "vulnhunter/security/",
        "vulnhunter/scanner/",
        "vulnhunter/observations/storage.py",
        "vulnhunter/ml/splitting.py",
    )
    critical_changed = any(
        any(path.startswith(prefix) for prefix in critical_prefixes) for path in paths
    )
    documented = any(path.startswith("docs/") or path == "AGENTS.md" for path in paths)
    if critical_changed and not documented:
        findings.append("Security-critical code changed without corresponding documentation.")

    unique_findings = tuple(dict.fromkeys(findings))
    return SecurityEvidence(
        iteration=manifest.iteration_count,
        verifier_id=verifier,
        created_at=datetime.now(UTC),
        passed=not unique_findings,
        findings=unique_findings,
        diff_sha256=diff_sha,
    )


def _run_command(
    root: Path,
    verifier: VerifierKind,
    argv: tuple[str, ...],
    *,
    timeout_seconds: int,
) -> CommandEvidence:
    started = time.monotonic()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONPATH",
            "TERM",
            "VIRTUAL_ENV",
        }
    }
    environment.update(
        {
            "PYTHONNOUSERSITE": "1",
            "VULNHUNTER_OFFLINE": "1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost,::1",
        }
    )

    timed_out = False
    exit_code = 1
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                argv,
                cwd=root,
                env=environment,
                shell=False,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                exit_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = 124
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                output.write(b"\nVerifier timed out.\n")

            output.flush()
            output.seek(0)
            digest = hashlib.sha256()
            tail = bytearray()
            while True:
                chunk = output.read(65_536)
                if not chunk:
                    break
                digest.update(chunk)
                tail.extend(chunk)
                if len(tail) > 65_536:
                    del tail[:-65_536]
    except OSError as exc:
        raise LoopEvaluationError(f"Unable to execute verifier {verifier.value}: {exc}") from exc

    duration = time.monotonic() - started
    decoded_tail = tail.decode("utf-8", errors="replace")
    excerpt = redact_text(decoded_tail)[-_OUTPUT_LIMIT:]
    return CommandEvidence(
        verifier=verifier,
        argv=argv,
        exit_code=exit_code,
        passed=exit_code == 0 and not timed_out,
        duration_seconds=round(duration, 6),
        output_sha256=digest.hexdigest(),
        output_excerpt=excerpt,
        timed_out=timed_out,
    )


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LoopEvaluationError(
            "The orchestration harness requires a readable Git repository."
        ) from exc


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
        )
        return completed.stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LoopEvaluationError("Unable to collect Git diff evidence.") from exc


def _untracked_files(root: Path) -> set[str]:
    return {
        item
        for item in _git(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ).stdout.split("\0")
        if item
    }
