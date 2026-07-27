from __future__ import annotations

import hashlib
from pathlib import Path

from vulnhunter.source_hunt import (
    FixVerificationInput,
    FixVerificationVerdict,
    ReadOnlyFixVerifier,
    RepositorySnapshotBuilder,
    SourceHuntPolicy,
    SourceReference,
    VerifierReceipt,
)


def _snapshot(tmp_path: Path, *, revision: str):
    repository = tmp_path / revision[:8]
    repository.mkdir()
    source = repository / "app.py"
    source.write_text("def safe(name):\n    return name.replace('..', '')\n", encoding="utf-8")
    policy = SourceHuntPolicy(approved_roots=(tmp_path,))
    return RepositorySnapshotBuilder(policy).build(repository, revision=revision)


def _receipt(name: str, *, passed: bool = True) -> VerifierReceipt:
    content = f"{name}:{passed}".encode()
    return VerifierReceipt(
        verifier_id=name,
        passed=passed,
        exit_code=0 if passed else 1,
        output_sha256=hashlib.sha256(content).hexdigest(),
        duration_seconds=0.2,
        safe_summary="Verifier completed with bounded output.",
    )


def test_read_only_fix_verifier_proves_fixed_snapshot(tmp_path):
    snapshot = _snapshot(tmp_path, revision="f" * 40)
    file = snapshot.files[0]
    request = FixVerificationInput(
        finding_id="src-finding-01",
        original_revision="e" * 40,
        fixed_snapshot=snapshot,
        allowed_paths=("app.py",),
        changed_files=("app.py",),
        security_test=_receipt("security-regression"),
        regression_tests=(_receipt("pytest"), _receipt("ruff")),
        fixed_evidence_refs=(
            SourceReference(
                path=file.path,
                source_sha256=file.sha256,
                line_start=1,
                line_end=2,
                symbol="safe",
            ),
        ),
        original_attack_blocked=True,
    )

    report = ReadOnlyFixVerifier().verify(request)

    assert report.verdict == FixVerificationVerdict.FIXED
    assert report.fixed_revision == snapshot.revision


def test_read_only_fix_verifier_rejects_out_of_scope_change(tmp_path):
    snapshot = _snapshot(tmp_path, revision="d" * 40)
    request = FixVerificationInput(
        finding_id="src-finding-02",
        original_revision="c" * 40,
        fixed_snapshot=snapshot,
        allowed_paths=("app.py",),
        changed_files=("tests/test_policy.py",),
        security_test=_receipt("security-regression"),
        regression_tests=(_receipt("pytest"),),
        original_attack_blocked=True,
    )

    report = ReadOnlyFixVerifier().verify(request)

    assert report.verdict == FixVerificationVerdict.OUT_OF_SCOPE_CHANGE
    assert report.regressions == ("tests/test_policy.py",)


def test_read_only_fix_verifier_surfaces_regression(tmp_path):
    snapshot = _snapshot(tmp_path, revision="b" * 40)
    request = FixVerificationInput(
        finding_id="src-finding-03",
        original_revision="a" * 40,
        fixed_snapshot=snapshot,
        allowed_paths=(".",),
        changed_files=("app.py",),
        security_test=_receipt("security-regression"),
        regression_tests=(_receipt("pytest", passed=False),),
        original_attack_blocked=True,
    )

    report = ReadOnlyFixVerifier().verify(request)

    assert report.verdict == FixVerificationVerdict.REGRESSION_DETECTED
    assert report.regressions == ("pytest",)
