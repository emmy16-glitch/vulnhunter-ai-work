"""Audit the current VulnHunter documentation authority chain.

This script keeps its historical filename so old automation does not fail with a
missing path, but the former 608-row future-master-plan matrix is retired. The
current product uses explicit status, roadmap, product/security contracts and
historical-document markers instead of treating one old plan as canonical.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuthorityCheck:
    name: str
    path: str
    required_fragments: tuple[str, ...]


CURRENT_CHECKS: tuple[AuthorityCheck, ...] = (
    AuthorityCheck(
        "repository operating manual",
        "AGENTS.md",
        (
            "PUBLIC_TARGET_ASSESSMENT.md",
            "LIVE_EXECUTION_ACTIVITY.md",
            "authorised public",
        ),
    ),
    AuthorityCheck(
        "current implementation status",
        "docs/intelligence/CURRENT_STATE.md",
        (
            "PUBLIC-TARGET WORKER EXECUTION",
            "NOT COMPLETE",
            "RICH LIVE EXECUTION ACTIVITY",
            "PARTIAL",
        ),
    ),
    AuthorityCheck(
        "dependency roadmap",
        "docs/intelligence/ROADMAP.md",
        (
            "Authorised public-target passive execution",
            "Persisted live execution activity",
            "UI Contract V2 runtime migration",
        ),
    ),
    AuthorityCheck(
        "public target contract",
        "docs/product/PUBLIC_TARGET_ASSESSMENT.md",
        (
            "A public address is not permission",
            "Connection-time revalidation",
            "Host and TLS identity preservation",
        ),
    ),
    AuthorityCheck(
        "live execution contract",
        "docs/product/LIVE_EXECUTION_ACTIVITY.md",
        (
            "operational telemetry",
            "One persisted activity stream",
            "hidden chain-of-thought",
        ),
    ),
    AuthorityCheck(
        "chat-first workflow",
        "docs/product/CHAT_FIRST_WORKSPACE.md",
        (
            "Public target workflow",
            "Live running-task behavior",
        ),
    ),
    AuthorityCheck(
        "Source Hunt contract",
        "docs/product/SOURCE_HUNT.md",
        (
            "Mandatory preflight",
            "Permitted-path semantics",
            "Live execution activity",
        ),
    ),
)


RETIRED_CHECKS: tuple[AuthorityCheck, ...] = (
    AuthorityCheck(
        "future master plan",
        "docs/intelligence/VULNHUNTER_FUTURE_MASTER_PLAN.md",
        ("RETIRED AS AN AUTHORITY SOURCE",),
    ),
    AuthorityCheck(
        "total programme execution tracker",
        "docs/intelligence/TOTAL_PROGRAMME_EXECUTION_TRACKER.md",
        ("HISTORICAL / NON-AUTHORITATIVE",),
    ),
    AuthorityCheck(
        "total programme evidence catalogue",
        "docs/intelligence/TOTAL_PROGRAMME_REPOSITORY_EVIDENCE_CATALOGUE.md",
        ("HISTORICAL / NON-AUTHORITATIVE",),
    ),
)


@dataclass(frozen=True)
class AuditResult:
    name: str
    path: str
    ok: bool
    detail: str


def audit(root: Path) -> tuple[AuditResult, ...]:
    results: list[AuditResult] = []
    for check in CURRENT_CHECKS + RETIRED_CHECKS:
        path = root / check.path
        if not path.is_file():
            results.append(AuditResult(check.name, check.path, False, "missing file"))
            continue
        text = path.read_text(encoding="utf-8")
        missing = [fragment for fragment in check.required_fragments if fragment not in text]
        results.append(
            AuditResult(
                check.name,
                check.path,
                not missing,
                "ok" if not missing else "missing: " + ", ".join(missing),
            )
        )
    return tuple(results)


def render(results: tuple[AuditResult, ...]) -> str:
    failures = [result for result in results if not result.ok]
    rows = "\n".join(
        f"| {result.name} | `{result.path}` | {'PASS' if result.ok else 'FAIL'} | {result.detail} |"
        for result in results
    )
    return f"""# Programme Authority Reconciliation Report

**Status:** {'PASS' if not failures else 'FAIL'}

The former 608-row future-master-plan coverage matrix is retired. Current
coverage is governed by explicit current-state, roadmap, product/security
contracts and historical-document markers.

| Check | File | Result | Detail |
| --- | --- | --- | --- |
{rows}

## Current authority rule

- `docs/intelligence/CURRENT_STATE.md` owns implementation status.
- `docs/intelligence/ROADMAP.md` owns dependency order.
- `docs/intelligence/KNOWN_FAILURES.md` owns unresolved limitations.
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md` owns authorised public-target behavior.
- `docs/product/LIVE_EXECUTION_ACTIVITY.md` owns persisted running-task telemetry.
- historical total-programme/future-plan files are not implementation authority.

## Result

- Failed checks: `{len(failures)}`
- Transition gate: `{'PASS' if not failures else 'FAIL'}`
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    results = audit(args.root)
    output = render(results)
    if args.check:
        return 0 if all(result.ok for result in results) else 1

    output_path = args.root / args.output
    output_path.write_text(output, encoding="utf-8")
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
