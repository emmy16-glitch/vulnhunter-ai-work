"""Connect execution evidence artifacts to normalized VulnHunter findings."""

from __future__ import annotations

from pathlib import Path

from vulnhunter.security_tools.models import ToolExecutionResult
from vulnhunter.security_tools.parsers import (
    NormalizedFinding,
    parse_jsonl_findings,
    parse_nmap_xml,
    parse_structured_findings,
)

_JSONL_TOOLS = {"httpx", "nuclei"}
_STRUCTURED_TOOLS = {
    "bearer",
    "bandit",
    "detect-secrets",
    "gitleaks",
    "trivy",
    "grype",
    "osv-scanner",
    "capa",
    "ffuf",
    "testssl",
}


def normalize_execution_findings(
    result: ToolExecutionResult,
    *,
    target_reference: str,
) -> tuple[NormalizedFinding, ...]:
    """Normalize supported evidence files while retaining raw artifacts as authority."""

    findings: list[NormalizedFinding] = []
    for raw_path in result.output_files:
        path = Path(raw_path)
        if not path.is_file():
            continue
        if result.tool_id == "nmap" and path.suffix.lower() == ".xml":
            findings.extend(parse_nmap_xml(path, target_reference=target_reference))
        elif result.tool_id in _JSONL_TOOLS and path.suffix.lower() == ".jsonl":
            findings.extend(
                parse_jsonl_findings(
                    path,
                    tool_id=result.tool_id,
                    target_reference=target_reference,
                )
            )
        elif result.tool_id in _STRUCTURED_TOOLS and path.suffix.lower() == ".json":
            findings.extend(
                parse_structured_findings(
                    path,
                    tool_id=result.tool_id,
                    target_reference=target_reference,
                )
            )
    return tuple(findings)
