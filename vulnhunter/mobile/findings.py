"""Normalize and correlate Android findings without overstating confidence."""

from __future__ import annotations

from collections import defaultdict

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.models import MobileFinding

_SEVERITY_ORDER = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def correlate_mobile_findings(
    findings: tuple[MobileFinding, ...],
) -> tuple[MobileFinding, ...]:
    grouped: dict[tuple[str, str | None], list[MobileFinding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.weakness_id, finding.component)].append(finding)

    correlated: list[MobileFinding] = []
    for (weakness_id, component), items in sorted(grouped.items()):
        severity = max(items, key=lambda item: _SEVERITY_ORDER.get(item.severity, 0)).severity
        tool_ids = tuple(sorted({tool for item in items for tool in item.tool_ids}))
        evidence = {
            "source_findings": [item.finding_id for item in items],
            "source_evidence": [item.evidence for item in items],
        }
        digest = sha256_json(
            {
                "artifact": items[0].artifact_sha256,
                "weakness": weakness_id,
                "component": component,
                "tools": tool_ids,
            }
        )[:24]
        correlated.append(
            MobileFinding(
                finding_id=f"finding-{digest}",
                weakness_id=weakness_id,
                title=items[0].title,
                severity=severity,
                confidence="observed" if len(tool_ids) > 1 else items[0].confidence,
                component=component,
                tool_ids=tool_ids,
                evidence=evidence,
                artifact_sha256=items[0].artifact_sha256,
            )
        )
    return tuple(correlated)
