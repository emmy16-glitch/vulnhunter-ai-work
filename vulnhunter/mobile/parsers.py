"""Conservative normalisers for APKiD and MobSF JSON reports."""

from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.models import MobileFinding


def parse_apkid_json(path: Path, *, artifact_sha256: str) -> tuple[MobileFinding, ...]:
    report = json.loads(path.read_text(encoding="utf-8"))
    findings: list[MobileFinding] = []
    for label, values in _walk_apkid(report):
        normalized = label.lower().replace("_", "-").replace(" ", "-")
        weakness = f"apkid-{normalized}"[:127]
        digest = sha256_json({"artifact": artifact_sha256, "label": label, "values": values})[:24]
        findings.append(
            MobileFinding(
                finding_id=f"finding-{digest}",
                weakness_id=weakness,
                title=f"APKiD detected {label}",
                severity="info",
                tool_ids=("apkid",),
                evidence={"matches": values},
                artifact_sha256=artifact_sha256,
            )
        )
    return tuple(findings)


def parse_mobsf_json(path: Path, *, artifact_sha256: str) -> tuple[MobileFinding, ...]:
    report = json.loads(path.read_text(encoding="utf-8"))
    findings: list[MobileFinding] = []
    for section_name in ("manifest_analysis", "code_analysis", "binary_analysis"):
        section = report.get(section_name)
        if not isinstance(section, list):
            continue
        for index, item in enumerate(section, start=1):
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("rule") or f"MobSF finding {index}")
            severity = str(item.get("severity", "unknown")).lower()
            weakness = str(item.get("rule") or section_name).lower()
            weakness = "mobsf-" + "-".join(part for part in weakness.split() if part)
            weakness = weakness.replace("_", "-")[:127]
            digest = sha256_json(
                {
                    "artifact": artifact_sha256,
                    "section": section_name,
                    "index": index,
                    "title": title,
                }
            )[:24]
            findings.append(
                MobileFinding(
                    finding_id=f"finding-{digest}",
                    weakness_id=weakness,
                    title=title,
                    severity=severity,
                    tool_ids=("mobsf",),
                    evidence={"section": section_name, "record_index": index},
                    artifact_sha256=artifact_sha256,
                )
            )
    return tuple(findings)


def _walk_apkid(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"compiler", "packer", "obfuscator", "protector", "anti_vm"}:
                values = child if isinstance(child, list) else [child]
                yield key, [str(item) for item in values]
            yield from _walk_apkid(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_apkid(child)
