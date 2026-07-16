"""Minimal normalisers for structured tool output."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vulnhunter.actions.models import sha256_json


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    tool_id: str
    title: str
    severity: str
    target_reference: str
    evidence: dict[str, object]
    confidence: str = "candidate"
    source_sha256: str


def parse_jsonl_findings(
    path: Path,
    *,
    tool_id: str,
    target_reference: str,
) -> tuple[NormalizedFinding, ...]:
    data = path.read_bytes()
    digest = __import__("hashlib").sha256(data).hexdigest()
    findings: list[NormalizedFinding] = []
    for index, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        title = str(
            item.get("info", {}).get("name")
            if isinstance(item.get("info"), dict)
            else item.get("name", f"{tool_id} finding {index}")
        )
        severity = "unknown"
        info = item.get("info")
        if isinstance(info, dict):
            severity = str(info.get("severity", "unknown"))
        findings.append(
            NormalizedFinding(
                finding_id=sha256_json(
                    {
                        "tool_id": tool_id,
                        "index": index,
                        "target": target_reference,
                        "source": digest,
                    }
                )[:24],
                tool_id=tool_id,
                title=title,
                severity=severity,
                target_reference=target_reference,
                evidence={"record_index": index},
                source_sha256=digest,
            )
        )
    return tuple(findings)


def parse_nmap_xml(path: Path, *, target_reference: str) -> tuple[NormalizedFinding, ...]:
    data = path.read_bytes()
    digest = __import__("hashlib").sha256(data).hexdigest()
    root = ET.fromstring(data)
    findings: list[NormalizedFinding] = []
    index = 0
    for host in root.findall("host"):
        address_node = host.find("address")
        address = address_node.get("addr") if address_node is not None else target_reference
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            index += 1
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            port_id = port.get("portid", "unknown")
            findings.append(
                NormalizedFinding(
                    finding_id=sha256_json(
                        {
                            "tool_id": "nmap",
                            "address": address,
                            "port": port_id,
                            "source": digest,
                        }
                    )[:24],
                    tool_id="nmap",
                    title=f"Open {service_name} service on port {port_id}",
                    severity="info",
                    target_reference=target_reference,
                    evidence={
                        "address": address,
                        "port": port_id,
                        "service": service_name,
                    },
                    source_sha256=digest,
                )
            )
    return tuple(findings)


def parse_structured_findings(
    path: Path,
    *,
    tool_id: str,
    target_reference: str,
) -> tuple[NormalizedFinding, ...]:
    """Normalize supported JSON outputs without trusting their schema blindly."""

    data = path.read_bytes()
    digest = __import__("hashlib").sha256(data).hexdigest()
    try:
        payload = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return ()

    records: list[dict[str, object]] = []
    if tool_id == "bandit" and isinstance(payload, dict):
        records = [item for item in payload.get("results", []) if isinstance(item, dict)]
    elif tool_id == "detect-secrets" and isinstance(payload, dict):
        results = payload.get("results", {})
        if isinstance(results, dict):
            for filename, items in results.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict):
                        records.append({**item, "filename": filename})
    elif tool_id == "gitleaks" and isinstance(payload, list):
        records = [item for item in payload if isinstance(item, dict)]
    elif tool_id == "grype" and isinstance(payload, dict):
        records = [item for item in payload.get("matches", []) if isinstance(item, dict)]
    elif tool_id == "osv-scanner" and isinstance(payload, dict):
        for result in payload.get("results", []):
            if not isinstance(result, dict):
                continue
            source = result.get("source", {})
            for package_record in result.get("packages", []):
                if not isinstance(package_record, dict):
                    continue
                package = package_record.get("package", {})
                for vuln in package_record.get("vulnerabilities", []):
                    if isinstance(vuln, dict):
                        records.append(
                            {"vulnerability": vuln, "package": package, "source": source}
                        )
    elif tool_id == "bearer":
        records = _find_dict_records(payload, required_keys={"rule_id", "severity"})
        if not records:
            records = _find_dict_records(payload, required_keys={"id", "severity"})
    elif tool_id == "capa" and isinstance(payload, dict):
        rules = payload.get("rules", {})
        if isinstance(rules, dict):
            records = [
                {"rule": name, **details}
                for name, details in rules.items()
                if isinstance(details, dict)
            ]
    elif tool_id == "trivy" and isinstance(payload, dict):
        for result in payload.get("Results", []):
            if not isinstance(result, dict):
                continue
            for vulnerability in result.get("Vulnerabilities") or []:
                if isinstance(vulnerability, dict):
                    records.append({**vulnerability, "Target": result.get("Target")})
    elif tool_id == "ffuf" and isinstance(payload, dict):
        records = [item for item in payload.get("results", []) if isinstance(item, dict)]
    elif tool_id == "testssl":
        if isinstance(payload, list):
            records = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            records = _find_dict_records(payload, required_keys={"severity"})
    else:
        records = _find_dict_records(payload, required_keys={"severity"})

    findings: list[NormalizedFinding] = []
    for index, record in enumerate(records, start=1):
        title, severity, evidence = _record_summary(tool_id, record, index)
        findings.append(
            NormalizedFinding(
                finding_id=sha256_json(
                    {
                        "tool_id": tool_id,
                        "index": index,
                        "target": target_reference,
                        "source": digest,
                        "title": title,
                    }
                )[:24],
                tool_id=tool_id,
                title=title,
                severity=severity,
                target_reference=target_reference,
                evidence=evidence,
                source_sha256=digest,
            )
        )
    return tuple(findings)


def _find_dict_records(value: object, *, required_keys: set[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if isinstance(value, dict):
        if required_keys <= set(value):
            records.append(value)
        for child in value.values():
            records.extend(_find_dict_records(child, required_keys=required_keys))
    elif isinstance(value, list):
        for child in value:
            records.extend(_find_dict_records(child, required_keys=required_keys))
    return records


def _record_summary(
    tool_id: str, record: dict[str, object], index: int
) -> tuple[str, str, dict[str, object]]:
    if tool_id == "bandit":
        return (
            str(record.get("issue_text", f"Bandit finding {index}")),
            str(record.get("issue_severity", "unknown")).lower(),
            {
                "test_id": record.get("test_id"),
                "filename": record.get("filename"),
                "line_number": record.get("line_number"),
                "confidence": record.get("issue_confidence"),
            },
        )
    if tool_id == "detect-secrets":
        return (
            f"Potential {record.get('type', 'secret')} detected",
            "high",
            {
                "filename": record.get("filename"),
                "line_number": record.get("line_number"),
                "hashed_secret": record.get("hashed_secret"),
            },
        )
    if tool_id == "gitleaks":
        return (
            str(record.get("Description") or record.get("RuleID") or f"Secret finding {index}"),
            "high",
            {
                "rule_id": record.get("RuleID"),
                "file": record.get("File"),
                "line": record.get("StartLine"),
                "fingerprint": record.get("Fingerprint"),
            },
        )
    if tool_id == "grype":
        vulnerability = record.get("vulnerability", {})
        artifact = record.get("artifact", {})
        vulnerability = vulnerability if isinstance(vulnerability, dict) else {}
        artifact = artifact if isinstance(artifact, dict) else {}
        vuln_id = vulnerability.get("id", "unknown vulnerability")
        package = artifact.get("name", "unknown package")
        return (
            f"{vuln_id} affects {package}",
            str(vulnerability.get("severity", "unknown")).lower(),
            {
                "vulnerability_id": vuln_id,
                "package": package,
                "version": artifact.get("version"),
                "fix": vulnerability.get("fix"),
            },
        )
    if tool_id == "osv-scanner":
        vulnerability = record.get("vulnerability", {})
        package = record.get("package", {})
        source = record.get("source", {})
        vulnerability = vulnerability if isinstance(vulnerability, dict) else {}
        package = package if isinstance(package, dict) else {}
        source = source if isinstance(source, dict) else {}
        vuln_id = vulnerability.get("id", "OSV vulnerability")
        package_name = package.get("name", "unknown package")
        return (
            f"{vuln_id} affects {package_name}",
            "unknown",
            {
                "vulnerability_id": vuln_id,
                "aliases": vulnerability.get("aliases", []),
                "package": package_name,
                "version": package.get("version"),
                "source": source.get("path"),
            },
        )
    if tool_id == "capa":
        return (
            str(record.get("rule", f"Capability match {index}")),
            "info",
            {"namespace": record.get("meta", {}), "matches": record.get("matches", [])},
        )
    if tool_id == "trivy":
        vuln_id = record.get("VulnerabilityID", "Trivy vulnerability")
        package = record.get("PkgName", "unknown package")
        return (
            str(record.get("Title") or f"{vuln_id} affects {package}"),
            str(record.get("Severity", "unknown")).lower(),
            {
                "vulnerability_id": vuln_id,
                "package": package,
                "installed_version": record.get("InstalledVersion"),
                "fixed_version": record.get("FixedVersion"),
                "target": record.get("Target"),
            },
        )
    if tool_id == "ffuf":
        return (
            f"Discovered HTTP resource {record.get('url', record.get('input', 'unknown'))}",
            "info",
            {
                "url": record.get("url"),
                "status": record.get("status"),
                "length": record.get("length"),
                "words": record.get("words"),
            },
        )
    if tool_id == "testssl":
        return (
            str(record.get("id") or record.get("finding") or f"TLS finding {index}"),
            str(record.get("severity", "unknown")).lower(),
            {"finding": record.get("finding"), "cve": record.get("cve")},
        )
    title = str(
        record.get("title")
        or record.get("name")
        or record.get("rule_id")
        or record.get("id")
        or f"{tool_id} finding {index}"
    )
    return title, str(record.get("severity", "unknown")).lower(), {"record": record}
