"""Conservative analysis of an Apktool-decoded AndroidManifest.xml file."""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.mobile.models import MobileFinding

_ANDROID = "{http://schemas.android.com/apk/res/android}"
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_STATE",
}
_COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")


def analyze_decoded_manifest(path: Path, *, artifact_sha256: str) -> tuple[MobileFinding, ...]:
    data = path.read_bytes()
    root = ET.fromstring(data)
    source_sha256 = hashlib.sha256(data).hexdigest()
    findings: list[MobileFinding] = []
    application = root.find("application")
    if application is not None:
        if _bool_attr(application, "debuggable"):
            findings.append(
                _finding(
                    artifact_sha256,
                    "android-debuggable-enabled",
                    "Application is marked debuggable",
                    "high",
                    "application",
                    {"source_sha256": source_sha256},
                )
            )
        if _bool_attr(application, "usesCleartextTraffic"):
            findings.append(
                _finding(
                    artifact_sha256,
                    "android-cleartext-traffic",
                    "Application explicitly permits cleartext network traffic",
                    "high",
                    "application",
                    {"source_sha256": source_sha256},
                )
            )
        if _bool_attr(application, "allowBackup"):
            findings.append(
                _finding(
                    artifact_sha256,
                    "android-backup-enabled",
                    "Application backup is enabled",
                    "medium",
                    "application",
                    {"source_sha256": source_sha256},
                )
            )
        for component_type in _COMPONENTS:
            for component in application.findall(component_type):
                exported = _bool_attr(component, "exported")
                if not exported:
                    continue
                name = component.get(f"{_ANDROID}name", "unnamed")
                permission = component.get(f"{_ANDROID}permission")
                if permission:
                    continue
                findings.append(
                    _finding(
                        artifact_sha256,
                        "android-exported-component",
                        f"Exported {component_type} has no component permission",
                        "medium",
                        name,
                        {
                            "component_type": component_type,
                            "source_sha256": source_sha256,
                        },
                    )
                )

    requested = {
        item.get(f"{_ANDROID}name")
        for item in root.findall("uses-permission")
        if item.get(f"{_ANDROID}name")
    }
    dangerous = sorted(requested & _DANGEROUS_PERMISSIONS)
    if dangerous:
        findings.append(
            _finding(
                artifact_sha256,
                "android-dangerous-permissions",
                "Application requests high-impact Android permissions",
                "info",
                "manifest",
                {"permissions": dangerous, "source_sha256": source_sha256},
            )
        )
    return tuple(findings)


def _bool_attr(element: ET.Element, name: str) -> bool:
    return element.get(f"{_ANDROID}{name}", "false").strip().lower() == "true"


def _finding(
    artifact_sha256: str,
    weakness_id: str,
    title: str,
    severity: str,
    component: str,
    evidence: dict[str, object],
) -> MobileFinding:
    finding_id = sha256_json(
        {
            "artifact": artifact_sha256,
            "weakness": weakness_id,
            "component": component,
            "evidence": evidence,
        }
    )[:24]
    return MobileFinding(
        finding_id=f"finding-{finding_id}",
        weakness_id=weakness_id,
        title=title,
        severity=severity,
        component=component,
        tool_ids=("apktool-manifest",),
        evidence=evidence,
        artifact_sha256=artifact_sha256,
    )
