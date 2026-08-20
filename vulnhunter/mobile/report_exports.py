"""Machine-readable exports for layered mobile analysis reports."""

from __future__ import annotations

import csv
import io
from typing import Any

from vulnhunter.mobile.layered_analysis import LayeredStaticReport


def to_graph_json(report: LayeredStaticReport) -> dict[str, object]:
    return {
        "schema_version": report.schema_version,
        "artifact_sha256": report.artifact_sha256,
        "nodes": [{"id": node} for node in report.architecture_nodes],
        "edges": [item.model_dump(mode="json") for item in report.architecture_edges],
    }


def to_sarif(report: LayeredStaticReport) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for observation in report.observations:
        category = str(observation.get("category", "mobile-observation"))
        status = str(observation.get("status", "observed"))
        results.append(
            {
                "ruleId": f"vulnhunter/{category}",
                "level": "note" if status == "observed" else "warning",
                "message": {
                    "text": (
                        f"Static {category} observation; this is not a verified vulnerability. "
                        f"Disposition status: {status}."
                    )
                },
                "properties": {
                    "confidence": observation.get("confidence", "unknown"),
                    "artifact_sha256": report.artifact_sha256,
                    "observation": observation,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "VulnHunter-AI layered static analyzer"}},
                "results": results,
                "properties": {
                    "artifact_sha256": report.artifact_sha256,
                    "completeness": report.completeness.model_dump(mode="json"),
                },
            }
        ],
    }


def to_cyclonedx(report: LayeredStaticReport) -> dict[str, object]:
    components: list[dict[str, object]] = []
    for item in report.package_components:
        components.append(
            {
                "type": "file",
                "name": item.path,
                "bom-ref": item.sha256,
                "hashes": [{"alg": "SHA-256", "content": item.sha256}],
                "properties": [{"name": "vulnhunter.kind", "value": item.kind}],
            }
        )
    for item in report.dex_inventory:
        components.append(
            {
                "type": "file",
                "name": item.path,
                "bom-ref": item.sha256,
                "hashes": [{"alg": "SHA-256", "content": item.sha256}],
                "properties": [
                    {"name": "vulnhunter.class_count", "value": str(item.class_count)},
                    {"name": "vulnhunter.method_count", "value": str(item.method_count)},
                ],
            }
        )
    for item in report.native_inventory:
        components.append(
            {
                "type": "library",
                "name": item.path,
                "bom-ref": item.sha256,
                "hashes": [{"alg": "SHA-256", "content": item.sha256}],
                "properties": [{"name": "vulnhunter.architecture", "value": item.architecture}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": report.manifest.get("package_name") or report.filename,
                "bom-ref": report.artifact_sha256,
                "hashes": [{"alg": "SHA-256", "content": report.artifact_sha256}],
            }
        },
        "components": components,
    }


def endpoints_csv(report: LayeredStaticReport) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=(
            "endpoint",
            "host",
            "port",
            "protocol",
            "likely_role",
            "source_file",
            "source_offset",
            "static_or_runtime",
            "confidence",
        ),
    )
    writer.writeheader()
    for endpoint in report.network_endpoints:
        writer.writerow(endpoint.model_dump(mode="json"))
    return output.getvalue()


def export_bundle(report: LayeredStaticReport) -> dict[str, Any]:
    return {
        "json": report.model_dump(mode="json"),
        "sarif": to_sarif(report),
        "cyclonedx": to_cyclonedx(report),
        "graph": to_graph_json(report),
        "endpoints_csv": endpoints_csv(report),
    }


__all__ = [
    "endpoints_csv",
    "export_bundle",
    "to_cyclonedx",
    "to_graph_json",
    "to_sarif",
]
