from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.source_hunt import (
    MobileGraphEdgeType,
    MobileSourceHuntEngine,
    MobileSourceHuntState,
    MobileSourceHuntStore,
)

ARTIFACT_SHA256 = "a" * 64


def _intelligence(
    *,
    source_coverage: str = "partial",
    endpoints: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "artifact_id": "apk-test-source-hunt",
        "artifact_sha256": ARTIFACT_SHA256,
        "coverage": {
            "capabilities": [
                {
                    "capability": "jadx",
                    "status": source_coverage,
                    "detail": "retained partial source" if source_coverage == "partial" else None,
                    "evidence_references": ["tool:jadx:test"],
                }
            ]
        },
        "exported_component_surfaces": [
            {
                "component_id": "component:webview",
                "name": "com.example.NotificationWebViewActivity",
                "kind": "activity",
                "ownership": "app_owned",
                "permission": None,
                "intent_filters": [],
                "evidence_references": ["manifest:attack-surface"],
            }
        ],
        "verified_configurations": [
            {
                "record_id": "finding:cleartext",
                "title": "Application permits cleartext traffic",
                "weakness_id": "android-cleartext-traffic",
                "ownership": "unknown",
                "evidence_references": ["observation:cleartext"],
                "security_property": "transport_confidentiality",
            }
        ],
        "candidates": [
            {
                "record_id": "finding:dynamic-endpoint",
                "title": "Network-derived endpoint assignment",
                "weakness_id": "dynamic-endpoint-assignment",
                "ownership": "app_owned",
                "evidence_references": ["observation:dynamic-endpoint"],
                "security_property": "endpoint_integrity",
            }
        ],
        "endpoint_references": endpoints
        or [
            {
                "endpoint": "http://api.example.test/update",
                "normalized_endpoint": "http://api.example.test/update",
                "host": "api.example.test",
                "protocol": "http",
                "likely_role": "firmware_update",
                "ownership": "app_owned",
                "confidence": "confirmed",
                "evidence_references": ["endpoint:update"],
            },
            {
                "endpoint": "http://api.example.test/update/",
                "normalized_endpoint": "http://api.example.test/update",
                "host": "api.example.test",
                "protocol": "http",
                "likely_role": "firmware_update",
                "ownership": "app_owned",
                "confidence": "confirmed",
                "evidence_references": ["endpoint:update-duplicate"],
            },
        ],
    }


def _write_source(root: Path, name: str, content: str) -> Path:
    path = root / "sources" / "com" / "example" / name
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_component_without_retained_implementation_is_inconclusive(tmp_path: Path):
    report = MobileSourceHuntEngine(
        source_root=tmp_path,
        intelligence=_intelligence(),
        analysis_run_id="source-run-component-missing",
    ).run()

    component = next(item for item in report.results if item.seed.seed_type == "component")

    assert component.state == MobileSourceHuntState.INCONCLUSIVE
    assert component.bounded_negative is True
    assert component.verified_finding is False
    assert "not present" in component.summary
    assert report.verified_finding_count == 0


def test_cleartext_source_hunt_builds_deduplicated_evidence_graph(tmp_path: Path):
    source = _write_source(
        tmp_path,
        "HttpUrlDefines.java",
        """package com.example;

public final class HttpUrlDefines {
    static final String UPDATE = "http://api.example.test/update";
}
""",
    )
    report = MobileSourceHuntEngine(
        source_root=tmp_path,
        intelligence=_intelligence(),
        analysis_run_id="source-run-cleartext",
    ).run()

    cleartext = next(
        item for item in report.results if item.seed.weakness_id == "android-cleartext-traffic"
    )
    endpoint_nodes = [
        node for node in report.graph.nodes if node.node_type.value == "network_endpoint"
    ]
    cleartext_edges = [
        edge for edge in report.graph.edges if edge.relation == MobileGraphEdgeType.LOADS_URL
    ]

    assert cleartext.state == MobileSourceHuntState.EVIDENCE_REQUIRED
    assert cleartext.verified_finding is False
    assert source.relative_to(tmp_path).as_posix() in {
        reference.path for reference in cleartext.source_references
    }
    assert len(endpoint_nodes) == 1
    assert len(cleartext_edges) == 1
    assert len(report.graph.graph_sha256) == 64


def test_dynamic_endpoint_source_hunt_preserves_missing_controls(tmp_path: Path):
    _write_source(
        tmp_path,
        "GlobalDefines.java",
        """package com.example;

final class GlobalDefines {
    void assign(String responseUrl) {
        GlobalConfiguration.sDynamicAssignOtaServer = responseUrl;
    }
}
""",
    )
    report = MobileSourceHuntEngine(
        source_root=tmp_path,
        intelligence=_intelligence(),
        analysis_run_id="source-run-dynamic-endpoint",
    ).run()

    dynamic = next(
        item for item in report.results if item.seed.weakness_id == "dynamic-endpoint-assignment"
    )

    assert dynamic.state == MobileSourceHuntState.EVIDENCE_REQUIRED
    assert "allowlist" in " ".join(dynamic.missing_evidence)
    assert "GlobalDefines.java" in dynamic.source_references[0].path
    assert any(edge.relation == MobileGraphEdgeType.ASSIGNS_TO for edge in report.graph.edges)


def test_mobile_source_hunt_store_round_trips_graph_report(tmp_path: Path):
    report = MobileSourceHuntEngine(
        source_root=tmp_path,
        intelligence=_intelligence(),
        analysis_run_id="source-run-store",
    ).run()
    store = MobileSourceHuntStore(tmp_path / "reports")

    destination = store.save(report)
    loaded = store.load(report.report_id)

    assert destination.exists()
    assert loaded == report
    assert (
        json.loads(destination.read_text(encoding="utf-8"))["graph"]["graph_sha256"]
        == report.graph.graph_sha256
    )
