#!/usr/bin/env python3
"""Run bounded deterministic Source Hunt against retained APK source/evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnhunter.source_hunt import MobileSourceHuntEngine, MobileSourceHuntStore


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--report-root", type=Path, required=True)
    parser.add_argument("--analysis-run-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-seeds", type=int, default=64)
    parser.add_argument("--max-source-files", type=int, default=100_000)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    intelligence = receipt.get("intelligence")
    if not isinstance(intelligence, dict):
        raise SystemExit("receipt does not contain normalized APK intelligence")
    report = MobileSourceHuntEngine(
        source_root=args.source_root,
        intelligence=intelligence,
        analysis_run_id=args.analysis_run_id,
        max_seed_count=args.max_seeds,
        max_source_files=args.max_source_files,
    ).run()
    destination = MobileSourceHuntStore(args.report_root).save(report)
    summary = {
        "report_id": report.report_id,
        "report_path": str(destination),
        "artifact_id": report.artifact_id,
        "artifact_sha256": report.artifact_sha256,
        "source_identity": report.source_identity,
        "analysis_run_id": report.analysis_run_id,
        "coverage": report.coverage.model_dump(mode="json"),
        "seeds_examined": report.seeds_examined,
        "verified_finding_count": report.verified_finding_count,
        "rejected_count": report.rejected_count,
        "inconclusive_count": report.inconclusive_count,
        "evidence_required_count": report.evidence_required_count,
        "blocked_count": report.blocked_count,
        "graph_id": report.graph.graph_id,
        "graph_sha256": report.graph.graph_sha256,
        "node_count": len(report.graph.nodes),
        "edge_count": len(report.graph.edges),
        "results": [
            {
                "seed_id": item.seed.seed_id,
                "seed_type": item.seed.seed_type,
                "title": item.seed.title,
                "component_name": item.seed.component_name,
                "weakness_id": item.seed.weakness_id,
                "state": item.state.value,
                "summary": item.summary,
                "entry_point": item.entry_point,
                "source_symbols": item.source_symbols,
                "sink_symbols": item.sink_symbols,
                "controls_observed": item.controls_observed,
                "missing_evidence": item.missing_evidence,
                "source_references": [
                    ref.model_dump(mode="json") for ref in item.source_references
                ],
                "graph_node_ids": item.graph_node_ids,
                "graph_edge_ids": item.graph_edge_ids,
                "bounded_negative": item.bounded_negative,
                "verified_finding": item.verified_finding,
                "remediation": item.remediation,
                "deterministic_validation": item.deterministic_validation,
            }
            for item in report.results
        ],
    }
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
