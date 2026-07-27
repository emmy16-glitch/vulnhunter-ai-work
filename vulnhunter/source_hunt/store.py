"""Atomic local persistence for source-hunt reports."""

from __future__ import annotations

import json
from pathlib import Path

from vulnhunter.source_hunt.models import SourceHuntReport


class SourceHuntStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def save(self, report: SourceHuntReport) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{report.report_id}.json"
        if destination.exists():
            existing = self.load(report.report_id)
            if existing != report:
                raise ValueError(
                    "source-hunt report identifier already contains different evidence"
                )
            return destination
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination

    def load(self, report_id: str) -> SourceHuntReport:
        if not report_id.startswith("source-report-") or "/" in report_id or "\\" in report_id:
            raise ValueError("source-hunt report identifier is invalid")
        return SourceHuntReport.model_validate_json(
            (self.root / f"{report_id}.json").read_text(encoding="utf-8")
        )

    def list(self, *, limit: int = 50) -> tuple[SourceHuntReport, ...]:
        if not self.root.exists():
            return ()
        reports: list[SourceHuntReport] = []
        for path in sorted(self.root.glob("source-report-*.json"), reverse=True)[:limit]:
            try:
                reports.append(
                    SourceHuntReport.model_validate_json(path.read_text(encoding="utf-8"))
                )
            except (OSError, ValueError):
                continue
        return tuple(reports)
