"""Atomic sidecar persistence for Source Hunt Intelligence V2 bundles."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from vulnhunter.source_hunt.intelligence import SourceHuntIntelligenceBundle


class SourceHuntIntelligenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def save(self, bundle: SourceHuntIntelligenceBundle) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self._path(bundle.report_id)
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(bundle.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination

    def load(self, report_id: str) -> SourceHuntIntelligenceBundle:
        return SourceHuntIntelligenceBundle.model_validate_json(
            self._path(report_id).read_text(encoding="utf-8")
        )

    def exists(self, report_id: str) -> bool:
        return self._path(report_id).is_file()

    def list(self, *, limit: int = 50) -> tuple[SourceHuntIntelligenceBundle, ...]:
        self.root.mkdir(parents=True, exist_ok=True)
        bundles: list[SourceHuntIntelligenceBundle] = []
        for path in self.root.glob("source-report-*.intelligence.json"):
            try:
                bundles.append(SourceHuntIntelligenceBundle.model_validate_json(path.read_text()))
            except (OSError, ValueError):
                continue
        return tuple(sorted(bundles, key=lambda item: item.created_at, reverse=True)[:limit])

    def _path(self, report_id: str) -> Path:
        self._validate_report_id(report_id)
        return self.root / f"{report_id}.intelligence.json"

    @staticmethod
    def _validate_report_id(report_id: str) -> None:
        prefix = "source-report-"
        suffix = report_id[len(prefix) :] if report_id.startswith(prefix) else ""
        if len(suffix) != 24 or any(character not in "0123456789abcdef" for character in suffix):
            raise ValueError("source-hunt report identifier is invalid")
