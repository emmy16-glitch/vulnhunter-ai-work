"""Append-only JSONL evidence store with artifact integrity checks."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.evidence.models import EvidenceRecord, FindingStatus


class EvidenceStoreError(RuntimeError):
    pass


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.ledger = self.root / "evidence.jsonl"

    def append(
        self,
        *,
        evidence_id: str,
        campaign_id: str,
        run_id: str,
        action_manifest_sha256: str,
        tool_id: str,
        target_reference: str,
        finding_status: FindingStatus,
        title: str,
        severity: str,
        confidence: str,
        recorded_by: str,
        artifact_path: Path | None = None,
        metadata: dict[str, object] | None = None,
    ) -> EvidenceRecord:
        previous = self.list()[-1].record_sha256 if self.list() else "0" * 64
        artifact_reference: str | None = None
        artifact_sha256: str | None = None
        if artifact_path is not None:
            resolved = artifact_path.expanduser().resolve()
            try:
                resolved.relative_to(self.root)
            except ValueError as exc:
                raise EvidenceStoreError("artifact must live inside the evidence root") from exc
            if not resolved.is_file():
                raise EvidenceStoreError("artifact file does not exist")
            artifact_reference = str(resolved.relative_to(self.root))
            artifact_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()

        draft = {
            "evidence_id": evidence_id,
            "campaign_id": campaign_id,
            "run_id": run_id,
            "action_manifest_sha256": action_manifest_sha256,
            "tool_id": tool_id,
            "target_reference": target_reference,
            "finding_status": finding_status,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "artifact_path": artifact_reference,
            "artifact_sha256": artifact_sha256,
            "metadata": metadata or {},
            "recorded_by": recorded_by,
            "previous_record_sha256": previous,
            "record_sha256": "0" * 64,
        }
        temporary = EvidenceRecord.model_validate(draft)
        record = temporary.model_copy(update={"record_sha256": temporary.expected_sha256()})
        line = record.model_dump_json() + "\n"
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def list(self) -> tuple[EvidenceRecord, ...]:
        if not self.ledger.is_file():
            return ()
        records: list[EvidenceRecord] = []
        previous = "0" * 64
        for line_number, line in enumerate(
            self.ledger.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not line.strip():
                continue
            try:
                record = EvidenceRecord.model_validate_json(line)
            except ValidationError as exc:
                raise EvidenceStoreError(f"evidence ledger line {line_number} is invalid") from exc
            if record.previous_record_sha256 != previous:
                raise EvidenceStoreError("evidence ledger chain has been altered")
            if record.expected_sha256() != record.record_sha256:
                raise EvidenceStoreError("evidence record digest does not match")
            if record.artifact_path:
                path = (self.root / record.artifact_path).resolve()
                try:
                    path.relative_to(self.root)
                except ValueError as exc:
                    raise EvidenceStoreError("artifact path escapes evidence root") from exc
                if not path.is_file():
                    raise EvidenceStoreError("referenced artifact is missing")
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != record.artifact_sha256:
                    raise EvidenceStoreError("artifact digest does not match")
            previous = record.record_sha256
            records.append(record)
        return tuple(records)
