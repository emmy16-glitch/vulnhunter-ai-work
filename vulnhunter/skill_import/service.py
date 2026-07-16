"""Static, non-activating inspection for third-party skill packs."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from vulnhunter.actions.models import sha256_json
from vulnhunter.skill_import.models import (
    ImportDecision,
    ImportedFileRecord,
    ImportRisk,
    SkillImportReview,
)

_FORBIDDEN_PATTERNS: tuple[tuple[re.Pattern[str], str, ImportRisk], ...] = (
    (
        re.compile(r"\b(sudo|su\s+-|setuid|chmod\s+4[0-7]{3})\b", re.I),
        "privileged command instruction",
        ImportRisk.CRITICAL,
    ),
    (
        re.compile(r"\b(curl|wget)\b.*\|\s*(sh|bash)", re.I),
        "remote pipe-to-shell installation",
        ImportRisk.CRITICAL,
    ),
    (
        re.compile(r"authorization\s+(is\s+)?(implied|assumed)|mentioning.*target.*author", re.I),
        "attempt to weaken authorization",
        ImportRisk.CRITICAL,
    ),
    (
        re.compile(r"ignore\s+(previous|system|global)\s+instructions", re.I),
        "prompt-injection instruction",
        ImportRisk.HIGH,
    ),
    (
        re.compile(r"disable\s+(audit|logging)|delete\s+logs", re.I),
        "attempt to disable audit evidence",
        ImportRisk.CRITICAL,
    ),
    (
        re.compile(r"self[- ]?(approve|grant|authorize)", re.I),
        "self-granted authority",
        ImportRisk.CRITICAL,
    ),
    (
        re.compile(r"persistence|credential\s+dump|edr\s+bypass|lateral\s+movement", re.I),
        "high-risk offensive methodology",
        ImportRisk.HIGH,
    ),
)
_ALLOWED_TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".rst"}


class SkillImportError(RuntimeError):
    pass


class SkillPackInspector:
    def __init__(self, *, maximum_files: int = 500, maximum_total_bytes: int = 20_000_000) -> None:
        self.maximum_files = maximum_files
        self.maximum_total_bytes = maximum_total_bytes

    def inspect(self, root: Path, *, review_id: str, source_reference: str) -> SkillImportReview:
        source_root = root.expanduser().resolve(strict=True)
        if not source_root.is_dir():
            raise SkillImportError("skill source must be a directory")
        records: list[ImportedFileRecord] = []
        total_bytes = 0
        aggregate: list[dict[str, object]] = []
        highest = ImportRisk.LOW
        reasons: list[str] = []

        for path in sorted(source_root.rglob("*")):
            if path.is_symlink():
                reasons.append(f"symlink rejected: {path.relative_to(source_root)}")
                highest = max_risk(highest, ImportRisk.HIGH)
                continue
            if not path.is_file():
                continue
            if len(records) >= self.maximum_files:
                raise SkillImportError("skill pack contains too many files")
            relative = path.relative_to(source_root).as_posix()
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise SkillImportError(f"unable to read skill file: {relative}") from exc
            total_bytes += len(raw)
            if total_bytes > self.maximum_total_bytes:
                raise SkillImportError("skill pack exceeds the total size limit")
            executable = bool(path.stat().st_mode & 0o111)
            findings: list[str] = []
            if executable or path.suffix.lower() not in _ALLOWED_TEXT_SUFFIXES:
                findings.append("non-text or executable content cannot be imported as authority")
                highest = max_risk(highest, ImportRisk.HIGH)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            for pattern, reason, risk in _FORBIDDEN_PATTERNS:
                if pattern.search(text):
                    findings.append(reason)
                    reasons.append(f"{relative}: {reason}")
                    highest = max_risk(highest, risk)
            digest = hashlib.sha256(raw).hexdigest()
            record = ImportedFileRecord(
                relative_path=relative,
                sha256=digest,
                size_bytes=len(raw),
                executable=executable,
                findings=tuple(findings),
            )
            records.append(record)
            aggregate.append(record.model_dump(mode="json"))

        source_sha256 = sha256_json(aggregate)
        if highest == ImportRisk.CRITICAL:
            decision = ImportDecision.REJECTED
        elif highest == ImportRisk.HIGH or reasons:
            decision = ImportDecision.REVIEW_REQUIRED
        else:
            decision = ImportDecision.SAFE_TO_REWRITE
            reasons.append(
                "No prohibited instruction patterns detected; human rewrite is still required."
            )
        return SkillImportReview(
            review_id=review_id,
            source_reference=source_reference,
            source_sha256=source_sha256,
            files=tuple(records),
            risk=highest,
            decision=decision,
            reasons=tuple(reasons),
            activation_allowed=False,
        )

    @staticmethod
    def export_review(review: SkillImportReview, output: Path) -> None:
        destination = output.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise SkillImportError("review output may not be a symlink")
        destination.write_text(review.model_dump_json(indent=2) + "\n", encoding="utf-8")


_RISK_RANK = {ImportRisk.LOW: 0, ImportRisk.MEDIUM: 1, ImportRisk.HIGH: 2, ImportRisk.CRITICAL: 3}


def max_risk(left: ImportRisk, right: ImportRisk) -> ImportRisk:
    return left if _RISK_RANK[left] >= _RISK_RANK[right] else right
