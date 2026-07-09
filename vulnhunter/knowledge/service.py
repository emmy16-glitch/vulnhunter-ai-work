"""High-level controlled knowledge-ingestion operations."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from vulnhunter.knowledge.models import (
    HumanReviewStatus,
    InjectionReviewStatus,
    Sensitivity,
    SourceManifest,
    SourceType,
    TrustLevel,
)
from vulnhunter.knowledge.store import KnowledgeStore


def register_source(
    root: Path,
    source_path: Path,
    *,
    title: str,
    origin: str,
    source_type: SourceType,
    sensitivity: Sensitivity,
    trust_level: TrustLevel,
    publication_date: date | None = None,
) -> SourceManifest:
    """Register one approved source without executing any source instruction."""
    store = KnowledgeStore(root)
    return store.register_source(
        source_path,
        title=title,
        origin=origin,
        source_type=source_type,
        sensitivity=sensitivity,
        trust_level=trust_level,
        publication_date=publication_date,
    )


def review_source(
    root: Path,
    source_id: str,
    *,
    status: HumanReviewStatus,
    note: str,
    injection_status: InjectionReviewStatus | None = None,
) -> SourceManifest:
    """Record one explicit human source-review decision."""
    return KnowledgeStore(root).set_review_status(
        source_id,
        status,
        note=note,
        injection_status=injection_status,
    )
