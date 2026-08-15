from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from vulnhunter.governance.models import ReviewerIdentity
from vulnhunter.source_hunt.controlled_corpus import (
    ControlledCorpusDraft,
    ControlledCorpusDraftBuilder,
    ControlledCorpusRelease,
    ControlledCorpusReleaseService,
    ControlledGroundTruthSpec,
    CorpusReviewAttestation,
    CorpusReviewLedger,
    CorpusReviewVerdict,
)
from vulnhunter.source_hunt.service import RepositorySnapshotBuilder, SourceHuntPolicy

_NOW = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)
_FIXTURE = Path(__file__).parents[1] / "fixtures" / "source_hunt_controlled" / "python_core"


def _sha(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identity(reviewer_id: str, roles: tuple[str, ...], marker: str) -> ReviewerIdentity:
    return ReviewerIdentity(
        reviewer_id=reviewer_id,
        display_name=reviewer_id,
        roles=roles,
        conflict_tags=(),
        status="active",
        credential_salt="a" * 24,
        credential_hash="b" * 48,
        created_by="root-admin",
        created_at=_NOW,
        status_changed_at=None,
        status_reason=None,
        record_sha256=marker * 64,
    )


def _draft():
    specs = TypeAdapter(tuple[ControlledGroundTruthSpec, ...]).validate_json(
        (_FIXTURE / "cases.json").read_text(encoding="utf-8")
    )
    snapshot = RepositorySnapshotBuilder(SourceHuntPolicy(approved_roots=(_FIXTURE.parent,))).build(
        _FIXTURE, revision="c" * 40
    )
    return ControlledCorpusDraftBuilder().build(
        corpus_id="python-core-v1",
        snapshot=snapshot,
        specs=specs,
        prepared_by=_identity("preparer", ("campaign_admin",), "1"),
        assigned_reviewers=(
            _identity("reviewer-a", ("reviewer",), "2"),
            _identity("reviewer-b", ("reviewer",), "3"),
        ),
        created_at=_NOW,
    )


def _release():
    draft = _draft()
    reviewer_a = _identity("reviewer-a", ("reviewer",), "2")
    reviewer_b = _identity("reviewer-b", ("reviewer",), "3")
    reviews = (
        CorpusReviewAttestation.create(
            draft=draft,
            reviewer=reviewer_a,
            verdict=CorpusReviewVerdict.APPROVED,
            reason="Reviewed exact source anchors and labels.",
            reviewed_at=_NOW,
        ),
        CorpusReviewAttestation.create(
            draft=draft,
            reviewer=reviewer_b,
            verdict=CorpusReviewVerdict.APPROVED,
            reason="Reviewed exact source anchors and labels.",
            reviewed_at=_NOW,
        ),
    )
    return ControlledCorpusReleaseService().release(
        draft=draft,
        reviews=reviews,
        reviewer_identities={
            reviewer_a.reviewer_id: reviewer_a,
            reviewer_b.reviewer_id: reviewer_b,
        },
        released_by=_identity("release-admin", ("campaign_admin",), "4"),
        released_at=_NOW,
    )


def test_operational_draft_rejects_recomputed_production_accuracy_claim() -> None:
    payload = _draft().model_dump(mode="json")
    payload["production_accuracy_claim_permitted"] = True
    canonical = {
        key: value for key, value in payload.items() if key not in {"draft_id", "draft_sha256"}
    }
    digest = _sha(canonical)
    payload["draft_sha256"] = digest
    payload["draft_id"] = f"source-corpus-draft-{digest[:24]}"

    with pytest.raises(ValidationError, match="cannot permit production accuracy claims"):
        ControlledCorpusDraft.model_validate(payload)


def test_operational_release_rejects_recomputed_review_from_other_draft() -> None:
    payload = _release().model_dump(mode="json")
    review = payload["reviews"][0]
    review["draft_id"] = "source-corpus-draft-" + "d" * 24
    review["draft_sha256"] = "e" * 64
    review_canonical = {
        key: value
        for key, value in review.items()
        if key not in {"attestation_id", "attestation_sha256"}
    }
    review_digest = _sha(review_canonical)
    review["attestation_sha256"] = review_digest
    review["attestation_id"] = f"source-corpus-review-{review_digest[:24]}"

    canonical = {
        key: value for key, value in payload.items() if key not in {"release_id", "release_sha256"}
    }
    release_digest = _sha(canonical)
    payload["release_sha256"] = release_digest
    payload["release_id"] = f"source-corpus-release-{release_digest[:24]}"

    with pytest.raises(ValidationError, match="different draft identifier"):
        ControlledCorpusRelease.model_validate(payload)


def test_review_ledger_rejects_path_traversal_draft_identifier(tmp_path: Path) -> None:
    ledger = CorpusReviewLedger(tmp_path)

    with pytest.raises(ValueError, match="draft identifier is invalid"):
        ledger._path("../../outside", "reviewer-a")
