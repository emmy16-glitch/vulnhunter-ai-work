"""Governed controlled-lab corpus release and offline benchmark campaign evidence."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.review import normalize_reviewer_id
from vulnhunter.source_hunt.benchmark_acceptance import (
    SourceBenchmarkAcceptanceBundle,
    SourceBenchmarkAcceptanceEvaluator,
    SourceBenchmarkAcceptancePolicy,
    SourceBenchmarkCampaignRunner,
    SourceBenchmarkSuite,
    SourceBenchmarkSuiteEntry,
)
from vulnhunter.source_hunt.benchmark_v2 import BenchmarkCorpusKind, SourceBenchmarkCorpus
from vulnhunter.source_hunt.models import RepositorySnapshot, SourceHuntReport


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("controlled corpus timestamps must include a timezone")
    return current.astimezone(UTC)


class ControlledCorpusReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ControlledFixtureFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, max_length=512)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_count: int = Field(ge=0)


class ControlledFixtureBinding(BaseModel):
    """Source provenance without persisting a local repository root."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_id: str = Field(min_length=2, max_length=128)
    revision: str = Field(min_length=1, max_length=128)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: tuple[ControlledFixtureFile, ...]

    @classmethod
    def from_snapshot(cls, snapshot: RepositorySnapshot) -> ControlledFixtureBinding:
        return cls(
            repository_id=snapshot.repository_id,
            revision=snapshot.revision,
            snapshot_sha256=snapshot.snapshot_sha256,
            files=tuple(
                ControlledFixtureFile(
                    path=item.path,
                    source_sha256=item.sha256,
                    line_count=item.line_count,
                )
                for item in snapshot.files
            ),
        )


class ControlledCorpusDraft(BaseModel):
    """Exact controlled-lab labels proposed by one authenticated reviewer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    draft_id: str = Field(pattern=r"^source-corpus-draft-[0-9a-f]{24}$")
    fixture: ControlledFixtureBinding
    corpus: SourceBenchmarkCorpus
    created_by: str = Field(min_length=2, max_length=64)
    created_at: datetime
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        snapshot: RepositorySnapshot,
        corpus: SourceBenchmarkCorpus,
        created_by: str,
        created_at: datetime | None = None,
    ) -> ControlledCorpusDraft:
        fixture = ControlledFixtureBinding.from_snapshot(snapshot)
        created = _utc(created_at)
        canonical = {
            "fixture": fixture.model_dump(mode="json"),
            "corpus": corpus.model_dump(mode="json"),
            "created_by": normalize_reviewer_id(created_by),
            "created_at": created.isoformat(),
        }
        digest = _canonical_sha256(canonical)
        return cls(
            draft_id=f"source-corpus-draft-{digest[:24]}",
            draft_sha256=digest,
            **canonical,
        )

    @model_validator(mode="after")
    def verify_contract(self) -> ControlledCorpusDraft:
        if self.corpus.kind != BenchmarkCorpusKind.CONTROLLED_LAB:
            raise ValueError("governed corpus drafts must be controlled-lab corpora")
        files = {item.path: item for item in self.fixture.files}
        if not files:
            raise ValueError("controlled corpus fixture cannot be empty")
        if len(files) != len(self.fixture.files):
            raise ValueError("controlled corpus fixture file paths must be unique")
        for case in self.corpus.cases:
            fixture_file = files.get(case.path)
            if fixture_file is None:
                raise ValueError(
                    f"ground-truth case {case.case_id} references a missing fixture file"
                )
            if case.line_end > fixture_file.line_count:
                raise ValueError(
                    f"ground-truth case {case.case_id} exceeds the fixture source line count"
                )
        canonical = {
            "fixture": self.fixture.model_dump(mode="json"),
            "corpus": self.corpus.model_dump(mode="json"),
            "created_by": self.created_by,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
        }
        digest = _canonical_sha256(canonical)
        if digest != self.draft_sha256:
            raise ValueError("controlled corpus draft digest does not match its contents")
        if self.draft_id != f"source-corpus-draft-{digest[:24]}":
            raise ValueError("controlled corpus draft identifier does not match its digest")
        return self


class ControlledCorpusReviewAttestation(BaseModel):
    """Authenticated whole-draft decision bound to the exact label set."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attestation_id: str = Field(pattern=r"^source-corpus-review-[0-9a-f]{24}$")
    draft_id: str
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str = Field(min_length=2, max_length=64)
    decision: ControlledCorpusReviewDecision
    reviewed_at: datetime
    attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        draft: ControlledCorpusDraft,
        reviewer_id: str,
        decision: ControlledCorpusReviewDecision,
        reviewed_at: datetime | None = None,
    ) -> ControlledCorpusReviewAttestation:
        reviewed = _utc(reviewed_at)
        canonical = {
            "draft_id": draft.draft_id,
            "draft_sha256": draft.draft_sha256,
            "corpus_sha256": draft.corpus.corpus_sha256,
            "reviewer_id": normalize_reviewer_id(reviewer_id),
            "decision": decision.value,
            "reviewed_at": reviewed.isoformat(),
        }
        digest = _canonical_sha256(canonical)
        return cls(
            attestation_id=f"source-corpus-review-{digest[:24]}",
            attestation_sha256=digest,
            **canonical,
        )

    @model_validator(mode="after")
    def verify_digest(self) -> ControlledCorpusReviewAttestation:
        canonical = {
            "draft_id": self.draft_id,
            "draft_sha256": self.draft_sha256,
            "corpus_sha256": self.corpus_sha256,
            "reviewer_id": self.reviewer_id,
            "decision": self.decision.value,
            "reviewed_at": self.reviewed_at.astimezone(UTC).isoformat(),
        }
        digest = _canonical_sha256(canonical)
        if digest != self.attestation_sha256:
            raise ValueError("controlled corpus review digest does not match its contents")
        if self.attestation_id != f"source-corpus-review-{digest[:24]}":
            raise ValueError("controlled corpus review identifier does not match its digest")
        return self


class ControlledCorpusRelease(BaseModel):
    """Promotion-eligible corpus released only after independent current approvals."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    release_id: str = Field(pattern=r"^source-corpus-release-[0-9a-f]{24}$")
    draft: ControlledCorpusDraft
    attestations: tuple[ControlledCorpusReviewAttestation, ...]
    approved_reviewer_ids: tuple[str, ...]
    released_at: datetime
    release_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @classmethod
    def create(
        cls,
        *,
        draft: ControlledCorpusDraft,
        attestations: tuple[ControlledCorpusReviewAttestation, ...],
        released_at: datetime | None = None,
    ) -> ControlledCorpusRelease:
        ordered = tuple(sorted(attestations, key=lambda item: item.reviewer_id))
        reviewer_ids = tuple(item.reviewer_id for item in ordered)
        released = _utc(released_at)
        canonical = {
            "draft": draft.model_dump(mode="json"),
            "attestations": [item.model_dump(mode="json") for item in ordered],
            "approved_reviewer_ids": reviewer_ids,
            "released_at": released.isoformat(),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return cls(
            release_id=f"source-corpus-release-{digest[:24]}",
            release_sha256=digest,
            **canonical,
        )

    @model_validator(mode="after")
    def verify_contract(self) -> ControlledCorpusRelease:
        if len(self.attestations) < 2:
            raise ValueError("controlled corpus release requires two independent approvals")
        reviewer_ids = tuple(item.reviewer_id for item in self.attestations)
        if reviewer_ids != tuple(sorted(reviewer_ids)):
            raise ValueError("controlled corpus review attestations must use canonical order")
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise ValueError("a reviewer can attest to a controlled corpus only once")
        if self.draft.created_by in reviewer_ids:
            raise ValueError("the controlled corpus creator cannot approve their own labels")
        if any(
            item.decision != ControlledCorpusReviewDecision.APPROVE for item in self.attestations
        ):
            raise ValueError("a rejected controlled corpus draft cannot be released")
        for item in self.attestations:
            if (
                item.draft_id != self.draft.draft_id
                or item.draft_sha256 != self.draft.draft_sha256
                or item.corpus_sha256 != self.draft.corpus.corpus_sha256
            ):
                raise ValueError("controlled corpus approval is not bound to the released draft")
        if reviewer_ids != self.approved_reviewer_ids:
            raise ValueError("controlled corpus approved reviewer set is inconsistent")
        canonical = {
            "draft": self.draft.model_dump(mode="json"),
            "attestations": [item.model_dump(mode="json") for item in self.attestations],
            "approved_reviewer_ids": self.approved_reviewer_ids,
            "released_at": self.released_at.astimezone(UTC).isoformat(),
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        if digest != self.release_sha256:
            raise ValueError("controlled corpus release digest does not match its contents")
        if self.release_id != f"source-corpus-release-{digest[:24]}":
            raise ValueError("controlled corpus release identifier does not match its digest")
        return self


class ControlledBenchmarkCampaignManifest(BaseModel):
    """Reviewed corpus releases and exact engine revisions admitted to one comparison."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str = Field(pattern=r"^source-controlled-campaign-[0-9a-f]{24}$")
    releases: tuple[ControlledCorpusRelease, ...]
    policy: SourceBenchmarkAcceptancePolicy
    baseline_engine_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    candidate_engine_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @classmethod
    def create(
        cls,
        *,
        releases: tuple[ControlledCorpusRelease, ...],
        policy: SourceBenchmarkAcceptancePolicy,
        baseline_engine_revision: str,
        candidate_engine_revision: str,
    ) -> ControlledBenchmarkCampaignManifest:
        ordered = tuple(sorted(releases, key=lambda item: item.draft.corpus.corpus_id))
        canonical = {
            "releases": [item.model_dump(mode="json") for item in ordered],
            "policy": policy.model_dump(mode="json"),
            "baseline_engine_revision": baseline_engine_revision,
            "candidate_engine_revision": candidate_engine_revision,
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return cls(
            campaign_id=f"source-controlled-campaign-{digest[:24]}",
            manifest_sha256=digest,
            **canonical,
        )

    @model_validator(mode="after")
    def verify_contract(self) -> ControlledBenchmarkCampaignManifest:
        if not self.releases:
            raise ValueError("controlled benchmark campaign requires released corpora")
        if self.baseline_engine_revision == self.candidate_engine_revision:
            raise ValueError("controlled benchmark engine revisions must be distinct")
        corpus_ids = tuple(item.draft.corpus.corpus_id for item in self.releases)
        if corpus_ids != tuple(sorted(corpus_ids)):
            raise ValueError("controlled benchmark releases must use canonical corpus order")
        release_ids = [item.release_id for item in self.releases]
        if len(release_ids) != len(set(release_ids)) or len(corpus_ids) != len(set(corpus_ids)):
            raise ValueError("controlled benchmark campaign releases must be unique")
        if any(
            item.draft.corpus.kind != BenchmarkCorpusKind.CONTROLLED_LAB for item in self.releases
        ):
            raise ValueError("controlled benchmark campaigns cannot contain synthetic corpora")
        canonical = self.model_dump(mode="json", exclude={"campaign_id", "manifest_sha256"})
        digest = _canonical_sha256(canonical)
        if digest != self.manifest_sha256:
            raise ValueError("controlled benchmark manifest digest does not match its contents")
        if self.campaign_id != f"source-controlled-campaign-{digest[:24]}":
            raise ValueError("controlled benchmark campaign identifier does not match its digest")
        return self

    def suite(self) -> SourceBenchmarkSuite:
        entries = tuple(
            SourceBenchmarkSuiteEntry(
                corpus=release.draft.corpus,
                repository_id=release.draft.fixture.repository_id,
                source_revision=release.draft.fixture.revision,
                snapshot_sha256=release.draft.fixture.snapshot_sha256,
            )
            for release in self.releases
        )
        return SourceBenchmarkSuite.create(
            suite_id=f"{self.campaign_id}.suite",
            entries=entries,
        )


class ControlledBenchmarkCampaignEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_sha256s: tuple[str, ...]
    acceptance_bundle: SourceBenchmarkAcceptanceBundle
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @classmethod
    def create(
        cls,
        *,
        manifest: ControlledBenchmarkCampaignManifest,
        acceptance_bundle: SourceBenchmarkAcceptanceBundle,
    ) -> ControlledBenchmarkCampaignEvidence:
        canonical = {
            "campaign_id": manifest.campaign_id,
            "manifest_sha256": manifest.manifest_sha256,
            "release_sha256s": [item.release_sha256 for item in manifest.releases],
            "acceptance_bundle": acceptance_bundle.model_dump(mode="json"),
            "production_accuracy_claim_permitted": False,
        }
        return cls(evidence_sha256=_canonical_sha256(canonical), **canonical)

    @model_validator(mode="after")
    def verify_digest(self) -> ControlledBenchmarkCampaignEvidence:
        canonical = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if _canonical_sha256(canonical) != self.evidence_sha256:
            raise ValueError("controlled benchmark evidence digest does not match its contents")
        return self


class ControlledCorpusService:
    """Authenticate label authors/reviewers and release only independently approved corpora."""

    def __init__(self, governance_store: GovernanceStore) -> None:
        self.governance_store = governance_store

    def create_draft(
        self,
        *,
        snapshot: RepositorySnapshot,
        corpus: SourceBenchmarkCorpus,
        creator_id: str,
        creator_secret: str,
        now: datetime | None = None,
    ) -> ControlledCorpusDraft:
        creator = authenticate_identity(
            self.governance_store,
            creator_id,
            creator_secret,
            required_role="reviewer",
        )
        return ControlledCorpusDraft.create(
            snapshot=snapshot,
            corpus=corpus,
            created_by=creator.reviewer_id,
            created_at=now,
        )

    def attest(
        self,
        *,
        draft: ControlledCorpusDraft,
        reviewer_id: str,
        reviewer_secret: str,
        decision: ControlledCorpusReviewDecision,
        now: datetime | None = None,
    ) -> ControlledCorpusReviewAttestation:
        reviewer = authenticate_identity(
            self.governance_store,
            reviewer_id,
            reviewer_secret,
            required_role="reviewer",
        )
        if reviewer.reviewer_id == draft.created_by:
            raise ValueError("controlled corpus creators cannot review their own labels")
        return ControlledCorpusReviewAttestation.create(
            draft=draft,
            reviewer_id=reviewer.reviewer_id,
            decision=decision,
            reviewed_at=now,
        )

    def release(
        self,
        *,
        draft: ControlledCorpusDraft,
        attestations: tuple[ControlledCorpusReviewAttestation, ...],
        now: datetime | None = None,
    ) -> ControlledCorpusRelease:
        for attestation in attestations:
            identity = self.governance_store.get_identity(attestation.reviewer_id)
            if identity.status != "active" or "reviewer" not in identity.roles:
                raise ValueError(
                    f"controlled corpus reviewer {attestation.reviewer_id} is no longer eligible"
                )
        return ControlledCorpusRelease.create(
            draft=draft,
            attestations=attestations,
            released_at=now,
        )


class ControlledBenchmarkCampaignService:
    """Evaluate exact pre-produced reports; never run Source Hunt or make network calls."""

    def evaluate(
        self,
        *,
        manifest: ControlledBenchmarkCampaignManifest,
        baseline_reports: dict[str, SourceHuntReport],
        candidate_reports: dict[str, SourceHuntReport],
    ) -> ControlledBenchmarkCampaignEvidence:
        suite = manifest.suite()
        runner = SourceBenchmarkCampaignRunner()
        baseline = runner.run(
            label="baseline",
            engine_revision=manifest.baseline_engine_revision,
            suite=suite,
            reports=baseline_reports,
        )
        candidate = runner.run(
            label="candidate",
            engine_revision=manifest.candidate_engine_revision,
            suite=suite,
            reports=candidate_reports,
        )
        acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
            policy=manifest.policy,
            baseline=baseline,
            candidate=candidate,
        )
        bundle = SourceBenchmarkAcceptanceBundle.create(
            baseline=baseline,
            candidate=candidate,
            acceptance=acceptance,
        )
        return ControlledBenchmarkCampaignEvidence.create(
            manifest=manifest,
            acceptance_bundle=bundle,
        )


class ControlledCorpusStore:
    """Atomic immutable local persistence for reviewable corpus evidence."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def _save(self, *, relative: Path, payload: BaseModel) -> Path:
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(payload.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
        if destination.exists():
            if destination.read_text(encoding="utf-8") != content:
                raise ValueError("controlled corpus evidence path already contains different data")
            return destination
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        temporary.write_text(content, encoding="utf-8")
        try:
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                if destination.read_text(encoding="utf-8") != content:
                    raise ValueError(
                        "controlled corpus evidence path already contains different data"
                    ) from exc
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    def save_draft(self, draft: ControlledCorpusDraft) -> Path:
        return self._save(relative=Path("drafts") / f"{draft.draft_id}.json", payload=draft)

    def save_attestation(self, attestation: ControlledCorpusReviewAttestation) -> Path:
        name = f"{attestation.reviewer_id}-{attestation.attestation_id}.json"
        return self._save(
            relative=Path("reviews") / attestation.draft_id / name,
            payload=attestation,
        )

    def save_release(self, release: ControlledCorpusRelease) -> Path:
        return self._save(
            relative=Path("releases") / f"{release.release_id}.json",
            payload=release,
        )

    def save_evidence(self, evidence: ControlledBenchmarkCampaignEvidence) -> Path:
        return self._save(
            relative=Path("campaigns") / f"{evidence.campaign_id}.json",
            payload=evidence,
        )
