from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from governance_test_support import add_identity, make_governance_store, prepare_identities

from vulnhunter.publication import (
    PublicationCorrection,
    PublicationDestinationConfig,
    PublicationManifest,
    PublicationRevocation,
    PublicationStore,
    PublishedArtifactReference,
    ReleaseApproval,
    ReleaseRequest,
)
from vulnhunter.publication.operations import (
    assess_publication_readiness,
    audit_publication_state,
    inspect_publication_operations,
    recover_publication_operations,
)
from vulnhunter.reports import FinalReportFormat
from vulnhunter.web.publication_service import publication_deployment_readiness

NOW = datetime(2026, 8, 1, 14, 0, tzinfo=UTC)
AUTHORITIES = {
    "release-requester": "release-requester-secret",
    "release-approver": "release-approver-secret",
    "release-publisher": "release-publisher-secret",
    "release-revoker": "release-revoker-secret",
}


def _world(tmp_path: Path):
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    for actor_id, secret in AUTHORITIES.items():
        add_identity(governance, actor_id, secret, ("campaign_admin",))
    store = PublicationStore(
        tmp_path / "publication-state",
        signing_key=b"publication-operations-signing-key-material",
    )
    root = tmp_path / "published"
    root.mkdir(mode=0o700)
    destination = PublicationDestinationConfig(
        destination_id="owner-release-vault",
        label="Owner-controlled local release vault",
        root=root,
        allowed_formats=(FinalReportFormat.JSON,),
    )
    return governance, store, destination, root


def _publication(
    store: PublicationStore,
    destination: PublicationDestinationConfig,
    *,
    marker: str,
    created_at: datetime,
    correction_of: str | None = None,
):
    raw = (f'{{"marker":"{marker}"}}\n').encode()
    request = ReleaseRequest.create(
        source_report_id=f"report-{marker}",
        source_manifest_id=f"manifest-{marker}",
        source_report_sha256=marker[0] * 64,
        source_manifest_sha256=marker[-1] * 64,
        source_finding_id="finding-01",
        destination=destination.policy(),
        formats=(FinalReportFormat.JSON,),
        requester_id="release-requester",
        requester_identity_sha256="a" * 64,
        reason=f"Release signed report {marker}.",
        correction_of_publication_id=correction_of,
        created_at=created_at,
        expires_at=created_at + timedelta(days=1),
    )
    approval = ReleaseApproval.create(
        request=request,
        approver_id="release-approver",
        approver_identity_sha256="b" * 64,
        approved_at=created_at + timedelta(minutes=1),
    )
    artifact = PublishedArtifactReference(
        format=FinalReportFormat.JSON,
        source_filename=f"report-{marker}.json",
        published_filename=f"report-{marker}.json",
        content_type="application/json",
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )
    publication = PublicationManifest.create(
        request=request,
        approval=approval,
        artifacts=(artifact,),
        publisher_id="release-publisher",
        publisher_identity_sha256="c" * 64,
        published_at=created_at + timedelta(minutes=2),
    )
    store.save_request(request)
    store.save_approval(approval)
    store.save_publication(publication)
    directory = destination.resolved_root() / publication.publication_id
    directory.mkdir(mode=0o700)
    artifact_path = directory / artifact.published_filename
    artifact_path.write_bytes(raw)
    artifact_path.chmod(0o600)
    return publication, raw


def test_publication_readiness_verifies_authorities_destinations_and_state(tmp_path) -> None:
    governance, store, destination, root = _world(tmp_path)
    report = assess_publication_readiness(
        governance,
        store,
        (destination,),
        frozenset(AUTHORITIES),
        probe_writes=True,
        minimum_free_bytes=1,
    )
    assert report.ready is True
    assert report.status == "ok"
    assert report.state_counts == {
        "requests": 0,
        "approvals": 0,
        "publications": 0,
        "corrections": 0,
        "revocations": 0,
    }
    assert not tuple(root.glob(".publication-preflight-*"))

    root.chmod(0o750)
    blocked = assess_publication_readiness(
        governance,
        store,
        (destination,),
        frozenset(AUTHORITIES),
        minimum_free_bytes=1,
    )
    assert blocked.ready is False
    assert any("not owner-private" in item for item in blocked.blockers)


def test_publication_readiness_rejects_missing_or_unqualified_authority(tmp_path) -> None:
    governance, store, destination, _root = _world(tmp_path)
    add_identity(
        governance,
        "ordinary-reviewer",
        "ordinary-reviewer-secret",
        ("reviewer",),
    )
    report = assess_publication_readiness(
        governance,
        store,
        (destination,),
        frozenset({*AUTHORITIES, "ordinary-reviewer", "missing-authority"}),
        minimum_free_bytes=1,
    )
    assert report.ready is False
    assert any("does not exist" in item for item in report.blockers)
    assert any("lacks campaign_admin" in item for item in report.blockers)


def test_safe_recovery_restores_signed_metadata_and_removes_stale_staging(tmp_path) -> None:
    _governance, store, destination, root = _world(tmp_path)
    first, _ = _publication(
        store,
        destination,
        marker="aa",
        created_at=NOW,
    )
    second, _ = _publication(
        store,
        destination,
        marker="bb",
        created_at=NOW + timedelta(hours=1),
        correction_of=first.publication_id,
    )
    correction = PublicationCorrection.create(
        superseded_publication_id=first.publication_id,
        replacement=second,
        authority_id=second.publisher_id,
        authority_identity_sha256=second.publisher_identity_sha256,
        created_at=NOW + timedelta(hours=1, minutes=3),
    )
    revocation = PublicationRevocation.create(
        publication=second,
        authority_id="release-revoker",
        authority_identity_sha256="d" * 64,
        reason="Independent governance review revoked the corrected release.",
        revoked_at=NOW + timedelta(hours=2),
    )
    store.save_correction(correction)
    store.save_revocation(revocation)

    staging = root / ".publication-crashed-operation"
    staging.mkdir(mode=0o700)
    stale_timestamp = (NOW - timedelta(hours=2)).timestamp()
    os.utime(staging, (stale_timestamp, stale_timestamp))

    inspected = inspect_publication_operations(
        store,
        (destination,),
        now=NOW,
        stale_after=timedelta(hours=1),
    )
    codes = {item.code for item in inspected.issues}
    assert "stale_staging_directory" in codes
    assert "missing_publication_notice" in codes
    assert "missing_correction_notice" in codes
    assert "missing_revocation_notice" in codes

    repaired = recover_publication_operations(
        store,
        (destination,),
        apply_safe=True,
        now=NOW,
        stale_after=timedelta(hours=1),
    )
    assert repaired.ready is True
    assert repaired.issues == ()
    assert not staging.exists()
    assert (root / first.publication_id / "publication-manifest.json").is_file()
    assert (root / first.publication_id / "correction.json").is_file()
    assert (root / second.publication_id / "publication-manifest.json").is_file()
    assert (root / second.publication_id / "revocation.json").is_file()
    assert audit_publication_state(store).counts["publications"] == 2


def test_safe_recovery_never_overwrites_modified_artifact(tmp_path) -> None:
    _governance, store, destination, root = _world(tmp_path)
    publication, _ = _publication(
        store,
        destination,
        marker="cc",
        created_at=NOW,
    )
    directory = root / publication.publication_id
    (directory / "publication-manifest.json").write_bytes(
        store.signed_envelope_bytes("publications", publication)
    )
    artifact_path = directory / publication.artifacts[0].published_filename
    artifact_path.write_bytes(b"modified\n")

    report = recover_publication_operations(
        store,
        (destination,),
        apply_safe=True,
        now=NOW,
    )
    assert any(item.code == "publication_artifact_mismatch" for item in report.blockers)
    assert artifact_path.read_bytes() == b"modified\n"


@pytest.mark.django_db
def test_publication_deployment_readiness_distinguishes_disabled_and_partial(
    settings,
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE", raising=False)
    monkeypatch.delenv("VULNHUNTER_PUBLICATION_CONFIG_FILE", raising=False)
    settings.VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE = ""
    settings.VULNHUNTER_PUBLICATION_CONFIG_FILE = ""
    disabled = publication_deployment_readiness()
    assert disabled.status == "disabled"
    assert disabled.enabled is False

    key = tmp_path / "publication.key"
    key.write_bytes(b"x" * 64)
    key.chmod(0o600)
    settings.VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE = str(key)
    partial = publication_deployment_readiness()
    assert partial.status == "failed"
    assert partial.enabled is True
    assert "partial" in partial.blockers[0]
