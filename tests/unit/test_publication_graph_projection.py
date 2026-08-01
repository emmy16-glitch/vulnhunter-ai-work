from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

from vulnhunter.publication import (
    PublicationCorrection,
    PublicationDestination,
    PublicationManifest,
    PublicationRevocation,
    PublicationStore,
    PublishedArtifactReference,
    ReleaseApproval,
    ReleaseRequest,
)
from vulnhunter.reports import FinalReportFormat
from vulnhunter.web.publication_service import publication_runtime_config
from vulnhunter.web.remediation_publication_projection import (
    project_publication_graph,
    publication_projection_for_finding,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _publication(
    *,
    report_id: str,
    manifest_id: str,
    published_at: datetime,
    correction_of: str | None = None,
) -> PublicationManifest:
    destination = PublicationDestination(
        destination_id="owner-release-vault",
        label="Owner-controlled release vault",
        root_sha256="a" * 64,
        allowed_formats=(FinalReportFormat.JSON,),
    )
    request = ReleaseRequest.create(
        source_report_id=report_id,
        source_manifest_id=manifest_id,
        source_report_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        source_finding_id="finding-01",
        destination=destination,
        formats=(FinalReportFormat.JSON,),
        requester_id="release-requester",
        requester_identity_sha256="d" * 64,
        reason="Release the exact independently reviewed report.",
        correction_of_publication_id=correction_of,
        created_at=published_at - timedelta(minutes=20),
        expires_at=published_at + timedelta(hours=1),
    )
    approval = ReleaseApproval.create(
        request=request,
        approver_id="release-approver",
        approver_identity_sha256="e" * 64,
        approved_at=published_at - timedelta(minutes=10),
    )
    artifact = PublishedArtifactReference(
        format=FinalReportFormat.JSON,
        source_filename=f"{report_id}.json",
        published_filename=f"{report_id}.json",
        content_type="application/json",
        sha256="f" * 64,
        size_bytes=42,
    )
    return PublicationManifest.create(
        request=request,
        approval=approval,
        artifacts=(artifact,),
        publisher_id="release-publisher",
        publisher_identity_sha256="1" * 64,
        published_at=published_at,
    )


def test_projection_tracks_published_correction_and_revocation(tmp_path):
    store = PublicationStore(
        tmp_path / "publication",
        signing_key=b"publication-projection-signing-key-material",
    )
    first = _publication(
        report_id="report-01",
        manifest_id="manifest-01",
        published_at=NOW,
    )
    store.save_publication(first)

    published = project_publication_graph(
        {
            "chat_stage": "final_report_generated_awaiting_release",
            "report_state": "generated_unreleased",
        },
        finding_id="finding-01",
        store=store,
    )
    assert published is not None
    assert published["publication_state"] == "published"
    assert published["chat_stage"] == "final_report_published"
    assert published["report_state"] == "published"
    assert published["publication_id"] == first.publication_id

    second = _publication(
        report_id="report-02",
        manifest_id="manifest-02",
        published_at=NOW + timedelta(hours=1),
        correction_of=first.publication_id,
    )
    store.save_publication(second)
    correction = PublicationCorrection.create(
        superseded_publication_id=first.publication_id,
        replacement=second,
        authority_id=second.publisher_id,
        authority_identity_sha256=second.publisher_identity_sha256,
        created_at=second.published_at,
    )
    store.save_correction(correction)

    history = publication_projection_for_finding("finding-01", store=store)
    assert history["publication_state"] == "published"
    assert [item["release_state"] for item in history["publication_history"]] == [
        "superseded",
        "published",
    ]
    assert (
        history["publication_history"][0]["correction"]["replacement_publication_id"]
        == second.publication_id
    )

    revocation = PublicationRevocation.create(
        publication=second,
        authority_id="release-revoker",
        authority_identity_sha256="2" * 64,
        reason="The published destination metadata requires correction.",
        revoked_at=NOW + timedelta(hours=2),
    )
    store.save_revocation(revocation)
    revoked = project_publication_graph(
        published,
        finding_id="finding-01",
        store=store,
    )
    assert revoked is not None
    assert revoked["publication_state"] == "revoked"
    assert revoked["chat_stage"] == "final_report_publication_revoked"
    assert revoked["report_state"] == "revoked"
    assert revoked["latest_publication"]["revocation"]["revocation_id"] == (
        revocation.revocation_id
    )


def test_projection_never_claims_release_when_store_is_unconfigured_or_tampered(tmp_path):
    unconfigured = project_publication_graph(
        {
            "chat_stage": "final_report_generated_awaiting_release",
            "report_state": "generated_unreleased",
        },
        finding_id="finding-01",
        store=None,
    )
    assert unconfigured is not None
    assert unconfigured["publication_state"] in {"unconfigured", "unreleased"}
    assert unconfigured["chat_stage"] == "final_report_generated_awaiting_release"

    store = PublicationStore(
        tmp_path / "publication",
        signing_key=b"publication-projection-signing-key-material",
    )
    publication = _publication(
        report_id="report-01",
        manifest_id="manifest-01",
        published_at=NOW,
    )
    store.save_publication(publication)
    path = store.root / "publications" / f"{publication.publication_id}.json"
    path.write_text(path.read_text().replace('"published"', '"revoked"', 1))

    tampered = project_publication_graph(
        {
            "chat_stage": "final_report_generated_awaiting_release",
            "report_state": "generated_unreleased",
        },
        finding_id="finding-01",
        store=store,
    )
    assert tampered is not None
    assert tampered["publication_state"] == "integrity_error"
    assert tampered["chat_stage"] == "publication_integrity_error"
    assert tampered["report_state"] == "blocked_publication_integrity"


def test_runtime_configuration_is_owner_private_and_explicit(tmp_path, settings):
    destination = tmp_path / "published"
    config = tmp_path / "publication.json"
    config.write_text(
        json.dumps(
            {
                "release_authority_ids": [
                    "release-requester",
                    "release-approver",
                    "release-publisher",
                ],
                "destinations": [
                    {
                        "destination_id": "owner-release-vault",
                        "label": "Owner-controlled release vault",
                        "kind": "local_directory",
                        "root": str(destination),
                        "allowed_formats": ["json", "html"],
                    }
                ],
            }
        )
    )
    os.chmod(config, 0o600)
    settings.VULNHUNTER_PUBLICATION_CONFIG_FILE = str(config)

    runtime = publication_runtime_config()

    assert runtime.release_authority_ids == frozenset(
        {"release-requester", "release-approver", "release-publisher"}
    )
    assert runtime.destinations[0].destination_id == "owner-release-vault"
    assert runtime.destinations[0].resolved_root() == destination.resolve()
    assert runtime.destinations[0].allowed_formats == (
        FinalReportFormat.JSON,
        FinalReportFormat.HTML,
    )
