"""Project signed publication state into remediation graph and workspace payloads."""

from __future__ import annotations

from vulnhunter.publication import PublicationStore, PublicationStoreError
from vulnhunter.web.publication_service import publication_store_if_configured


def _publication_payload(store: PublicationStore, publication) -> dict[str, object]:
    status = store.status(publication.publication_id)
    payload: dict[str, object] = {
        "publication_id": publication.publication_id,
        "publication_sha256": publication.fingerprint(),
        "source_report_id": publication.source_report_id,
        "source_manifest_id": publication.source_manifest_id,
        "destination_id": publication.destination.destination_id,
        "destination_label": publication.destination.label,
        "formats": [item.format.value for item in publication.artifacts],
        "requester_id": publication.requester_id,
        "approver_id": publication.approver_id,
        "publisher_id": publication.publisher_id,
        "correction_of_publication_id": publication.correction_of_publication_id,
        "published_at": publication.published_at.isoformat(),
        "release_state": status,
    }
    if status == "superseded":
        correction = store.load_correction(publication.publication_id)
        payload["correction"] = {
            "correction_id": correction.correction_id,
            "replacement_publication_id": correction.replacement_publication_id,
            "replacement_publication_sha256": correction.replacement_publication_sha256,
            "authority_id": correction.authority_id,
            "created_at": correction.created_at.isoformat(),
        }
    elif status == "revoked":
        revocation = store.load_revocation(publication.publication_id)
        payload["revocation"] = {
            "revocation_id": revocation.revocation_id,
            "authority_id": revocation.authority_id,
            "reason": revocation.reason,
            "revoked_at": revocation.revoked_at.isoformat(),
        }
    return payload


def publication_projection_for_finding(
    finding_id: str,
    *,
    store: PublicationStore | None = None,
) -> dict[str, object]:
    """Return only integrity-verified publication data for one finding."""

    resolved = store if store is not None else publication_store_if_configured()
    if resolved is None:
        return {
            "publication_state": "unconfigured",
            "publication_history": [],
            "latest_publication": None,
        }
    try:
        history = [
            _publication_payload(resolved, item)
            for item in resolved.list_publications_for_finding(finding_id)
        ]
    except PublicationStoreError:
        return {
            "publication_state": "integrity_error",
            "publication_history": [],
            "latest_publication": None,
        }
    latest = history[-1] if history else None
    return {
        "publication_state": (
            str(latest.get("release_state")) if isinstance(latest, dict) else "unreleased"
        ),
        "publication_history": history,
        "latest_publication": latest,
    }


def project_publication_graph(
    graph: dict[str, object] | None,
    *,
    finding_id: str,
    store: PublicationStore | None = None,
) -> dict[str, object] | None:
    """Enrich a graph status payload without changing task-node authority."""

    if graph is None:
        return None
    payload = dict(graph)
    projection = publication_projection_for_finding(finding_id, store=store)
    payload.update(projection)
    latest = projection.get("latest_publication")
    latest = latest if isinstance(latest, dict) else None
    state = str(projection.get("publication_state") or "unreleased")
    if latest is not None:
        payload["publication_id"] = latest.get("publication_id")
        payload["publication_sha256"] = latest.get("publication_sha256")
        payload["publication_destination_id"] = latest.get("destination_id")
    if state == "published":
        payload["chat_stage"] = "final_report_published"
        payload["report_state"] = "published"
    elif state == "revoked":
        payload["chat_stage"] = "final_report_publication_revoked"
        payload["report_state"] = "revoked"
    elif state == "superseded":
        payload["chat_stage"] = "final_report_publication_superseded"
        payload["report_state"] = "superseded"
    elif state == "integrity_error":
        payload["chat_stage"] = "publication_integrity_error"
        payload["report_state"] = "blocked_publication_integrity"
    return payload


__all__ = [
    "project_publication_graph",
    "publication_projection_for_finding",
]
