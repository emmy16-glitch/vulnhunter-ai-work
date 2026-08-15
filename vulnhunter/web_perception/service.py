"""Authorization-gated entry point for passive browser perception."""

from __future__ import annotations

from vulnhunter.authorization.service import validate_scan_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.scope.models import ApprovedTarget
from vulnhunter.web_perception.backend import OpenSandboxWebPerceptionBackend
from vulnhunter.web_perception.models import BrowserPerceptionPolicy, WebPerceptionResult


def run_authorized_web_perception(
    target: ApprovedTarget,
    *,
    authorization_store: AuthorizationStore,
    authorization_id: str,
    policy: BrowserPerceptionPolicy,
    backend: OpenSandboxWebPerceptionBackend,
) -> WebPerceptionResult:
    """Validate existing scan authority before any browser sandbox is created."""

    validate_scan_authorization(
        authorization_store,
        authorization_id,
        target,
        maximum_pages=policy.maximum_pages,
        maximum_depth=policy.maximum_depth,
        maximum_requests=policy.maximum_requests,
        request_delay_seconds=policy.minimum_request_delay_seconds,
    )
    authorization_store.append_event(
        authorization_id,
        "scan_started",
        {
            "collector": "playwright_passive_perception",
            "target_url": target.normalized_url,
        },
    )
    try:
        result = backend.execute(
            target,
            authorization_id=authorization_id,
            policy=policy,
        )
    except (Exception, KeyboardInterrupt) as exc:
        authorization_store.append_event(
            authorization_id,
            "scan_failed",
            {
                "collector": "playwright_passive_perception",
                "reason": str(exc),
            },
        )
        raise

    authorization_store.append_event(
        authorization_id,
        "scan_completed",
        {
            "collector": "playwright_passive_perception",
            "target_url": target.normalized_url,
            "pages_visited": len(result.evidence.pages),
            "graph_sha256": result.graph.graph_sha256,
            "evidence_sha256": result.evidence_sha256,
        },
    )
    return result
