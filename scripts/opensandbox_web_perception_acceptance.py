#!/usr/bin/env python3
"""Run one authorized passive browser-perception scan through real OpenSandbox."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.scope import validate_target
from vulnhunter.web_perception import (
    BrowserPerceptionPolicy,
    WebPerceptionActivationConfig,
    run_authorized_web_perception,
)

_FORBIDDEN_MARKERS = (
    "browser-form-secret",
    "browser-post-secret",
    "browser-api-secret",
    "browser-query-secret",
    "browser-ws-secret",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--release-registry", type=Path, required=True)
    parser.add_argument("--release-signature", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--domain", default="127.0.0.1:8080")
    parser.add_argument("--protocol", choices=("http", "https"), default="http")
    arguments = parser.parse_args()

    target = validate_target(arguments.target_url)
    backend = WebPerceptionActivationConfig.from_environment(
        {
            "VULNHUNTER_WEB_PERCEPTION_ENABLED": "true",
            "VULNHUNTER_WEB_PERCEPTION_PLAYWRIGHT_IMAGE": arguments.image,
            "VULNHUNTER_OPENSANDBOX_DOMAIN": arguments.domain,
            "VULNHUNTER_OPENSANDBOX_PROTOCOL": arguments.protocol,
            "VULNHUNTER_OPENSANDBOX_RELEASE_REGISTRY_FILE": str(arguments.release_registry),
            "VULNHUNTER_OPENSANDBOX_RELEASE_SIGNATURE_FILE": str(arguments.release_signature),
            "VULNHUNTER_OPENSANDBOX_RELEASE_PUBLIC_KEY_FILE": str(arguments.release_public_key),
        }
    ).build_backend()
    if backend is None:
        raise SystemExit("browser perception backend unexpectedly remained disabled")

    with tempfile.TemporaryDirectory(prefix="vulnhunter-web-perception-") as directory:
        store = AuthorizationStore.from_path(Path(directory) / "authorizations.db")
        store.initialize()
        record = issue_authorization(
            store,
            target,
            owner="private-lab-owner",
            approved_by="private-lab-approver",
            purpose="deterministic OpenSandbox browser-perception acceptance",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            limits=AuthorizationLimits(
                maximum_pages=5,
                maximum_depth=2,
                maximum_requests=50,
                minimum_request_delay_seconds=0,
            ),
        )
        result = run_authorized_web_perception(
            target,
            authorization_store=store,
            authorization_id=record.authorization_id,
            policy=BrowserPerceptionPolicy(
                maximum_pages=5,
                maximum_depth=2,
                maximum_requests=50,
                maximum_links_per_page=50,
                navigation_timeout_ms=10_000,
                settle_time_ms=1_000,
                minimum_request_delay_seconds=0,
            ),
            backend=backend,
        )

    payload = result.model_dump(mode="json")
    serialized = json.dumps(payload, sort_keys=True)
    for marker in _FORBIDDEN_MARKERS:
        if marker in serialized:
            raise SystemExit(f"browser perception leaked forbidden target content: {marker}")

    if result.evidence.blocked_mutating_requests < 1:
        raise SystemExit("browser perception did not block the deliberate POST request")
    if result.evidence.blocked_external_requests < 1:
        raise SystemExit("browser perception did not block the out-of-path request")
    if result.evidence.blocked_websockets < 1:
        raise SystemExit("browser perception did not block the deliberate WebSocket")
    if result.evidence.allowed_requests < 3:
        raise SystemExit("browser perception allowed too few read-only target requests")
    if not any(page.url.endswith("/app/profile") for page in result.evidence.pages):
        raise SystemExit("browser perception did not breadth-first map the profile page")

    node_kinds = {node.kind.value for node in result.graph.nodes}
    if not {"page", "endpoint", "form", "script"}.issubset(node_kinds):
        raise SystemExit("surface graph omitted required passive node classes")

    print(
        json.dumps(
            {
                "status": "accepted",
                "worker": "playwright",
                "worker_image": result.runtime_image,
                "release_id": result.runtime_release_id,
                "release_key_id": result.runtime_release_key_id,
                "plan_sha256": result.plan_sha256,
                "evidence_sha256": result.evidence_sha256,
                "graph_sha256": result.graph.graph_sha256,
                "pages": len(result.evidence.pages),
                "nodes": len(result.graph.nodes),
                "edges": len(result.graph.edges),
                "allowed_requests": result.evidence.allowed_requests,
                "blocked_external_requests": result.evidence.blocked_external_requests,
                "blocked_mutating_requests": result.evidence.blocked_mutating_requests,
                "blocked_websockets": result.evidence.blocked_websockets,
                "budget_exhausted": result.evidence.budget_exhausted,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
