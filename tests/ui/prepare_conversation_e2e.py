#!/usr/bin/env python3
"""Prepare an exact private authorization for browser conversation acceptance."""

# ruff: noqa: E402

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")

import django

django.setup()

from django.conf import settings

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.scope import validate_target
from vulnhunter.web.assessment_workflow import bind_nuclei_authorization


def main() -> int:
    target = validate_target(
        "http://10.0.11.34:8010/",
        resolver=lambda _hostname: ("10.0.11.34",),
    )
    now = datetime.now(UTC)
    store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
    store.initialize()
    record = issue_authorization(
        store,
        target,
        owner="admin-a",
        approved_by="browser-e2e-owner",
        purpose="Deterministic browser acceptance for the governed conversation workflow.",
        evidence_reference="browser-e2e-private-target",
        expires_at=now + timedelta(hours=2),
        limits=AuthorizationLimits(
            maximum_pages=2,
            maximum_depth=0,
            maximum_requests=10,
            minimum_request_delay_seconds=1,
        ),
        now=now,
    )
    bind_nuclei_authorization(
        store,
        authorization_id=record.authorization_id,
        approved_profiles=("passive",),
        private_network_approved=True,
        recorded_by="admin-a",
        approval_basis="Browser E2E exact passive target confirmation.",
        now=now,
    )
    readiness = Path(settings.VULNHUNTER_NUCLEI_READINESS_REPORT)
    readiness.parent.mkdir(parents=True, exist_ok=True)
    readiness.write_text(
        json.dumps(
            {
                "ready": True,
                "installed": True,
                "expected_engine": "v3.8.0",
                "expected_templates": "v10.4.5",
                "engine_pin_matches": True,
                "templates_pin_matches": True,
                "execution_enabled": True,
                "reason": "Deterministic browser acceptance readiness.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    key = Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_bytes(b"browser-e2e-worker-signing-key-2026")
    key.chmod(0o600)
    print(record.authorization_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
