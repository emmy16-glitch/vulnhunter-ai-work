#!/usr/bin/env python3
"""Prepare an exact private authorization for browser conversation acceptance."""

# Django must be configured before importing application models in this standalone seed.
# ruff: noqa: E402, I001

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")

import django

django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.scope import validate_target
from vulnhunter.web.assessment_workflow import bind_nuclei_authorization
from vulnhunter.web.models import WebUserMapping


USERNAME = "conversation-e2e"
IDENTITY_ID = "conversation-e2e-user"
PASSWORD = "Vh-Conversation-E2E-2026!"


def prepare_user() -> None:
    model = get_user_model()
    user, _ = model.objects.get_or_create(username=USERNAME)
    user.set_password(PASSWORD)
    user.is_active = True
    user.is_staff = False
    user.save()
    WebUserMapping.objects.update_or_create(
        user=user,
        defaults={
            "governance_identity_id": IDENTITY_ID,
            "product_roles": ["campaign-operator"],
        },
    )


def main() -> int:
    prepare_user()
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
        owner=IDENTITY_ID,
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
        recorded_by=IDENTITY_ID,
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
