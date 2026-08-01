"""Web configuration for signed independent remediation review receipts."""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings

from vulnhunter.findings import (
    FindingStore,
    RemediationReviewReceiptStore,
    RemediationReviewService,
)
from vulnhunter.web.remediation_fix_verification import (
    remediation_fix_verification_store,
)
from vulnhunter.web.retest_service import retest_receipt_store
from vulnhunter.web.services import governance_store


def remediation_review_root() -> Path:
    configured = os.environ.get(
        "VULNHUNTER_REMEDIATION_REVIEW_ROOT",
        str(
            getattr(
                settings,
                "VULNHUNTER_REMEDIATION_REVIEW_ROOT",
                Path(settings.VULNHUNTER_TASK_GRAPH_ROOT) / "remediation-reviews",
            )
        ),
    )
    return Path(configured)


def remediation_review_receipt_store() -> RemediationReviewReceiptStore:
    return RemediationReviewReceiptStore(
        remediation_review_root(),
        signing_key=str(settings.SECRET_KEY).encode("utf-8"),
    )


def remediation_review_service() -> RemediationReviewService:
    finding_database = os.environ.get(
        "VULNHUNTER_FINDING_DATABASE",
        str(
            getattr(
                settings,
                "VULNHUNTER_FINDING_DATABASE",
                settings.BASE_DIR / ".local" / "findings" / "findings.sqlite3",
            )
        ),
    )
    return RemediationReviewService(
        finding_store=FindingStore(Path(finding_database)),
        governance_store=governance_store(),
        fix_verification_store=remediation_fix_verification_store(),
        retest_receipt_store=retest_receipt_store(),
        receipt_store=remediation_review_receipt_store(),
    )


__all__ = [
    "remediation_review_receipt_store",
    "remediation_review_root",
    "remediation_review_service",
]
