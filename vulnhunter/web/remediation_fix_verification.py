"""Web configuration adapter for immutable remediation fix-verification receipts."""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings

from vulnhunter.findings import (
    FindingStore,
    RemediationFixVerificationService,
    RemediationFixVerificationStore,
)


def remediation_fix_verification_root() -> Path:
    configured = os.environ.get(
        "VULNHUNTER_REMEDIATION_FIX_ROOT",
        str(
            getattr(
                settings,
                "VULNHUNTER_REMEDIATION_FIX_ROOT",
                Path(settings.VULNHUNTER_TASK_GRAPH_ROOT) / "remediation-fix-verification",
            )
        ),
    )
    return Path(configured)


def remediation_fix_verification_store() -> RemediationFixVerificationStore:
    return RemediationFixVerificationStore(remediation_fix_verification_root())


def remediation_fix_verification_service() -> RemediationFixVerificationService:
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
    return RemediationFixVerificationService(
        finding_store=FindingStore(Path(finding_database)),
        receipt_store=remediation_fix_verification_store(),
    )


__all__ = [
    "remediation_fix_verification_root",
    "remediation_fix_verification_service",
    "remediation_fix_verification_store",
]
