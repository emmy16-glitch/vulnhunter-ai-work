"""Web configuration adapter for governed retest services and receipt storage."""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings

from vulnhunter.findings import FindingStore, GovernedRetestService, RetestReceiptStore


def retest_receipt_root() -> Path:
    configured = os.environ.get(
        "VULNHUNTER_RETEST_RECEIPT_ROOT",
        str(
            getattr(
                settings,
                "VULNHUNTER_RETEST_RECEIPT_ROOT",
                Path(settings.VULNHUNTER_TASK_GRAPH_ROOT) / "retest-receipts",
            )
        ),
    )
    return Path(configured)


def retest_receipt_store() -> RetestReceiptStore:
    return RetestReceiptStore(retest_receipt_root())


def governed_retest_service() -> GovernedRetestService:
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
    return GovernedRetestService(
        finding_store=FindingStore(Path(finding_database)),
        receipt_store=retest_receipt_store(),
    )


__all__ = [
    "governed_retest_service",
    "retest_receipt_root",
    "retest_receipt_store",
]
