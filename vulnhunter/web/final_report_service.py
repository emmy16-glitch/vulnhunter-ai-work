"""Web configuration for governed final remediation report generation."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from django.conf import settings

from vulnhunter.findings import FindingStore
from vulnhunter.reports import (
    BuiltInPdfRenderer,
    FinalRemediationReportError,
    FinalRemediationReportService,
    FinalReportStore,
    PdfRendererReadiness,
)
from vulnhunter.web.remediation_fix_verification import remediation_fix_verification_store
from vulnhunter.web.remediation_review_service import remediation_review_receipt_store
from vulnhunter.web.retest_service import retest_receipt_store
from vulnhunter.web.services import governance_store

_PDF_RENDERER_CONTRACT = b"vulnhunter-builtin-minimal-pdf-v1"


def final_report_root() -> Path:
    configured = os.environ.get(
        "VULNHUNTER_FINAL_REPORT_ROOT",
        str(
            getattr(
                settings,
                "VULNHUNTER_FINAL_REPORT_ROOT",
                Path(settings.VULNHUNTER_TASK_GRAPH_ROOT) / "final-reports",
            )
        ),
    )
    return Path(configured)


def final_report_signing_key() -> bytes:
    configured = os.environ.get(
        "VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE",
        str(getattr(settings, "VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE", "")),
    ).strip()
    if not configured:
        raise FinalRemediationReportError(
            "final report generation requires an owner-private signing-key file"
        )
    path = Path(configured).expanduser().resolve()
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise FinalRemediationReportError(
                "final report signing key must be a regular file"
            )
        if metadata.st_mode & 0o077:
            raise FinalRemediationReportError(
                "final report signing key must be owner-private"
            )
        key = path.read_bytes().strip()
    except FinalRemediationReportError:
        raise
    except OSError as exc:
        raise FinalRemediationReportError("final report signing key is unavailable") from exc
    if len(key) < 32:
        raise FinalRemediationReportError(
            "final report signing key must contain at least 32 bytes"
        )
    return key


def final_report_pdf_readiness() -> PdfRendererReadiness:
    raw = os.environ.get(
        "VULNHUNTER_FINAL_REPORT_PDF_ENABLED",
        str(getattr(settings, "VULNHUNTER_FINAL_REPORT_PDF_ENABLED", "false")),
    )
    enabled = raw.strip().casefold() in {"1", "true", "yes", "on"}
    return PdfRendererReadiness(
        enabled=enabled,
        renderer_id="builtin-minimal-pdf",
        renderer_version="1.0",
        renderer_sha256=hashlib.sha256(_PDF_RENDERER_CONTRACT).hexdigest(),
    )


def final_report_store() -> FinalReportStore:
    return FinalReportStore(final_report_root(), signing_key=final_report_signing_key())


def final_report_service() -> FinalRemediationReportService:
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
    readiness = final_report_pdf_readiness()
    return FinalRemediationReportService(
        finding_store=FindingStore(Path(finding_database)),
        governance_store=governance_store(),
        fix_verification_store=remediation_fix_verification_store(),
        retest_receipt_store=retest_receipt_store(),
        review_receipt_store=remediation_review_receipt_store(),
        report_store=final_report_store(),
        pdf_renderer=BuiltInPdfRenderer(readiness),
    )


__all__ = [
    "final_report_pdf_readiness",
    "final_report_root",
    "final_report_service",
    "final_report_signing_key",
    "final_report_store",
]
