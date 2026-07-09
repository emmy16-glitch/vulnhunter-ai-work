"""Explicit authorization records for bounded laboratory scans."""

from vulnhunter.authorization.models import (
    AuthorizationDecision,
    AuthorizationEvent,
    AuthorizationLimits,
    AuthorizationRecord,
    authorization_record_sha256,
)
from vulnhunter.authorization.service import (
    issue_authorization,
    validate_scan_authorization,
)
from vulnhunter.authorization.store import AuthorizationStore

__all__ = [
    "AuthorizationDecision",
    "AuthorizationEvent",
    "AuthorizationLimits",
    "AuthorizationRecord",
    "AuthorizationStore",
    "authorization_record_sha256",
    "issue_authorization",
    "validate_scan_authorization",
]
