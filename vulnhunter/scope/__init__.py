"""Approved-target and derived-URL scope validation."""

from vulnhunter.scope.guard import validate_scoped_url
from vulnhunter.scope.models import ApprovedTarget, ScopedUrl
from vulnhunter.scope.validator import validate_target

__all__ = [
    "ApprovedTarget",
    "ScopedUrl",
    "validate_scoped_url",
    "validate_target",
]
