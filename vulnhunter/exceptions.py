"""Application-specific exceptions for VulnHunter AI."""


class VulnHunterError(Exception):
    """Base exception for expected VulnHunter errors."""


class ScopeValidationError(VulnHunterError):
    """Raised when a target falls outside the permitted laboratory scope."""
