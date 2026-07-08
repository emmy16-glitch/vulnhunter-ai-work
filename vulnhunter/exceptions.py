"""Application-specific exceptions for VulnHunter AI."""


class VulnHunterError(Exception):
    """Base exception for expected VulnHunter errors."""


class ScopeValidationError(VulnHunterError):
    """Raised when a target cannot become an approved laboratory scope."""


class ScopeViolationError(ScopeValidationError):
    """Raised when a derived URL attempts to leave an approved scope."""
