"""Application-specific exceptions for VulnHunter AI."""


class VulnHunterError(Exception):
    """Base exception for expected VulnHunter errors."""


class ScopeValidationError(VulnHunterError):
    """Raised when a target cannot become an approved laboratory scope."""


class ScopeViolationError(ScopeValidationError):
    """Raised when a derived URL attempts to leave an approved scope."""


class TransportPolicyError(VulnHunterError):
    """Base exception for controlled HTTP transport-policy failures."""


class HttpMethodNotAllowedError(TransportPolicyError):
    """Raised when code attempts to use a prohibited HTTP method."""


class RequestCancelledError(TransportPolicyError):
    """Raised when a scan or request has been cancelled."""


class RequestBudgetExceededError(TransportPolicyError):
    """Raised when a scan has consumed its permitted request count."""


class RedirectLimitExceededError(TransportPolicyError):
    """Raised when a response exceeds the approved redirect limit."""


class ResponseTooLargeError(TransportPolicyError):
    """Raised before a response body exceeds the configured size limit."""
