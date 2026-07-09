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


class UnsafeRequestHeaderError(TransportPolicyError):
    """Raised when a caller attempts to override a protected HTTP header."""


class TransportRequestError(TransportPolicyError):
    """Raised when an HTTP request fails in a controlled manner."""


class MachineLearningError(VulnHunterError):
    """Base exception for reviewed-dataset and model operations."""


class InsufficientTrainingDataError(MachineLearningError):
    """Raised when reviewed labels cannot support a defensible model."""


class ModelArtifactError(MachineLearningError):
    """Raised when a model artifact is malformed, unsafe, or incompatible."""


class BenchmarkError(VulnHunterError):
    """Base exception for controlled local benchmark operations."""


class BenchmarkManifestError(BenchmarkError):
    """Raised when benchmark provenance is missing, inconsistent, or tampered."""


class AuthorizationError(VulnHunterError):
    """Base exception for explicit target-authorization failures."""


class AuthorizationNotFoundError(AuthorizationError):
    """Raised when an authorization record cannot be found."""


class AuthorizationIntegrityError(AuthorizationError):
    """Raised when a stored authorization record fails integrity checks."""


class AuthorizationPolicyError(AuthorizationError):
    """Raised when a requested scan exceeds an authorization boundary."""


class LoopError(VulnHunterError):
    """Base exception for bounded engineering-loop failures."""


class LoopNotFoundError(LoopError):
    """Raised when an orchestration loop cannot be found."""


class LoopIntegrityError(LoopError):
    """Raised when loop manifests, evidence, or audit events are invalid."""


class LoopPolicyError(LoopError):
    """Raised when a loop action violates an explicit boundary."""


class LoopStateError(LoopError):
    """Raised when an action is invalid for the current loop state."""


class LoopBudgetError(LoopError):
    """Raised when an iteration, time, token, or cost ceiling is exceeded."""


class LoopEvaluationError(LoopError):
    """Raised when deterministic proof collection cannot be completed."""


class ResearchError(VulnHunterError):
    """Base exception for transactional autoresearch failures."""


class ResearchNotFoundError(ResearchError):
    """Raised when an experiment record cannot be found."""


class ResearchIntegrityError(ResearchError):
    """Raised when experiment state, evidence, or provenance was altered."""


class ResearchBoundaryError(ResearchError):
    """Raised when a candidate attempts to cross an immutable resource boundary."""


class ResearchStateError(ResearchError):
    """Raised when an experiment action is invalid for its current state."""


class ResearchEvaluationError(ResearchError):
    """Raised when trusted experiment evaluation cannot be completed."""


class ResearchGitError(ResearchError):
    """Raised when transactional Git worktree operations fail safely."""


class UnattendedError(VulnHunterError):
    """Base exception for unattended-operations control-plane failures."""


class UnattendedNotFoundError(UnattendedError):
    """Raised when a permission manifest or run cannot be found."""


class UnattendedIntegrityError(UnattendedError):
    """Raised when unattended state, evidence, or event history was altered."""


class UnattendedPolicyError(UnattendedError):
    """Raised when a requested unattended action exceeds its permission manifest."""


class UnattendedStateError(UnattendedError):
    """Raised when an unattended action is invalid for the current lifecycle state."""


class UnattendedExecutionError(UnattendedError):
    """Raised when a fixed command cannot execute safely."""
