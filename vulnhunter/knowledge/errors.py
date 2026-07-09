"""Expected failures for the controlled knowledge-ingestion system."""


class KnowledgeError(Exception):
    """Base exception for expected knowledge-system failures."""


class KnowledgeStoreError(KnowledgeError):
    """Raised when the knowledge store is unavailable or malformed."""


class DuplicateSourceError(KnowledgeError):
    """Raised when an identical source is already registered."""


class SourceNotFoundError(KnowledgeError):
    """Raised when a requested source manifest does not exist."""


class UnsafeSourcePathError(KnowledgeError):
    """Raised when a source path is unsafe to ingest."""


class ReviewRequiredError(KnowledgeError):
    """Raised when publication is attempted before explicit human approval."""
