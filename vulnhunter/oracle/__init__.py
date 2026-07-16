"""Machine Oracle proof-capsule and verification contracts."""

from vulnhunter.oracle.connectors import (
    DurableResponseReplayLedger,
    OracleResponseAuthenticator,
    PentestAiConnector,
    PentestAiConnectorError,
)
from vulnhunter.oracle.models import (
    FindingClaim,
    OracleConflict,
    OracleResponse,
    OracleSession,
    OracleSessionEvent,
    OracleSessionStatus,
    OracleVerdict,
    ProofCapsule,
    StructuredObservation,
    VerificationStrategy,
)
from vulnhunter.oracle.service import OracleVerificationError, OracleVerifier
from vulnhunter.oracle.store import OracleStore, OracleStoreError

__all__ = [
    "FindingClaim",
    "DurableResponseReplayLedger",
    "OracleConflict",
    "OracleResponse",
    "OracleResponseAuthenticator",
    "OracleSession",
    "OracleSessionEvent",
    "OracleSessionStatus",
    "OracleStore",
    "OracleStoreError",
    "OracleVerdict",
    "OracleVerificationError",
    "OracleVerifier",
    "PentestAiConnector",
    "PentestAiConnectorError",
    "ProofCapsule",
    "StructuredObservation",
    "VerificationStrategy",
]
