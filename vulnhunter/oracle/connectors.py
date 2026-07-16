"""Disabled-by-default pentest-ai Machine Oracle connector contract."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from vulnhunter.actions.models import sha256_json
from vulnhunter.oracle.models import OracleResponse, ProofCapsule


class PentestAiConnectorError(RuntimeError):
    pass


class OracleResponseAuthenticator(Protocol):
    """Authenticator contract for isolated external verifier responses."""

    def authenticate(self, capsule: ProofCapsule, response: OracleResponse) -> bool:
        """Return true only when the response is authenticated by a trusted verifier."""


class DurableResponseReplayLedger:
    """Atomic response-hash replay ledger using digest-derived paths."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def claim(self, response_hash: str) -> None:
        path = self._path_for_digest(response_hash)
        payload = sha256_json({"response_hash": response_hash})
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise PentestAiConnectorError("verifier response replay rejected") from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _path_for_digest(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise PentestAiConnectorError("response digest is malformed")
        path = (self.root / f"{digest}.claimed").resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise PentestAiConnectorError("response digest path escapes replay ledger") from exc
        if path.exists():
            raise PentestAiConnectorError("verifier response replay rejected")
        return path


class PentestAiConnector:
    def __init__(
        self,
        *,
        enabled: bool = False,
        trusted_verifier_identities: tuple[str, ...] = (),
        supported_versions: tuple[str, ...] = (),
        authenticator: OracleResponseAuthenticator | None = None,
        replay_ledger: DurableResponseReplayLedger | None = None,
    ) -> None:
        self.enabled = enabled
        self.trusted_verifier_identities = trusted_verifier_identities
        self.supported_versions = supported_versions
        self.authenticator = authenticator
        self.replay_ledger = replay_ledger

    def submit(self, capsule: ProofCapsule) -> None:
        if not self.enabled:
            raise PentestAiConnectorError("pentest-ai connector is disabled by default")
        raise PentestAiConnectorError(
            f"live pentest-ai connector activation is not available for {capsule.capsule_id}"
        )

    def validate_response(self, capsule: ProofCapsule, response: OracleResponse) -> OracleResponse:
        if response.capsule_sha256 != capsule.capsule_hash():
            raise PentestAiConnectorError("verifier response is bound to another capsule")
        if response.expected_hash() != response.response_hash:
            raise PentestAiConnectorError("verifier response hash does not match")
        if response.verifier_identity not in self.trusted_verifier_identities:
            raise PentestAiConnectorError("unknown verifier identity")
        if response.verifier_version not in self.supported_versions:
            raise PentestAiConnectorError("unsupported verifier version")
        if self.authenticator is None:
            raise PentestAiConnectorError("external verifier response authenticator is required")
        if not self.authenticator.authenticate(capsule, response):
            raise PentestAiConnectorError("external verifier response authentication failed")
        if self.replay_ledger is None:
            raise PentestAiConnectorError("durable response replay ledger is required")
        self.replay_ledger.claim(response.response_hash)
        return response
