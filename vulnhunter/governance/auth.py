"""Local secret hashing and authentication for governance identities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from vulnhunter.exceptions import GovernanceAuthenticationError

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def validate_secret(secret: str) -> str:
    """Validate a local governance secret without storing or logging it."""
    if not isinstance(secret, str):
        raise GovernanceAuthenticationError("A reviewer secret is required.")
    if len(secret) < 12:
        raise GovernanceAuthenticationError("Reviewer secrets must contain at least 12 characters.")
    if len(secret) > 1_024:
        raise GovernanceAuthenticationError("Reviewer secrets are too long.")
    return secret


def hash_secret(secret: str, *, salt: bytes | None = None) -> tuple[str, str]:
    """Return a random salt and scrypt hash suitable for local authentication."""
    validated = validate_secret(secret)
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        validated.encode("utf-8"),
        salt=actual_salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return _encode(actual_salt), _encode(digest)


def verify_secret(secret: str, *, encoded_salt: str, encoded_hash: str) -> bool:
    """Verify a secret using constant-time comparison."""
    try:
        actual_salt = _decode(encoded_salt)
        expected = _decode(encoded_hash)
        validated = validate_secret(secret)
    except (ValueError, GovernanceAuthenticationError):
        return False

    candidate = hashlib.scrypt(
        validated.encode("utf-8"),
        salt=actual_salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=len(expected),
    )
    return hmac.compare_digest(candidate, expected)
