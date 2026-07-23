"""Sensitive key names and value patterns used by the redaction service."""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_PAYMENT_DATA = "[REDACTED_PAYMENT_DATA]"

# These values are normalised before comparison by removing punctuation,
# underscores, spaces, and differences in letter casing.
SENSITIVE_KEY_NAMES = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "apikey",
        "xapikey",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "password",
        "passwd",
        "secret",
        "secretkey",
        "clientsecret",
        "privatekey",
        "session",
        "sessionid",
        "sessiontoken",
        "csrftoken",
        "xsrf",
        "xcsrftoken",
    }
)

# Matches HTTP authentication values such as:
# Bearer abc123
# Basic dXNlcjpwYXNzd29yZA==
AUTHORIZATION_VALUE_PATTERN = re.compile(
    r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
    flags=re.IGNORECASE,
)

# Matches a typical three-part JSON Web Token.
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\b"
)

# Matches common key=value or key: value secrets in text.
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b("
    r"api[_-]?key|"
    r"token|"
    r"access[_-]?token|"
    r"refresh[_-]?token|"
    r"id[_-]?token|"
    r"password|"
    r"passwd|"
    r"secret|"
    r"client[_-]?secret|"
    r"session(?:[_-]?id|[_-]?token)?|"
    r"csrf(?:[_-]?token)?"
    r")\b"
    r"(\s*[:=]\s*)"
    r"[^\s,;&]+",
    flags=re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)

# This is intentionally conservative. It detects long digit sequences that
# resemble payment-card numbers, including spaces or hyphens.
PAYMENT_CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
