"""Errors raised by the independent web-verification boundary."""


class WebVerificationError(RuntimeError):
    """Base error for independent web verification."""


class WebVerificationContractError(WebVerificationError):
    """Raised when source evidence or verifier bindings fail closed."""
