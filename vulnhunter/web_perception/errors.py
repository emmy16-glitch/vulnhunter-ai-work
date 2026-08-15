"""Errors raised by passive browser perception."""

from vulnhunter.exceptions import VulnHunterError


class WebPerceptionError(VulnHunterError):
    """Base error for fail-closed passive browser perception."""
