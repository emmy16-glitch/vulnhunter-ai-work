"""Errors for the bounded adaptive web-hunter coordinator."""

from vulnhunter.exceptions import VulnHunterError


class WebHunterError(VulnHunterError):
    """Base error for advisory web-hunter processing."""


class WebHunterContractError(WebHunterError):
    """Raised when graph, evidence, or hunter output fails an integrity contract."""


class WebHunterExecutionError(WebHunterError):
    """Raised when a specialist hunter fails instead of returning advisory output."""
