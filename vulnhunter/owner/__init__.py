"""Owner break-glass contracts without stored sudo credentials."""

from vulnhunter.owner.models import PrivilegedBrokerRequest, PrivilegeGrant

__all__ = ["PrivilegeGrant", "PrivilegedBrokerRequest"]
