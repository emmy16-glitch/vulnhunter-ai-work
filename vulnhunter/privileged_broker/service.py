"""Preparation-only privileged broker service.

This module validates action-bound grants and exact allowlisted argv. It does
not execute commands and cannot be activated accidentally.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .models import BrokerOperation, GrantStatus, PrivilegedGrant


class PrivilegedBrokerError(RuntimeError):
    """Raised when a privileged request is not safe and exactly bound."""


class PrivilegedBrokerPolicy:
    def __init__(self, operations: tuple[BrokerOperation, ...]) -> None:
        self._operations = {item.operation_id: item for item in operations}
        if len(self._operations) != len(operations):
            raise PrivilegedBrokerError("duplicate broker operation identifier")

    def build_argv(
        self,
        *,
        grant: PrivilegedGrant,
        operation_id: str,
        action_manifest_sha256: str,
        execution_id: str,
        target_sha256: str,
        variable_arguments: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        timestamp = now or datetime.now(UTC)
        if grant.status != GrantStatus.ISSUED:
            raise PrivilegedBrokerError("privileged grant is not active")
        if timestamp >= grant.expires_at:
            raise PrivilegedBrokerError("privileged grant has expired")
        bindings = {
            "operation_id": operation_id,
            "action_manifest_sha256": action_manifest_sha256,
            "execution_id": execution_id,
            "target_sha256": target_sha256,
        }
        for field, supplied in bindings.items():
            if getattr(grant, field) != supplied:
                raise PrivilegedBrokerError(f"privileged grant binding mismatch: {field}")
        try:
            operation = self._operations[operation_id]
        except KeyError as exc:
            raise PrivilegedBrokerError("operation is not allowlisted") from exc
        if variable_arguments and not operation.allow_variable_arguments:
            raise PrivilegedBrokerError("variable arguments are not permitted")
        for argument in variable_arguments:
            if "\x00" in argument or "\n" in argument or "\r" in argument:
                raise PrivilegedBrokerError("unsafe argument encoding")
        return (operation.executable, *operation.fixed_arguments, *variable_arguments)

    @staticmethod
    def consume(grant: PrivilegedGrant, *, now: datetime | None = None) -> PrivilegedGrant:
        timestamp = now or datetime.now(UTC)
        if grant.status != GrantStatus.ISSUED:
            raise PrivilegedBrokerError("privileged grant is not active")
        if timestamp >= grant.expires_at:
            raise PrivilegedBrokerError("privileged grant has expired")
        return grant.model_copy(update={"status": GrantStatus.CONSUMED, "consumed_at": timestamp})
