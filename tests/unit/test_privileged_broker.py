from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.privileged_broker import (
    BrokerOperation,
    PrivilegedBrokerError,
    PrivilegedBrokerPolicy,
    PrivilegedGrant,
)


def _grant(now: datetime) -> PrivilegedGrant:
    return PrivilegedGrant(
        grant_id="grant-1",
        operation_id="restart-worker",
        actor_id="operator-1",
        approver_id="owner-1",
        action_manifest_sha256="a" * 64,
        execution_id="execution-1",
        target_sha256="b" * 64,
        issued_at=now,
        expires_at=now + timedelta(minutes=1),
    )


def test_broker_builds_only_exact_allowlisted_argv() -> None:
    now = datetime(2026, 7, 15, tzinfo=UTC)
    policy = PrivilegedBrokerPolicy(
        (
            BrokerOperation(
                operation_id="restart-worker",
                executable="/usr/bin/systemctl",
                fixed_arguments=("restart", "vulnhunter-worker.service"),
            ),
        )
    )
    argv = policy.build_argv(
        grant=_grant(now),
        operation_id="restart-worker",
        action_manifest_sha256="a" * 64,
        execution_id="execution-1",
        target_sha256="b" * 64,
        now=now,
    )
    assert argv == ("/usr/bin/systemctl", "restart", "vulnhunter-worker.service")


def test_broker_rejects_binding_mismatch_and_variable_arguments() -> None:
    now = datetime(2026, 7, 15, tzinfo=UTC)
    policy = PrivilegedBrokerPolicy(
        (
            BrokerOperation(
                operation_id="restart-worker",
                executable="/usr/bin/systemctl",
                fixed_arguments=("restart", "vulnhunter-worker.service"),
            ),
        )
    )
    with pytest.raises(PrivilegedBrokerError, match="binding mismatch"):
        policy.build_argv(
            grant=_grant(now),
            operation_id="restart-worker",
            action_manifest_sha256="c" * 64,
            execution_id="execution-1",
            target_sha256="b" * 64,
            now=now,
        )
    with pytest.raises(PrivilegedBrokerError, match="variable arguments"):
        policy.build_argv(
            grant=_grant(now),
            operation_id="restart-worker",
            action_manifest_sha256="a" * 64,
            execution_id="execution-1",
            target_sha256="b" * 64,
            variable_arguments=("anything",),
            now=now,
        )
