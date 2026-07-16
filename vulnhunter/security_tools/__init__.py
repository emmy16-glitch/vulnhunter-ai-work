"""Governed external security-tool registry and shell-free execution."""

from vulnhunter.security_tools.catalog import SecurityToolCatalog, default_catalog
from vulnhunter.security_tools.executor import SecurityToolExecutor
from vulnhunter.security_tools.integration import normalize_execution_findings
from vulnhunter.security_tools.models import (
    CommandPlan,
    SecurityToolDefinition,
    SecurityToolRequest,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolExecutionResult,
    ToolProfile,
    ToolTargetKind,
)

__all__ = [
    "CommandPlan",
    "SecurityToolCatalog",
    "SecurityToolDefinition",
    "SecurityToolExecutor",
    "SecurityToolRequest",
    "ToolAvailability",
    "ToolAvailabilityStatus",
    "ToolExecutionResult",
    "ToolProfile",
    "ToolTargetKind",
    "default_catalog",
    "normalize_execution_findings",
]
