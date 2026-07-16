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
from vulnhunter.security_tools.nuclei_activation import (
    EngagementAuthorization,
    NucleiActivationDecision,
    NucleiActivationError,
    NucleiCommandPlan,
    NucleiPlanApproval,
    NucleiRunControl,
    NucleiTemplateManifest,
    NucleiTemplateManifestEntry,
    ProcessGroupTerminator,
    ScopedNucleiTarget,
    validate_evidence_directory,
    validate_nuclei_plan_approval,
    validate_nuclei_redirect_scope,
    validate_nuclei_target_scope,
    verify_redacted_evidence,
)

__all__ = [
    "CommandPlan",
    "EngagementAuthorization",
    "NucleiActivationDecision",
    "NucleiActivationError",
    "NucleiCommandPlan",
    "NucleiPlanApproval",
    "NucleiRunControl",
    "NucleiTemplateManifest",
    "NucleiTemplateManifestEntry",
    "ProcessGroupTerminator",
    "ScopedNucleiTarget",
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
    "validate_evidence_directory",
    "validate_nuclei_plan_approval",
    "validate_nuclei_redirect_scope",
    "validate_nuclei_target_scope",
    "verify_redacted_evidence",
]
