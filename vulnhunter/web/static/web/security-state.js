(() => {
  "use strict";
  if (typeof window === "undefined") return;
  const SECURITY_STATE_LABELS = Object.freeze({
    verified_configuration: "Verified configuration",
    verified_finding: "Verified finding",
    evidence_required: "Evidence required",
    rejected: "Rejected",
    inconclusive: "Inconclusive",
    partial: "Partial",
    blocked: "Blocked",
    not_applicable: "Not applicable",
    operational_issue: "Operational issue",
  });
  const TOOL_STATE_LABELS = Object.freeze({
    completed: "Completed",
    running: "Running",
    partial: "Partial",
    blocked: "Blocked",
    not_applicable: "Not applicable",
    failed: "Failed",
    queued: "Queued",
  });
  const label = (value, fallback = "Unknown") => {
    const key = String(value || "").toLowerCase();
    return SECURITY_STATE_LABELS[key] || TOOL_STATE_LABELS[key] || fallback;
  };
  window.VulnHunterSecurityState = Object.freeze({ SECURITY_STATE_LABELS, TOOL_STATE_LABELS, label });
})();
