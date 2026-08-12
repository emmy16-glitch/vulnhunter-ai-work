(() => {
  "use strict";

  const labels = {
    authorization: "Checking authorization",
    plan: "Preparing assessment plan",
    approval: "Waiting for approval",
    execution: "Running assessment",
    scanner: "Running scanner",
    evidence: "Normalizing evidence",
    verification: "Verifying observations",
    review: "Waiting for independent review",
    report: "Preparing report",
    complete: "Assessment complete",
  };

  const icons = {
    completed: "✓",
    running: "◌",
    pending: "○",
    queued: "○",
    blocked: "Ⅱ",
    recovering: "↻",
    failed: "!",
    cancelled: "×",
  };

  const canonicalStatus = (value) => {
    const raw = String(value || "pending").trim().toLowerCase();
    return (
      {
        active: "running",
        claimed: "running",
        waiting: "pending",
        prepared: "pending",
        approval_required: "blocked",
        confirmation_required: "blocked",
        error: "failed",
        succeeded: "completed",
        success: "completed",
        done: "completed",
      }[raw] || raw
    );
  };

  const readable = (value) =>
    String(value || "pending")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const asObject = (value) =>
    value && typeof value === "object" && !Array.isArray(value) ? value : {};

  const stageStatus = (run, stageName) => {
    const stages = Array.isArray(run?.assessment_projection?.stages)
      ? run.assessment_projection.stages
      : [];
    const match = stages.find((item) => String(item?.stage || "") === stageName);
    return canonicalStatus(match?.status);
  };

  const addToolChip = (root, { label, status = "pending", detail = "" }) => {
    if (!root || !label) return;
    const normalized = canonicalStatus(status);
    const chip = document.createElement("span");
    chip.className = `vh-tool-chip is-${normalized}`;
    const marker = document.createElement("i");
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = icons[normalized] || "○";
    const copy = document.createElement("span");
    copy.textContent = detail ? `${label} · ${detail}` : label;
    chip.append(marker, copy);
    chip.setAttribute("aria-label", `${label}: ${readable(normalized)}${detail ? `, ${detail}` : ""}`);
    root.append(chip);
  };

  const renderToolChips = (card, run) => {
    const root = card?.querySelector("[data-run-tool-chips]");
    if (!root) return false;
    root.replaceChildren();

    const execution = asObject(run?.execution);
    const progress = asObject(execution.progress);
    const toolStates = asObject(progress.tool_states);
    const seen = new Set();

    Object.entries(toolStates)
      .slice(0, 8)
      .forEach(([tool, status]) => {
        const label = readable(tool);
        if (!label) return;
        seen.add(String(tool).toLowerCase());
        addToolChip(root, { label, status });
      });

    const scanner = String(run?.scanner || run?.requested_tool || "").trim();
    if (scanner && !seen.has(scanner.toLowerCase())) {
      const scannerStatus = stageStatus(run, "scanner") || stageStatus(run, "execution");
      addToolChip(root, { label: scanner, status: scannerStatus || "pending" });
    }

    const evidenceCount = Number(run?.assessment_projection?.evidence?.record_count);
    if (Number.isInteger(evidenceCount) && evidenceCount >= 0) {
      addToolChip(root, {
        label: "Evidence",
        status: stageStatus(run, "evidence") || (evidenceCount > 0 ? "completed" : "pending"),
        detail: String(evidenceCount),
      });
    }

    return root.children.length > 0;
  };

  window.VulnHunterAssessmentWorkspace = {
    renderTimeline(card, run) {
      const root = card?.querySelector("[data-run-stages]");
      const projection = run?.assessment_projection;
      const stages = Array.isArray(projection?.stages) ? projection.stages : [];
      if (!root || !stages.length) {
        renderToolChips(card, run);
        return false;
      }

      root.replaceChildren();
      stages.forEach((item) => {
        const stage = String(item?.stage || "").trim();
        const status = canonicalStatus(item?.status);
        if (!stage) return;

        const row = document.createElement("div");
        row.className = `vh-assessment-timeline-row is-${status}`;

        const marker = document.createElement("span");
        marker.className = "vh-assessment-timeline-state";
        marker.setAttribute("aria-hidden", "true");
        marker.textContent = icons[status] || "○";

        const copy = document.createElement("div");
        const title = document.createElement("strong");
        const detail = document.createElement("small");
        title.textContent = labels[stage] || readable(stage);
        const persistedDetail = String(item?.detail || item?.summary || "").trim();
        detail.textContent = persistedDetail || readable(status);
        copy.append(title, detail);

        row.append(marker, copy);
        root.append(row);
      });

      renderToolChips(card, run);
      return root.children.length > 0;
    },
    renderToolChips,
  };
})();
