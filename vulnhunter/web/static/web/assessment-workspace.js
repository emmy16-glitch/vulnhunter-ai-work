(() => {
  "use strict";

  const labels = {
    authorization: "Checking authorization",
    plan: "Preparing assessment plan",
    approval: "Waiting for approval",
    execution: "Running assessment",
    scanner: "Collecting evidence",
    evidence: "Collecting evidence",
    verification: "Verifying observations",
    review: "Waiting for independent review",
    report: "Preparing report",
  };
  const icons = { completed: "✓", running: "◌", pending: "○", queued: "○", blocked: "Ⅱ", recovering: "↻", failed: "!", cancelled: "×" };
  const readable = (value) => String(value || "pending").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

  window.VulnHunterAssessmentWorkspace = {
    renderTimeline(card, run) {
      const root = card?.querySelector("[data-run-stages]");
      const projection = run?.assessment_projection;
      const stages = Array.isArray(projection?.stages) ? projection.stages : [];
      if (!root || !stages.length) return false;
      root.replaceChildren();
      stages.forEach((item) => {
        const stage = String(item?.stage || "").trim();
        const status = String(item?.status || "pending").trim().toLowerCase();
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
        detail.textContent = readable(status);
        copy.append(title, detail);
        row.append(marker, copy);
        root.append(row);
      });
      return root.children.length > 0;
    },
  };
})();
