(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const toolList = workspace?.querySelector("[data-inspector-tools]");
  if (!workspace || !toolList) return;

  let plan = null;
  const asArray = (value) => (Array.isArray(value) ? value : []);
  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const render = () => {
    toolList.querySelectorAll("[data-deferred-tool]").forEach((item) => item.remove());
    asArray(plan?.deferred_tools).forEach((tool) => {
      const state = text(tool.state || tool.status || "gated");
      const row = document.createElement("div");
      row.className = `vh-inspector-tool is-${state}`;
      row.dataset.deferredTool = text(tool.tool_id);
      row.title = text(tool.reason || "Infrastructure approval is required.");

      const marker = document.createElement("span");
      marker.className = "vh-inspector-tool-marker";
      marker.textContent = state === "approval_required" ? "⌁" : "×";

      const copy = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = text(tool.name || tool.tool_id);
      const gate = document.createElement("small");
      gate.textContent = `${pretty(state)} · ${pretty(tool.gate || "approval")}`;
      const reason = document.createElement("em");
      reason.textContent = text(tool.reason || "Infrastructure is not ready.");
      copy.append(label, gate, reason);
      row.append(marker, copy);
      toolList.append(row);
    });
  };

  document.addEventListener("vh:mobile-plan", (event) => {
    plan = event.detail || null;
    queueMicrotask(render);
  });
  document.addEventListener("vh:mobile-status", () => queueMicrotask(render));
  document.addEventListener("vh:mobile-reset", () => {
    plan = null;
    render();
  });
})();
