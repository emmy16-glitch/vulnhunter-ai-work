(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const toolList = workspace?.querySelector("[data-inspector-tools]");
  const form = workspace?.querySelector("[data-conversation-form]");
  if (!workspace || !toolList || !form) return;

  let plan = null;
  const statuses = new Map();
  const timers = new Map();
  const asArray = (value) => (Array.isArray(value) ? value : []);
  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  const csrf = () => form.querySelector('input[name="csrfmiddlewaretoken"]')?.value || "";
  const kindFor = (toolId) => (toolId === "mobsf" ? "mobsf" : "runtime");

  const extensionFor = (toolId) => {
    const kind = kindFor(toolId);
    const jobs = asArray(plan?.extension_jobs);
    const matching = jobs.filter((job) => job?.kind === kind);
    return matching.at(-1) || null;
  };

  const stateFor = (tool) => {
    const job = extensionFor(text(tool.tool_id));
    if (!job) return text(tool.state || tool.status || "gated");
    const latest = statuses.get(text(job.job_id));
    return text(latest?.state || job.state || "queued");
  };

  const packageName = () => {
    const displayed = text(workspace.querySelector("[data-inspector-package]")?.textContent).trim();
    if (displayed && displayed !== "Pending analysis") return displayed;
    return window.prompt("Enter the exact Android package name, for example com.example.app:", "")?.trim() || "";
  };

  const poll = async (job) => {
    const jobId = text(job?.job_id);
    const statusUrl = text(job?.status_url);
    if (!jobId || !statusUrl || timers.has(jobId)) return;
    const tick = async () => {
      try {
        const response = await fetch(statusUrl, {
          method: "GET",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        const payload = await response.json();
        const status = payload?.mobile_extension;
        if (response.ok && status) {
          statuses.set(jobId, status);
          document.dispatchEvent(new CustomEvent("vh:mobile-extension-status", { detail: status }));
          render();
          if (["completed", "failed", "rejected"].includes(text(status.state))) {
            clearInterval(timers.get(jobId));
            timers.delete(jobId);
          }
        }
      } catch (_error) {
        return;
      }
    };
    await tick();
    if (!["completed", "failed", "rejected"].includes(text(statuses.get(jobId)?.state))) {
      timers.set(jobId, window.setInterval(tick, 1200));
    }
  };

  const approve = async (tool, button) => {
    const kind = kindFor(text(tool.tool_id));
    const packageValue = kind === "runtime" ? packageName() : "";
    if (kind === "runtime" && !packageValue) return;
    const label = kind === "mobsf" ? "private MobSF analysis" : "disposable ADB and Frida runtime analysis";
    if (!window.confirm(`Approve this exact ${label} for the current APK and plan digest?`)) return;
    button.disabled = true;
    button.textContent = "Approving…";
    const body = new URLSearchParams({
      kind,
      package_name: packageValue,
      reason: `Approve exact ${label} for this content-addressed APK and immutable plan.`,
    });
    try {
      const response = await fetch("/workspace/mobile-extensions/approve/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          "X-CSRFToken": csrf(),
        },
        body: body.toString(),
      });
      const payload = await response.json();
      if (!response.ok || !payload?.mobile_extension) {
        throw new Error(text(payload?.detail || "Extension approval failed."));
      }
      plan = payload.mobile_plan || plan;
      const extension = payload.mobile_extension;
      statuses.set(text(extension.job_id), extension);
      document.dispatchEvent(new CustomEvent("vh:mobile-plan", { detail: plan }));
      await poll(extension);
    } catch (error) {
      button.disabled = false;
      button.textContent = "Approve exact run";
      window.alert(text(error?.message || "Extension approval failed closed."));
    }
  };

  const render = () => {
    toolList.querySelectorAll("[data-deferred-tool]").forEach((item) => item.remove());
    asArray(plan?.deferred_tools).forEach((tool) => {
      const toolId = text(tool.tool_id);
      const state = stateFor(tool);
      const row = document.createElement("div");
      row.className = `vh-inspector-tool is-${state}`;
      row.dataset.deferredTool = toolId;

      const marker = document.createElement("span");
      marker.className = "vh-inspector-tool-marker";
      marker.textContent = state === "completed" ? "✓" : state === "failed" ? "!" : state === "approval_required" ? "⌁" : "×";

      const copy = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = text(tool.name || toolId);
      const gate = document.createElement("small");
      gate.textContent = `${pretty(state)} · ${pretty(tool.gate || "approval")}`;
      const job = extensionFor(toolId);
      const latest = job ? statuses.get(text(job.job_id)) : null;
      const reason = document.createElement("em");
      reason.textContent = text(latest?.reason || tool.reason || "Infrastructure is not ready.");
      copy.append(label, gate, reason);

      const mayApprove = state === "approval_required" && (toolId === "mobsf" || toolId === "adb");
      if (mayApprove) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "vh-inspector-extension-approve";
        button.textContent = "Approve exact run";
        button.addEventListener("click", () => approve(tool, button));
        copy.append(button);
      }
      row.append(marker, copy);
      toolList.append(row);
      if (job && ["queued", "running"].includes(text(latest?.state || job.state))) poll(job);
    });
  };

  document.addEventListener("vh:mobile-plan", (event) => {
    plan = event.detail || null;
    queueMicrotask(render);
  });
  document.addEventListener("vh:mobile-status", () => queueMicrotask(render));
  document.addEventListener("vh:mobile-reset", () => {
    plan = null;
    statuses.clear();
    timers.forEach((timer) => clearInterval(timer));
    timers.clear();
    render();
  });
})();
