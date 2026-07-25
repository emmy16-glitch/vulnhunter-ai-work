(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const inspector = workspace?.querySelector("[data-analysis-inspector]");
  if (!workspace || !inspector) return;

  const select = (name) => inspector.querySelector(`[data-inspector-${name}]`);
  const elements = {
    filename: select("filename"),
    digest: select("digest"),
    package: select("package"),
    inventory: select("inventory"),
    state: select("state"),
    stage: select("stage"),
    progress: select("progress"),
    progressValue: select("progress-value"),
    tools: select("tools"),
    events: select("events"),
    findings: select("findings"),
    findingsCount: select("findings-count"),
    artifacts: select("artifacts"),
    artifactsCount: select("artifacts-count"),
    graph: select("graph"),
    graphCount: select("graph-count"),
    emptyFindings: select("empty-findings"),
    emptyArtifacts: select("empty-artifacts"),
    emptyGraph: select("empty-graph"),
  };
  const tabs = [...inspector.querySelectorAll("[data-inspector-tab]")];
  const panels = [...inspector.querySelectorAll("[data-inspector-panel]")];
  const mobileButtons = [...workspace.querySelectorAll("[data-mobile-workspace-view]")];
  const close = inspector.querySelector("[data-analysis-inspector-close]");
  const state = {
    attachment: null,
    plan: null,
    execution: null,
    activeTab: "overview",
  };

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };
  const safeArray = (value) => (Array.isArray(value) ? value : []);

  const showInspector = () => {
    inspector.hidden = false;
    workspace.classList.add("has-analysis-inspector");
  };

  const hideInspector = () => {
    inspector.hidden = true;
    workspace.classList.remove("has-analysis-inspector");
    workspace.dataset.mobileWorkspaceView = "chat";
  };

  const setTab = (name) => {
    state.activeTab = name;
    tabs.forEach((tab) => {
      const selected = tab.dataset.inspectorTab === name;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.inspectorPanel !== name;
    });
  };

  const setMobileView = (name) => {
    workspace.dataset.mobileWorkspaceView = name;
    if (name !== "chat") {
      showInspector();
      setTab(name === "analysis" ? "overview" : name);
    }
    mobileButtons.forEach((button) => {
      button.classList.toggle("is-active", button.dataset.mobileWorkspaceView === name);
    });
  };

  const updateArtifact = () => {
    const attachment = state.attachment || state.plan?.artifact || {};
    const artifact = state.plan?.artifact || attachment;
    elements.filename.textContent = text(
      artifact.original_filename || attachment.original_filename || "Android application",
    );
    const digest = text(artifact.artifact_sha256 || attachment.artifact_sha256);
    elements.digest.textContent = digest ? `${digest.slice(0, 18)}…${digest.slice(-8)}` : "Pending";
    const packageName =
      state.execution?.progress?.result_summary?.captures
        ?.find((capture) => capture.tool === "androguard")
        ?.evidence?.structured?.package_name || "Pending analysis";
    elements.package.textContent = text(packageName);
    const dex = Number(artifact.dex_count || attachment.dex_count || 0);
    const nativeCount = Number(
      artifact.native_library_count || attachment.native_library_count || 0,
    );
    const size = formatBytes(artifact.size_bytes || attachment.size_bytes || 0);
    elements.inventory.textContent = `${size} · ${dex} DEX${nativeCount ? ` · ${nativeCount} native` : ""}`;
  };

  const planTools = () => {
    const planned = safeArray(state.plan?.tools).map((tool) => ({
      id: text(tool.tool_id || tool.name).toLowerCase(),
      label: text(tool.name || tool.tool_id),
      gate: text(tool.gate || "policy"),
      plannedState: tool.status === "blocked" ? "blocked" : "planned",
    }));
    const activated = safeArray(state.plan?.execution?.tools).map((tool) => ({
      id: text(tool).toLowerCase(),
      label: pretty(tool),
      gate: "worker",
      plannedState: "planned",
    }));
    const byId = new Map();
    [...planned, ...activated].forEach((tool) => {
      if (tool.id) byId.set(tool.id, tool);
    });
    return [...byId.values()];
  };

  const currentToolStates = () => {
    const toolStates = state.execution?.progress?.tool_states;
    return toolStates && typeof toolStates === "object" ? toolStates : {};
  };

  const updateTools = () => {
    elements.tools.replaceChildren();
    const toolStates = currentToolStates();
    const tools = planTools();
    if (!tools.length) {
      const empty = document.createElement("p");
      empty.className = "vh-inspector-empty";
      empty.textContent = "Tools appear after the governed plan is created.";
      elements.tools.append(empty);
      return;
    }
    tools.forEach((tool) => {
      const row = document.createElement("div");
      const current = text(toolStates[tool.id] || tool.plannedState || "planned");
      row.className = `vh-inspector-tool is-${current}`;
      const marker = document.createElement("span");
      marker.className = "vh-inspector-tool-marker";
      marker.textContent = current === "completed" ? "✓" : current === "failed" ? "!" : "";
      const copy = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = tool.label;
      const gate = document.createElement("small");
      gate.textContent = `${pretty(current)} · ${pretty(tool.gate)}`;
      copy.append(label, gate);
      row.append(marker, copy);
      elements.tools.append(row);
    });
  };

  const updateEvents = () => {
    elements.events.replaceChildren();
    const events = safeArray(state.execution?.progress?.events).slice(-40).reverse();
    if (!events.length) {
      const empty = document.createElement("li");
      empty.className = "vh-inspector-empty";
      empty.textContent = state.plan
        ? "Waiting for the signed worker to publish its first progress receipt."
        : "Activity appears after an APK plan is submitted.";
      elements.events.append(empty);
      return;
    }
    events.forEach((event) => {
      const item = document.createElement("li");
      const stamp = document.createElement("time");
      const parsed = new Date(text(event.at));
      stamp.textContent = Number.isNaN(parsed.valueOf())
        ? "--:--:--"
        : parsed.toLocaleTimeString([], { hour12: false });
      const copy = document.createElement("span");
      copy.textContent = text(event.detail || "Worker progress updated.");
      if (event.tool_state) item.className = `is-${text(event.tool_state)}`;
      item.append(stamp, copy);
      elements.events.append(item);
    });
  };

  const resultSummary = () => state.execution?.progress?.result_summary || {};
  const hunt = () => resultSummary().hunt || null;

  const updateFindings = () => {
    elements.findings.replaceChildren();
    const candidates = safeArray(hunt()?.candidates).filter(
      (candidate) => candidate.state !== "rejected",
    );
    elements.findingsCount.textContent = String(candidates.length);
    elements.emptyFindings.hidden = candidates.length > 0;
    candidates.forEach((candidate) => {
      const item = document.createElement("article");
      item.className = `vh-inspector-finding is-${text(candidate.state || "evidence_required")}`;
      const header = document.createElement("header");
      const severity = document.createElement("span");
      severity.textContent = pretty(candidate.severity || "unknown");
      const disposition = document.createElement("b");
      disposition.textContent = pretty(candidate.state || "evidence_required");
      header.append(severity, disposition);
      const title = document.createElement("strong");
      title.textContent = text(candidate.title || "Candidate observation");
      const component = document.createElement("small");
      component.textContent = text(candidate.component || candidate.weakness_id || "Application surface");
      const reason = document.createElement("p");
      reason.textContent = text(candidate.disposition_reason || "Additional evidence is required.");
      item.append(header, title, component, reason);
      elements.findings.append(item);
    });
  };

  const updateArtifacts = () => {
    elements.artifacts.replaceChildren();
    const captures = safeArray(resultSummary().captures);
    elements.artifactsCount.textContent = String(captures.length);
    elements.emptyArtifacts.hidden = captures.length > 0;
    captures.forEach((capture) => {
      const item = document.createElement("article");
      item.className = Number(capture.return_code) === 0 ? "is-success" : "is-failed";
      const title = document.createElement("strong");
      title.textContent = pretty(capture.tool || "tool");
      const meta = document.createElement("small");
      const duration = Number(capture.duration_ms || 0);
      meta.textContent = `Exit ${Number(capture.return_code)} · ${(duration / 1000).toFixed(1)}s`;
      const digest = document.createElement("code");
      digest.textContent = `Evidence ${text(capture.output_sha256).slice(0, 24)}…`;
      const metrics = document.createElement("p");
      const evidence = capture.evidence && typeof capture.evidence === "object" ? capture.evidence : {};
      if (capture.tool === "jadx") {
        metrics.textContent = `${Number(evidence.source_files || 0)} source files · ${formatBytes(evidence.generated_bytes || 0)}`;
      } else if (capture.tool === "androguard") {
        const structured = evidence.structured || {};
        metrics.textContent = `${Number(structured.class_count || 0)} classes · ${safeArray(structured.permissions).length} permissions`;
      } else if (capture.tool === "yara") {
        const structured = evidence.structured || {};
        metrics.textContent = `${safeArray(structured.matches).length} reviewed rule matches · ${Number(structured.scanned_files || 0)} files`;
      } else {
        metrics.textContent = text(evidence.library || "Bounded structured receipt stored");
      }
      item.append(title, meta, digest, metrics);
      elements.artifacts.append(item);
    });
  };

  const updateGraph = () => {
    elements.graph.replaceChildren();
    const graph = resultSummary().graph;
    const nodes = safeArray(graph?.nodes);
    const edges = safeArray(graph?.edges);
    elements.graphCount.textContent = String(nodes.filter((node) => node.kind === "candidate").length);
    elements.emptyGraph.hidden = nodes.length > 0;
    if (!nodes.length) return;

    const canvas = document.createElement("div");
    canvas.className = "vh-evidence-graph-canvas";
    const kinds = ["artifact", "tool", "component", "candidate"];
    kinds.forEach((kind) => {
      const columnNodes = nodes.filter((node) => node.kind === kind);
      if (!columnNodes.length) return;
      const column = document.createElement("section");
      column.className = `vh-evidence-graph-column is-${kind}`;
      const heading = document.createElement("small");
      heading.textContent = pretty(kind);
      column.append(heading);
      columnNodes.forEach((node) => {
        const card = document.createElement("article");
        card.className = `vh-evidence-node is-${text(node.state || "observed")}`;
        card.dataset.nodeId = text(node.node_id);
        const label = document.createElement("strong");
        label.textContent = text(node.label);
        const meta = document.createElement("span");
        meta.textContent = `${pretty(node.state)}${node.severity && node.severity !== "info" ? ` · ${pretty(node.severity)}` : ""}`;
        card.append(label, meta);
        column.append(card);
      });
      canvas.append(column);
    });
    elements.graph.append(canvas);
    const summary = document.createElement("p");
    summary.className = "vh-evidence-graph-summary";
    summary.textContent = `${Number(graph.verified_paths || 0)} verified condition path${Number(graph.verified_paths || 0) === 1 ? "" : "s"} · ${Number(graph.evidence_required_paths || 0)} requiring more evidence · ${edges.length} evidence-bound relations`;
    elements.graph.append(summary);
  };

  const updateProgress = () => {
    const execution = state.execution || state.plan?.execution || { state: "prepared" };
    const progress = execution.progress || {};
    const toolStates = currentToolStates();
    const values = Object.values(toolStates);
    const terminal = values.filter((value) => ["completed", "failed", "blocked"].includes(value)).length;
    const percent = values.length
      ? Math.round((terminal / values.length) * 100)
      : execution.state === "completed"
        ? 100
        : state.plan
          ? 8
          : 0;
    elements.progress.style.setProperty("--vh-analysis-progress", `${percent}%`);
    elements.progressValue.textContent = `${percent}%`;
    elements.state.textContent = pretty(execution.state || "prepared");
    const activeTool = progress.active_tool;
    const lastEvent = safeArray(progress.events).at(-1);
    elements.stage.textContent = activeTool
      ? `Running ${pretty(activeTool)}`
      : text(lastEvent?.detail || (state.plan ? "Plan prepared" : "APK validated"));
  };

  const render = () => {
    if (!state.attachment && !state.plan) {
      hideInspector();
      return;
    }
    showInspector();
    updateArtifact();
    updateProgress();
    updateTools();
    updateEvents();
    updateFindings();
    updateArtifacts();
    updateGraph();
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => setTab(tab.dataset.inspectorTab || "overview"));
  });
  mobileButtons.forEach((button) => {
    button.addEventListener("click", () => setMobileView(button.dataset.mobileWorkspaceView || "chat"));
  });
  close?.addEventListener("click", () => setMobileView("chat"));

  document.addEventListener("vh:mobile-attachment", (event) => {
    state.attachment = event.detail || null;
    state.plan = null;
    state.execution = null;
    setTab("overview");
    render();
  });
  document.addEventListener("vh:mobile-plan", (event) => {
    if (!event.detail) return;
    state.plan = event.detail;
    state.attachment = event.detail.artifact || state.attachment;
    state.execution = event.detail.execution || null;
    setTab("overview");
    render();
  });
  document.addEventListener("vh:mobile-status", (event) => {
    state.execution = event.detail || null;
    render();
  });
  document.addEventListener("vh:mobile-reset", () => {
    state.attachment = null;
    state.plan = null;
    state.execution = null;
    hideInspector();
  });

  setTab("overview");
})();
