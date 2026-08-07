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
    graphSection: select("graph-section"),
    reports: select("reports"),
    reportsCount: select("reports-count"),
    emptyFindings: select("empty-findings"),
    emptyArtifacts: select("empty-artifacts"),
    emptyGraph: select("empty-graph"),
    emptyReports: select("empty-reports"),
  };
  const tabs = [...inspector.querySelectorAll("[data-inspector-tab]")];
  const panels = [...inspector.querySelectorAll("[data-inspector-panel]")];
  const mobileButtons = [...workspace.querySelectorAll("[data-mobile-workspace-view]")];
  const close = inspector.querySelector("[data-analysis-inspector-close]");
  const state = {
    attachment: null,
    plan: null,
    execution: null,
    projection: null,
    taskCard: null,
    activeTab: "overview",
    returnFocus: null,
    sheetHistoryActive: false,
    unsubscribeSelectedAssessment: null,
  };

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  const safeArray = (value) => (Array.isArray(value) ? value : []);
  const isMobile = () => window.matchMedia("(max-width: 767px)").matches;
  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const selectedAssessmentId = () => text(state.projection?.assessment_id);
  const hasAuthoritativeAssessment = () =>
    Boolean(selectedAssessmentId() && state.taskCard?.assessment_id === selectedAssessmentId());

  const focusable = () =>
    [...inspector.querySelectorAll("button, [href], input, select, textarea, [tabindex]")].filter(
      (item) => !item.hidden && !item.disabled && item.getAttribute("tabindex") !== "-1",
    );

  const showInspector = ({ trigger = null, pushHistory = true } = {}) => {
    inspector.hidden = false;
    workspace.classList.add("has-analysis-inspector");
    if (!isMobile()) return;
    if (trigger instanceof HTMLElement) state.returnFocus = trigger;
    document.documentElement.classList.add("vh-mobile-sheet-open");
    inspector.setAttribute("aria-modal", "true");
    if (pushHistory && !state.sheetHistoryActive) {
      window.history.pushState({ vhAssessmentSheet: true }, "");
      state.sheetHistoryActive = true;
    }
    window.requestAnimationFrame(() => close?.focus());
  };

  const hideInspector = ({ restoreFocus = true, fromHistory = false } = {}) => {
    inspector.hidden = true;
    workspace.classList.remove("has-analysis-inspector");
    workspace.dataset.mobileWorkspaceView = "chat";
    document.documentElement.classList.remove("vh-mobile-sheet-open");
    inspector.removeAttribute("aria-modal");
    mobileButtons.forEach((button) => {
      button.classList.toggle("is-active", button.dataset.mobileWorkspaceView === "chat");
      button.setAttribute(
        "aria-current",
        button.dataset.mobileWorkspaceView === "chat" ? "page" : "false",
      );
    });
    if (isMobile() && state.sheetHistoryActive && !fromHistory) {
      state.sheetHistoryActive = false;
      window.history.back();
    } else if (fromHistory) {
      state.sheetHistoryActive = false;
    }
    if (restoreFocus && state.returnFocus instanceof HTMLElement) state.returnFocus.focus();
  };

  const setTab = (name) => {
    const valid = tabs.some((tab) => tab.dataset.inspectorTab === name) ? name : "overview";
    state.activeTab = valid;
    tabs.forEach((tab) => {
      const selected = tab.dataset.inspectorTab === valid;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.inspectorPanel !== valid;
    });
  };

  const setMobileView = (name, trigger = null) => {
    const view = name === "chat" ? "chat" : "analysis";
    workspace.dataset.mobileWorkspaceView = view;
    if (view === "chat") {
      hideInspector();
    } else {
      showInspector({ trigger });
      setTab("overview");
    }
    mobileButtons.forEach((button) => {
      const selected = button.dataset.mobileWorkspaceView === view;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-current", selected ? "page" : "false");
    });
  };

  const updateArtifact = () => {
    const subject = state.projection?.subject || {};
    const attachment = state.plan?.artifact || state.attachment || {};
    elements.filename.textContent = text(
      subject.label || attachment.original_filename || "Selected assessment",
    );
    const digest = text(subject.sha256 || attachment.artifact_sha256);
    elements.digest.textContent = digest
      ? `${digest.slice(0, 18)}…${digest.slice(-8)}`
      : selectedAssessmentId() || "Pending";
    const packageName =
      state.execution?.progress?.result_summary?.captures
        ?.find((capture) => capture.tool === "androguard")
        ?.evidence?.structured?.package_name || pretty(state.projection?.assessment_kind || "assessment");
    elements.package.textContent = text(packageName);
    const dex = Number(attachment.dex_count || 0);
    const nativeCount = Number(attachment.native_library_count || 0);
    const size = Number(attachment.size_bytes || 0);
    elements.inventory.textContent = size
      ? `${formatBytes(size)} · ${dex} DEX${nativeCount ? ` · ${nativeCount} native` : ""}`
      : "Authoritative assessment scope";
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
      empty.textContent = "Tools appear after an authorised plan is persisted.";
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

  const authoritativeEvents = () => {
    const persisted = safeArray(state.execution?.progress?.events);
    if (persisted.length) return persisted;
    const latest = state.taskCard?.activity?.latest_event;
    return latest ? [latest] : [];
  };

  const updateEvents = () => {
    elements.events.replaceChildren();
    const events = authoritativeEvents().slice(-40).reverse();
    if (!events.length) {
      const empty = document.createElement("li");
      empty.className = "vh-inspector-empty";
      empty.textContent = hasAuthoritativeAssessment()
        ? "No persisted activity receipt is available yet."
        : "Select an assessment to view persisted activity.";
      elements.events.append(empty);
      return;
    }
    events.forEach((event) => {
      const item = document.createElement("li");
      const stamp = document.createElement("time");
      const parsed = new Date(text(event.at));
      stamp.textContent = Number.isNaN(parsed.valueOf())
        ? "Recorded"
        : parsed.toLocaleTimeString([], { hour12: false });
      const copy = document.createElement("span");
      copy.textContent = text(event.detail || `${pretty(event.stage)} · ${pretty(event.status)}`);
      if (event.tool_state || event.status) item.className = `is-${text(event.tool_state || event.status)}`;
      item.append(stamp, copy);
      elements.events.append(item);
    });
  };

  const resultSummary = () => state.execution?.progress?.result_summary || {};
  const hunt = () => resultSummary().hunt || null;

  const updateFindings = () => {
    elements.findings.replaceChildren();
    const candidates = safeArray(hunt()?.candidates).map((candidate) => ({ ...candidate }));
    const rejected = safeArray(hunt()?.rejected).map((candidate) => ({
      ...candidate,
      state: "rejected",
    }));
    const findings = [...candidates, ...rejected];
    const projectedFindings = state.projection?.findings || {};
    const candidateCount = Number(projectedFindings.candidate_count);
    const rejectedCount = Number(projectedFindings.rejected_count);
    const hasProjectedCounts = Number.isInteger(candidateCount) && Number.isInteger(rejectedCount);
    elements.findingsCount.textContent = hasProjectedCounts
      ? String(candidateCount + rejectedCount)
      : "—";

    const verification = state.projection?.verification || resultSummary().verification || {};
    const verificationStatus = text(verification.status).toLowerCase();
    const finalVerification = ["verified", "rejected", "abstained", "mixed"].includes(
      verificationStatus,
    );
    elements.emptyFindings.hidden = findings.length > 0 || finalVerification;

    if (finalVerification) {
      const summary = document.createElement("article");
      summary.className = `vh-inspector-finding is-${verificationStatus}`;
      const header = document.createElement("header");
      const label = document.createElement("span");
      label.textContent = "Verification";
      const disposition = document.createElement("b");
      disposition.textContent = pretty(verificationStatus);
      header.append(label, disposition);
      const title = document.createElement("strong");
      title.textContent = "Persisted verification outcome";
      const counts = document.createElement("p");
      counts.textContent = `${Number(verification.verified_count || 0)} verified · ${Number(
        verification.rejected_count || 0,
      )} rejected · ${Number(verification.abstained_count || 0)} abstained`;
      summary.append(header, title, counts);
      elements.findings.append(summary);
    }

    findings.forEach((candidate) => {
      const dispositionState = text(candidate.state || "candidate").toLowerCase();
      const item = document.createElement("article");
      item.className = `vh-inspector-finding is-${dispositionState}`;
      const header = document.createElement("header");
      const severity = document.createElement("span");
      severity.textContent = pretty(candidate.severity || "unknown");
      const disposition = document.createElement("b");
      disposition.textContent = pretty(dispositionState);
      header.append(severity, disposition);
      const title = document.createElement("strong");
      title.textContent = text(candidate.title || "Candidate observation");
      const component = document.createElement("small");
      component.textContent = text(candidate.component || candidate.weakness_id || "Application surface");
      const reason = document.createElement("p");
      reason.textContent = text(
        candidate.disposition_reason ||
          (dispositionState === "candidate"
            ? "Candidate observation awaiting verification."
            : "Persisted assessment disposition."),
      );
      item.append(header, title, component, reason);
      elements.findings.append(item);
    });
  };

  const updateArtifacts = () => {
    elements.artifacts.replaceChildren();
    const captures = safeArray(resultSummary().captures);
    const authoritativeCount = Number(state.projection?.evidence?.record_count);
    elements.artifactsCount.textContent = String(
      Number.isInteger(authoritativeCount) ? authoritativeCount : captures.length,
    );
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
      metrics.textContent = text(evidence.library || "Bounded structured receipt stored");
      item.append(title, meta, digest, metrics);
      elements.artifacts.append(item);
    });
  };

  const updateGraph = () => {
    elements.graph.replaceChildren();
    const graph = resultSummary().graph;
    const nodes = safeArray(graph?.nodes);
    const edges = safeArray(graph?.edges);
    const meaningful = nodes.length > 1 && edges.length > 0;
    if (elements.graphSection) elements.graphSection.hidden = !meaningful;
    elements.graphCount.textContent = meaningful
      ? String(nodes.filter((node) => node.kind === "candidate").length)
      : "—";
    elements.emptyGraph.hidden = meaningful;
    if (!meaningful) return;
    const canvas = document.createElement("div");
    canvas.className = "vh-evidence-graph-canvas";
    ["artifact", "tool", "component", "candidate"].forEach((kind) => {
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
        meta.textContent = pretty(node.state || "observed");
        card.append(label, meta);
        column.append(card);
      });
      canvas.append(column);
    });
    elements.graph.append(canvas);
    const summary = document.createElement("p");
    summary.className = "vh-evidence-graph-summary";
    summary.textContent = `${Number(graph.verified_paths || 0)} verified paths · ${Number(
      graph.evidence_required_paths || 0,
    )} requiring evidence · ${edges.length} relations`;
    elements.graph.append(summary);
  };

  const reportFormats = [
    ["html", "HTML"],
    ["json", "JSON"],
    ["sarif", "SARIF"],
    ["evidence_zip", "Evidence ZIP"],
    ["pdf", "PDF"],
  ];

  const updateReports = () => {
    elements.reports.replaceChildren();
    const report = state.projection?.report || {};
    const formats = report.formats && typeof report.formats === "object" ? report.formats : null;
    const rows = formats
      ? reportFormats.map(([id, label]) => ({ id, label, value: formats[id] })).filter(
          (row) => row.value && typeof row.value === "object",
        )
      : [];
    const available = rows.filter((row) => text(row.value.status).toLowerCase() === "available");
    elements.reportsCount.textContent = rows.length === reportFormats.length ? String(available.length) : "—";
    elements.emptyReports.hidden = rows.length === reportFormats.length;
    if (rows.length !== reportFormats.length) return;

    const identity = document.createElement("article");
    identity.className = "vh-inspector-report-identity";
    const identityTitle = document.createElement("strong");
    identityTitle.textContent = text(state.projection?.subject?.label || "Selected assessment");
    const identityMeta = document.createElement("small");
    identityMeta.textContent = `${selectedAssessmentId()} · ${pretty(
      state.projection?.execution?.state || state.projection?.lifecycle || "unavailable",
    )}`;
    identity.append(identityTitle, identityMeta);
    elements.reports.append(identity);

    rows.forEach((row) => {
      const status = text(row.value.status).toLowerCase();
      const item = document.createElement("article");
      item.className = status === "available" ? "is-success" : "is-failed";
      const header = document.createElement("header");
      const title = document.createElement("strong");
      title.textContent = row.label;
      const stateLabel = document.createElement("b");
      stateLabel.textContent = pretty(status || "unavailable");
      header.append(title, stateLabel);
      const reason = document.createElement("p");
      reason.textContent = text(row.value.reason || "Readiness reason unavailable.");
      item.append(header, reason);
      if (row.id === "html" && status === "available" && report.report_id) {
        const receipt = document.createElement("code");
        const digest = text(report.digest);
        receipt.textContent = digest
          ? `${text(report.report_id)} · ${digest.slice(0, 24)}…`
          : text(report.report_id);
        item.append(receipt);
      }
      elements.reports.append(item);
    });
  };

  const updateProgress = () => {
    const projection = state.projection || {};
    const taskCard = state.taskCard || {};
    const stage = taskCard.current_stage || {};
    const completed = Number(taskCard.stage_progress?.completed);
    const total = Number(taskCard.stage_progress?.total);
    const measured =
      Number.isInteger(completed) && Number.isInteger(total) && total > 0 && completed <= total;
    elements.progress.style.setProperty(
      "--vh-analysis-progress",
      measured ? `${Math.round((completed / total) * 100)}%` : "0%",
    );
    elements.progressValue.textContent = measured ? `${completed} of ${total}` : "—";
    elements.progressValue.setAttribute(
      "aria-label",
      measured ? `${completed} of ${total} persisted stages complete` : "Progress unavailable",
    );
    elements.state.textContent = pretty(projection.execution?.state || taskCard.state || "unavailable");
    elements.stage.textContent = stage.stage
      ? `${pretty(stage.stage)} · ${pretty(stage.status || "pending")}`
      : "No persisted current stage is available.";
  };

  const render = () => {
    if (!hasAuthoritativeAssessment()) {
      hideInspector({ restoreFocus: false });
      return;
    }
    updateArtifact();
    updateProgress();
    updateTools();
    updateEvents();
    updateFindings();
    updateArtifacts();
    updateGraph();
    updateReports();
  };

  const applySelectedAssessment = (snapshot) => {
    state.projection = snapshot?.assessment_projection || null;
    state.taskCard = snapshot?.task_card || null;
    state.plan = snapshot?.mobile_plan || null;
    state.attachment = state.plan?.artifact || null;
    state.execution = snapshot?.mobile_execution || state.plan?.execution || null;
    if (!snapshot) {
      hideInspector({ restoreFocus: false });
      return;
    }
    setTab(state.activeTab);
    render();
  };

  const bindSelectedAssessmentStore = (store = window.vhSelectedAssessmentStore) => {
    if (!store || typeof store.subscribe !== "function") return;
    if (state.unsubscribeSelectedAssessment) return;
    state.unsubscribeSelectedAssessment = store.subscribe(applySelectedAssessment);
    applySelectedAssessment(store.getSnapshot());
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => setTab(tab.dataset.inspectorTab || "overview"));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      tabs[next].focus();
      setTab(tabs[next].dataset.inspectorTab || "overview");
    });
  });
  mobileButtons.forEach((button) => {
    button.addEventListener("click", () =>
      setMobileView(button.dataset.mobileWorkspaceView || "chat", button),
    );
  });
  close?.addEventListener("click", () => setMobileView("chat"));

  document.addEventListener("keydown", (event) => {
    if (inspector.hidden || !isMobile()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      hideInspector();
      return;
    }
    if (event.key !== "Tab") return;
    const items = focusable();
    if (!items.length) return;
    const first = items[0];
    const last = items.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  window.addEventListener("popstate", () => {
    if (!inspector.hidden && isMobile()) hideInspector({ fromHistory: true });
  });

  document.addEventListener("vh:selected-assessment-store-ready", (event) => {
    bindSelectedAssessmentStore(event.detail);
  });

  bindSelectedAssessmentStore();
  setTab("overview");
})();