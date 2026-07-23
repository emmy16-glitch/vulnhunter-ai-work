(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  if (!workspace || !dataElement) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const feed = workspace.querySelector("[data-conversation-feed]");
  const form = workspace.querySelector("[data-conversation-form]");
  const input = workspace.querySelector("[data-conversation-input]");
  const send = workspace.querySelector("[data-conversation-send]");
  const thinking = workspace.querySelector("[data-conversation-thinking]");
  const thinkingCopy = workspace.querySelector("[data-thinking-copy]");
  const reset = workspace.querySelector("[data-conversation-reset]");
  const historyToggle = workspace.querySelector("[data-history-toggle]");
  const historyPanel = workspace.querySelector("[data-history-panel]");
  const historyClose = workspace.querySelector("[data-history-close]");
  const messageTemplate = document.getElementById("vh-message-template");
  const runTemplate = document.getElementById("vh-run-template");
  const csrfToken = form?.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";

  if (!feed || !form || !input || !messageTemplate || !runTemplate) return;

  let activeRun = initial.active_run || null;
  let runCard = null;
  let pollTimer = null;
  let requestBusy = false;
  let busyStartedAt = 0;
  let busyTimer = null;
  let busyBaseCopy = "Understanding the request…";
  let lastRunSignature = "";
  const confirmedRuns = new Set();
  const renderedMessages = new Set();
  const announcedEvents = new Set();

  const stageDefinitions = [
    ["scope", "Checking authorised scope"],
    ["plan", "Preparing the passive plan"],
    ["approval", "Waiting for confirmation"],
    ["scanner", "Running Nuclei"],
    ["evidence", "Collecting evidence"],
    ["verification", "Verifying observations"],
    ["complete", "Assessment complete"],
  ];

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const prettyState = (value) =>
    text(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const formatDuration = (seconds) => {
    const safe = Math.max(0, Number(seconds) || 0);
    const minutes = Math.floor(safe / 60);
    const remaining = Math.floor(safe % 60);
    return `${String(minutes).padStart(2, "0")}:${String(remaining).padStart(2, "0")}`;
  };

  const elapsedFrom = (createdAt) => {
    const started = Date.parse(createdAt || "");
    if (!Number.isFinite(started)) return 0;
    return Math.max(0, (Date.now() - started) / 1000);
  };

  const formatTimestamp = (value) => {
    const parsed = Date.parse(value || "");
    if (!Number.isFinite(parsed)) return "";
    return new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    }).format(parsed);
  };

  const scrollFeed = ({ behavior = "smooth", force = false } = {}) => {
    const controller = window.VulnHunterConversationScroll;
    if (controller?.scrollToLatest) {
      controller.scrollToLatest({ behavior, force });
      return;
    }
    if (!force && feed.dataset.followLatest === "false") return;
    window.requestAnimationFrame(() => {
      feed.scrollTo({ top: feed.scrollHeight, behavior });
    });
  };

  const updateBusyCopy = () => {
    if (!thinkingCopy || !requestBusy) return;
    const seconds = Math.max(0, Math.floor((Date.now() - busyStartedAt) / 1000));
    thinkingCopy.textContent = seconds ? `${busyBaseCopy} · ${seconds}s` : busyBaseCopy;
  };

  const setBusy = (busy, copy = "Understanding the request…") => {
    requestBusy = busy;
    if (send) send.disabled = busy;
    input.disabled = busy;
    if (thinking) thinking.hidden = !busy;
    if (busyTimer) window.clearInterval(busyTimer);
    busyTimer = null;
    if (busy) {
      busyBaseCopy = copy;
      busyStartedAt = Date.now();
      updateBusyCopy();
      busyTimer = window.setInterval(updateBusyCopy, 1000);
      scrollFeed({ force: true });
    }
  };

  const messageKey = (message) =>
    [message.timestamp || "", message.role || "", message.kind || "", message.content || ""].join("|");

  const appendMessage = (message, { animate = false, forceScroll = true } = {}) => {
    if (!message || typeof message !== "object") return;
    const key = messageKey(message);
    if (renderedMessages.has(key)) return;
    renderedMessages.add(key);

    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const body = fragment.querySelector(".vh-message-body");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    const role = message.role === "user" ? "user" : "assistant";
    const kind = text(message.kind || "text");
    article.classList.add(`is-${role}`, `is-${kind}`);
    avatar.textContent = role === "user" ? "You" : "VH";

    const content = text(message.content || "");
    if (
      animate &&
      role === "assistant" &&
      content &&
      !window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      copy.textContent = "";
      const words = content.split(" ");
      let index = 0;
      const interval = window.setInterval(() => {
        copy.textContent += `${index ? " " : ""}${words[index] || ""}`;
        index += 1;
        if (index >= words.length) window.clearInterval(interval);
      }, 18);
    } else {
      copy.textContent = content;
    }

    const metadata = message.metadata && typeof message.metadata === "object" ? message.metadata : {};
    const suggestions = Array.isArray(metadata.suggestions) ? metadata.suggestions : [];
    suggestions.forEach((suggestion) => {
      if (!suggestion || typeof suggestion !== "object") return;
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vh-message-suggestion";
      button.textContent = text(suggestion.label || "Use suggestion");
      button.addEventListener("click", () => {
        input.value = text(suggestion.message || suggestion.label || "");
        resizeInput();
        input.focus();
      });
      actions.append(button);
    });
    if (!suggestions.length) actions.remove();

    const timestamp = formatTimestamp(message.timestamp);
    if (timestamp) {
      const time = document.createElement("time");
      time.className = "vh-message-time";
      time.dateTime = text(message.timestamp);
      time.textContent = timestamp;
      body.append(time);
    }

    feed.append(fragment);
    scrollFeed({ force: forceScroll });
  };

  const emptyBlock = (title, detail) => {
    const wrapper = document.createElement("div");
    wrapper.className = "vh-run-empty";
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = detail;
    wrapper.append(strong, span);
    return wrapper;
  };

  const appendFact = (container, label, value) => {
    const row = document.createElement("div");
    const small = document.createElement("small");
    const strong = document.createElement("strong");
    small.textContent = label;
    strong.textContent = text(value);
    row.append(small, strong);
    container.append(row);
  };

  const eventSummary = (event) => {
    if (!event || typeof event !== "object") return "Recorded assessment activity.";
    return text(event.summary || event.message || event.event_type || "Recorded assessment activity.");
  };

  const eventKey = (event) =>
    text(event?.sequence || event?.event_sha256 || `${event?.event_type || "event"}-${event?.timestamp || ""}`);

  const latestEvent = (run) => {
    const events = Array.isArray(run?.events) ? run.events : [];
    return events.length ? events[events.length - 1] : null;
  };

  const stageStatus = (run, key) => {
    const state = text(run.state);
    const terminalFailure = [
      "failed",
      "cancelled",
      "blocked",
      "denied",
      "timed_out",
      "readiness_blocked",
      "execution_blocked",
    ].includes(state);
    const approved = ["approved", "consumed"].includes(text(run.approval_state));
    const hasArtifacts = Array.isArray(run.artifacts) && run.artifacts.length > 0;
    const hasVerification = Boolean(run.evaluation_result) || (Array.isArray(run.findings) && run.findings.length > 0);
    const executing = ["queued", "running", "executing", "evaluating"].includes(state);
    const completed = state === "completed";

    if (key === "scope") return "complete";
    if (key === "plan") return run.approval ? "complete" : terminalFailure ? "error" : "complete";
    if (key === "approval") return approved ? "complete" : run.approval ? "active" : terminalFailure ? "error" : "waiting";
    if (key === "scanner") return completed ? "complete" : terminalFailure ? "error" : executing ? "active" : "waiting";
    if (key === "evidence") return hasArtifacts ? "complete" : terminalFailure ? "error" : completed ? "complete" : "waiting";
    if (key === "verification") return hasVerification ? "complete" : terminalFailure ? "error" : completed ? "complete" : "waiting";
    if (key === "complete") return completed ? "complete" : terminalFailure ? "error" : "waiting";
    return "waiting";
  };

  const currentStage = (run) => {
    const statuses = stageDefinitions.map(([key, label], index) => ({
      key,
      label,
      index,
      status: stageStatus(run, key),
    }));
    return (
      statuses.find((item) => item.status === "active") ||
      statuses.find((item) => item.status === "waiting") ||
      statuses[statuses.length - 1]
    );
  };

  const renderStages = (card, run) => {
    const track = card.querySelector("[data-run-stages]");
    track.replaceChildren();
    const row = document.createElement("div");
    row.className = `vh-run-stage-current ${run.terminal ? "is-complete" : "is-active"}`;
    const marker = document.createElement("span");
    marker.className = "vh-run-stage-marker";
    marker.textContent = run.terminal ? "✓" : "•";
    const body = document.createElement("div");
    const eyebrow = document.createElement("small");
    eyebrow.textContent = text(run.progress_label || "Assessment progress");
    const strong = document.createElement("strong");
    strong.textContent = text(run.current_step || "Preparing the governed assessment…");
    const paragraph = document.createElement("p");
    paragraph.textContent = text(run.check_progress || run.next_action || "");
    body.append(eyebrow, strong, paragraph);
    const duration = document.createElement("time");
    duration.dataset.runStageElapsed = "true";
    duration.textContent = text(run.elapsed_label || formatDuration(elapsedFrom(run.created_at)));
    row.append(marker, body, duration);
    const meter = document.createElement("div");
    meter.className = "vh-run-progress-meter";
    const fill = document.createElement("span");
    fill.style.width = `${Math.max(4, Number(run.progress_percent || 0))}%`;
    meter.append(fill);
    track.append(row, meter);
  };

  const renderSummary = (card, run) => {
    const body = card.querySelector("[data-summary-body]");
    body.replaceChildren();
    const grid = document.createElement("div");
    grid.className = "vh-run-facts";
    appendFact(grid, "Target", run.target || "Not recorded");
    appendFact(grid, "Profile", prettyState(run.profile));
    appendFact(grid, "Scanner", run.scanner || "Nuclei");
    appendFact(grid, "Execution", prettyState(run.execution_state));
    if (run.blocking_reason) appendFact(grid, "Current note", run.blocking_reason);
    body.append(grid);
  };

  const renderEvents = (card, run) => {
    const list = card.querySelector("[data-event-list]");
    const events = Array.isArray(run.events) ? run.events : [];
    const recent = events.slice(-4);
    list.replaceChildren();
    recent.forEach((event) => {
      const item = document.createElement("li");
      const marker = document.createElement("span");
      const body = document.createElement("div");
      const strong = document.createElement("strong");
      const paragraph = document.createElement("p");
      const time = document.createElement("time");
      marker.className = "vh-event-marker";
      strong.textContent = prettyState(event.event_type || event.type || "Activity");
      paragraph.textContent = eventSummary(event);
      time.dateTime = text(event.timestamp || event.created_at || "");
      time.textContent = formatTimestamp(event.timestamp || event.created_at) || text(event.timestamp || event.created_at || "");
      body.append(strong, paragraph, time);
      item.append(marker, body);
      list.append(item);
    });
    if (!events.length) {
      list.append(emptyBlock("Waiting for activity", "Scanner transitions will appear here as they happen."));
    }
    const suffix = events.length > recent.length ? ` · latest ${recent.length} shown` : "";
    card.querySelector("[data-progress-count]").textContent = `${events.length} event${events.length === 1 ? "" : "s"}${suffix}`;
    card.querySelector("[data-audit-count]").textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
  };

  const renderFindings = (card, run) => {
    const container = card.querySelector("[data-findings-list]");
    const findings = Array.isArray(run.findings) ? run.findings : [];
    container.replaceChildren();
    findings.forEach((finding) => {
      const item = document.createElement("article");
      item.className = "vh-finding-row";
      const severity = document.createElement("span");
      severity.className = `vh-finding-severity is-${text(finding.severity || "info").toLowerCase()}`;
      severity.textContent = prettyState(finding.severity || "info");
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      const detail = document.createElement("small");
      title.textContent = text(finding.title || "Candidate finding");
      detail.textContent = `${prettyState(finding.verification || "candidate")} · ${text(finding.target || run.target)}`;
      copy.append(title, detail);
      item.append(severity, copy);
      container.append(item);
    });
    if (!findings.length && run.terminal) {
      container.append(emptyBlock("No persisted finding", "No evidence-backed finding was produced by this assessment."));
    }
    card.querySelector("[data-findings-count]").textContent = String(findings.length);
    card.querySelector("[data-summary-findings]").textContent = String(findings.length);
  };

  const renderEvidence = (card, run) => {
    const container = card.querySelector("[data-evidence-list]");
    const artifacts = Array.isArray(run.artifacts) ? run.artifacts : [];
    container.replaceChildren();
    artifacts.forEach((artifact) => {
      const item = document.createElement("article");
      item.className = "vh-evidence-row";
      const icon = document.createElement("span");
      icon.textContent = "EV";
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      const detail = document.createElement("code");
      title.textContent = text(artifact.filename || "Evidence artifact");
      detail.textContent = `${text(artifact.type || "evidence")} · ${Number(artifact.size || 0).toLocaleString()} bytes · ${text(artifact.checksum || "").slice(0, 24)}${artifact.checksum ? "…" : ""}`;
      copy.append(title, detail);
      item.append(icon, copy);
      container.append(item);
    });
    card.querySelector("[data-evidence-count]").textContent = String(artifacts.length);
    card.querySelector("[data-summary-evidence]").textContent = String(artifacts.length);
  };

  const renderVerification = (card, run) => {
    const container = card.querySelector("[data-verification-body]");
    container.replaceChildren();
    const result = run.evaluation_result;
    if (result) {
      const panel = document.createElement("div");
      panel.className = "vh-verification-result is-ready";
      const strong = document.createElement("strong");
      strong.textContent = prettyState(result);
      const span = document.createElement("span");
      span.textContent = "The recorded result is backed by persisted scanner evidence.";
      panel.append(strong, span);
      container.append(panel);
    } else if (run.analysis_note) {
      container.append(emptyBlock("Deterministic evidence summary", run.analysis_note));
    } else if (run.terminal) {
      container.append(emptyBlock("Verification complete", "Review the persisted findings and evidence."));
    }
    card.querySelector("[data-verification-state]").textContent = result ? prettyState(result) : run.terminal ? "Not recorded" : "Pending";
  };

  const renderGuidance = (card, run) => {
    const container = card.querySelector("[data-guidance-body]");
    const findings = Array.isArray(run.findings) ? run.findings : [];
    container.replaceChildren();
    if (!findings.length) return;
    const list = document.createElement("ol");
    list.className = "vh-guidance-list";
    [
      "Confirm the affected service and reproduce only within the authorised scope.",
      "Apply the control recommended by the finding and preserve the change record.",
      "Run a bounded remediation retest and compare the new evidence with this assessment.",
    ].forEach((copy) => {
      const item = document.createElement("li");
      item.textContent = copy;
      list.append(item);
    });
    container.append(list);
  };

  const renderTechnical = (card, run) => {
    const container = card.querySelector("[data-technical-body]");
    container.replaceChildren();
    const grid = document.createElement("div");
    grid.className = "vh-run-facts";
    appendFact(grid, "Run ID", run.run_id);
    appendFact(grid, "Task state", prettyState(run.task_state));
    appendFact(grid, "Approval state", prettyState(run.approval_state));
    appendFact(grid, "Last update", run.updated_at || "Not recorded");
    container.append(grid);
  };

  const renderApproval = (card, run) => {
    const panel = card.querySelector("[data-inline-approval]");
    const approval = confirmedRuns.has(text(run.run_id)) ? null : run.approval;
    panel.hidden = !approval;
    if (!approval) return;
    panel.dataset.requestId = text(approval.request_id);
    panel.dataset.planDigest = text(approval.plan_digest);
    panel.querySelector("[data-approval-summary]").textContent = text(approval.summary || "Review this exact plan.");
    panel.querySelector("[data-approval-target]").textContent = text(approval.target || run.target);
    panel.querySelector("[data-approval-port]").textContent = text(approval.port || "Not recorded");
    panel.querySelector("[data-approval-profile]").textContent = prettyState(approval.profile || run.profile);
    panel.querySelector("[data-approval-scanner]").textContent = text(approval.scanner || run.scanner);
    const templateCount = Number(approval.template_count || 0);
    panel.querySelector("[data-approval-templates]").textContent = templateCount
      ? `${templateCount} reviewed template${templateCount === 1 ? "" : "s"}`
      : "No reviewed templates selected";
    const rateLimit = Number(approval.rate_limit || 0);
    const concurrency = Number(approval.concurrency || 0);
    panel.querySelector("[data-approval-limits]").textContent =
      rateLimit && concurrency
        ? `${rateLimit} request${rateLimit === 1 ? "" : "s"}/sec · concurrency ${concurrency}`
        : "Limits unavailable";
    panel.querySelector("[data-approval-digest]").textContent = text(approval.plan_digest || "");
    panel.querySelector("[data-approval-risk]").textContent = text(approval.risk_summary || "Execution remains bounded to this exact plan.");
  };

  const setSectionVisibility = (card, run) => {
    const events = Array.isArray(run.events) ? run.events : [];
    const findings = Array.isArray(run.findings) ? run.findings : [];
    const artifacts = Array.isArray(run.artifacts) ? run.artifacts : [];
    const rules = {
      summary: Boolean(run.terminal),
      progress: false,
      findings: findings.length > 0 || Boolean(run.terminal),
      evidence: artifacts.length > 0,
      verification: Boolean(run.evaluation_result) || Boolean(run.analysis_note),
      guidance: findings.length > 0,
      technical: true,
    };
    Object.entries(rules).forEach(([section, visible]) => {
      const detail = card.querySelector(`[data-section="${section}"]`);
      if (!detail) return;
      detail.hidden = !visible;
      if (!visible) detail.open = false;
    });
  };

  const normalizeRun = (run) => {
    if (!run || typeof run !== "object") return run;
    if (!confirmedRuns.has(text(run.run_id))) return run;
    return {
      ...run,
      approval: null,
      approval_state: ["approved", "consumed"].includes(text(run.approval_state))
        ? run.approval_state
        : "approved",
    };
  };

  const updateRunCard = (card, candidateRun) => {
    const run = normalizeRun(candidateRun);
    card.dataset.runId = text(run.run_id);
    card.className = `vh-run-card is-${text(run.state || "unknown")}`;
    card.querySelector("[data-run-state]").textContent = prettyState(run.state);
    card.querySelector("[data-run-target]").textContent = text(run.target || "Assessment");
    card.querySelector("[data-run-profile]").textContent = prettyState(run.profile);
    card.querySelector("[data-run-scanner]").textContent = text(run.scanner || "Nuclei");
    card.querySelector("[data-run-elapsed]").textContent = formatDuration(elapsedFrom(run.created_at));
    const latest = latestEvent(run);
    const liveCopy = card.querySelector("[data-run-live-copy]");
    if (liveCopy) liveCopy.textContent = text(run.current_step || eventSummary(latest));
    card.querySelector("[data-summary-state]").textContent = prettyState(run.state);
    card.querySelector("[data-summary-approval]").textContent = prettyState(run.approval_state);
    card.querySelector("[data-section-summary-state]").textContent = run.terminal ? "Finished" : "In progress";
    const detailLink = card.querySelector("[data-run-detail-link]");
    const findingsLink = card.querySelector("[data-findings-link]");
    detailLink.href = text(run.detail_url || "#");
    findingsLink.href = text(run.findings_url || "#");
    renderApproval(card, run);
    renderStages(card, run);
    renderSummary(card, run);
    renderEvents(card, run);
    renderFindings(card, run);
    renderEvidence(card, run);
    renderVerification(card, run);
    renderGuidance(card, run);
    renderTechnical(card, run);
    setSectionVisibility(card, run);
  };

  const ensureRunCard = (run, { forceScroll = false } = {}) => {
    if (!runCard || runCard.dataset.runId !== text(run.run_id)) {
      runCard?.remove();
      const fragment = runTemplate.content.cloneNode(true);
      runCard = fragment.querySelector("[data-run-card]");
      feed.append(fragment);
      bindRunControls(runCard);
    }
    updateRunCard(runCard, run);
    scrollFeed({ force: forceScroll });
  };

  const runSignature = (run) => {
    if (!run) return "";
    return JSON.stringify({
      id: run.run_id,
      state: run.state,
      approval_state: run.approval_state,
      approval: run.approval?.request_id || null,
      execution_state: run.execution_state,
      last_sequence: run.last_sequence,
      findings: Array.isArray(run.findings) ? run.findings.length : 0,
      artifacts: Array.isArray(run.artifacts) ? run.artifacts.length : 0,
      evaluation_result: run.evaluation_result,
      blocking_reason: run.blocking_reason,
      current_step: run.current_step,
      final_message: run.final_message,
      terminal: run.terminal,
    });
  };

  const announceRunProgress = (previous, next) => {
    const previousState = text(previous?.state);
    const nextState = text(next?.state);
    if (previousState === nextState && !next.terminal) return;
    const key = `${text(next.run_id)}:${nextState}:${next.terminal ? "terminal" : "live"}`;
    if (announcedEvents.has(key)) return;
    announcedEvents.add(key);
    const copy = next.terminal ? next.final_message : next.current_step;
    if (!copy) return;
    appendMessage(
      {
        role: "assistant",
        kind: next.terminal ? "result" : "status",
        content: copy,
        timestamp: next.updated_at || new Date().toISOString(),
      },
      { animate: true, forceScroll: false },
    );
  };

  const postForm = async (url, values) => {
    const payload = new FormData();
    Object.entries(values).forEach(([key, value]) => payload.append(key, text(value)));
    const response = await fetch(url, {
      method: "POST",
      body: payload,
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken, Accept: "application/json" },
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_error) {
      data = { detail: "The server returned an unreadable response." };
    }
    if (!response.ok) throw new Error(data.detail || data.message?.content || "The request could not be completed.");
    return data;
  };

  const approveRun = async (card) => {
    const panel = card.querySelector("[data-inline-approval]");
    const note = panel.querySelector("[data-approval-note]");
    const button = panel.querySelector("[data-approval-confirm]");
    const reason = note.value.trim();
    if (reason.length < 8) {
      note.focus();
      note.setCustomValidity("Enter at least eight characters.");
      note.reportValidity();
      note.setCustomValidity("");
      return;
    }
    button.disabled = true;
    setBusy(true, "Recording confirmation and releasing the signed job…");
    try {
      const data = await postForm(initial.approval_url, {
        request_id: panel.dataset.requestId,
        plan_digest: panel.dataset.planDigest,
        reason,
      });
      const runId = text(data.run?.run_id || card.dataset.runId);
      if (runId) confirmedRuns.add(runId);
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.clear_run) {
        if (pollTimer) window.clearTimeout(pollTimer);
        runCard?.remove();
        runCard = null;
        activeRun = null;
        lastRunSignature = "";
      }
      if (data.run) {
        activeRun = normalizeRun(data.run);
        lastRunSignature = runSignature(activeRun);
        ensureRunCard(activeRun, { forceScroll: true });
        beginPolling(activeRun, { immediate: true });
      }
    } catch (error) {
      appendMessage(
        { role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() },
        { animate: true },
      );
    } finally {
      button.disabled = false;
      setBusy(false);
    }
  };

  const cancelRun = async (card) => {
    const target = card.querySelector("[data-run-target]")?.textContent || "this assessment";
    input.value = `Cancel the current assessment for ${target}`;
    resizeInput();
    form.requestSubmit();
  };

  const bindRunControls = (card) => {
    card.querySelector("[data-approval-confirm]")?.addEventListener("click", () => approveRun(card));
    card.querySelector("[data-approval-cancel]")?.addEventListener("click", () => cancelRun(card));
    card.querySelectorAll("details").forEach((detail) => {
      detail.addEventListener("toggle", () => {
        if (!detail.open) return;
        card.querySelectorAll("details[open]").forEach((other) => {
          if (other !== detail) other.open = false;
        });
      });
    });
  };

  const fetchStatus = async (runId) => {
    const url = text(initial.status_url_template).replace("RUN_ID", encodeURIComponent(runId));
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Assessment status is unavailable.");
    return normalizeRun(data.run);
  };

  const beginPolling = (run, { immediate = false } = {}) => {
    if (pollTimer) window.clearTimeout(pollTimer);
    if (!run || run.terminal) return;
    const tick = async () => {
      try {
        const previous = activeRun;
        const next = await fetchStatus(run.run_id);
        const signature = runSignature(next);
        if (signature !== lastRunSignature) {
          announceRunProgress(previous, next);
          activeRun = next;
          lastRunSignature = signature;
          ensureRunCard(activeRun);
        }
        if (!next.terminal) pollTimer = window.setTimeout(tick, 1500);
      } catch (_error) {
        pollTimer = window.setTimeout(tick, 4000);
      }
    };
    pollTimer = window.setTimeout(tick, immediate ? 100 : 1200);
  };

  const resizeInput = () => {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
  };

  const openHistory = (open) => {
    if (!historyPanel || !historyToggle) return;
    historyPanel.hidden = !open;
    historyPanel.classList.toggle("is-open", open);
    historyToggle.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) historyClose?.focus();
  };

  historyToggle?.addEventListener("click", () => openHistory(historyPanel?.hidden !== false));
  historyClose?.addEventListener("click", () => openHistory(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && historyPanel && !historyPanel.hidden) openHistory(false);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (requestBusy) return;
    const value = input.value.trim();
    if (!value) return;
    appendMessage({ role: "user", kind: "text", content: value, timestamp: new Date().toISOString() });
    input.value = "";
    resizeInput();

    setBusy(true, "Understanding your request and checking authorised scope…");
    try {
      const data = await postForm(initial.message_url, { message: value });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.clear_run) {
        if (pollTimer) window.clearTimeout(pollTimer);
        runCard?.remove();
        runCard = null;
        activeRun = null;
        lastRunSignature = "";
      }
      if (data.run) {
        activeRun = normalizeRun(data.run);
        lastRunSignature = runSignature(activeRun);
        (activeRun.events || []).forEach((item) => announcedEvents.add(eventKey(item)));
        ensureRunCard(activeRun, { forceScroll: true });
        beginPolling(activeRun);
      }
    } catch (error) {
      appendMessage(
        { role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() },
        { animate: true },
      );
    } finally {
      setBusy(false);
      input.focus();
    }
  });

  input.addEventListener("input", resizeInput);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  reset?.addEventListener("click", async () => {
    if (requestBusy) return;
    setBusy(true, "Starting a clean conversation…");
    try {
      const data = await postForm(initial.reset_url, {});
      if (pollTimer) window.clearTimeout(pollTimer);
      renderedMessages.clear();
      announcedEvents.clear();
      confirmedRuns.clear();
      feed.replaceChildren();
      runCard = null;
      activeRun = null;
      lastRunSignature = "";
      (data.messages || []).forEach((message) => appendMessage(message, { forceScroll: false }));
      scrollFeed({ behavior: "auto", force: true });
    } catch (error) {
      appendMessage({ role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() });
    } finally {
      setBusy(false);
      input.focus();
    }
  });

  (initial.messages || []).forEach((message) => appendMessage(message, { forceScroll: false }));
  if (activeRun) {
    activeRun = normalizeRun(activeRun);
    lastRunSignature = runSignature(activeRun);
    (activeRun.events || []).forEach((item) => announcedEvents.add(eventKey(item)));
    ensureRunCard(activeRun);
    beginPolling(activeRun);
  }
  resizeInput();
  input.focus({ preventScroll: true });
  scrollFeed({ behavior: "auto", force: true });

  window.setInterval(() => {
    if (!runCard || !activeRun) return;
    const duration = formatDuration(elapsedFrom(activeRun.created_at));
    const elapsed = runCard.querySelector("[data-run-elapsed]");
    const stageElapsed = runCard.querySelector("[data-run-stage-elapsed]");
    if (elapsed) elapsed.textContent = duration;
    if (stageElapsed) stageElapsed.textContent = duration;
  }, 1000);
})();
