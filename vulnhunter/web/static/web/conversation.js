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
  const messageTemplate = document.getElementById("vh-message-template");
  const runTemplate = document.getElementById("vh-run-template");
  const csrfToken = form?.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";

  if (!feed || !form || !input || !messageTemplate || !runTemplate) return;

  let activeRun = initial.active_run || null;
  let runCard = null;
  let pollTimer = null;
  let requestBusy = false;
  const renderedMessages = new Set();
  const stageDefinitions = [
    ["scope", "Scope validated"],
    ["plan", "Assessment plan prepared"],
    ["approval", "Approval recorded"],
    ["scanner", "Nuclei assessment"],
    ["evidence", "Evidence stored"],
    ["verification", "Findings verified"],
    ["complete", "Assessment completed"],
  ];

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const escapeText = (value) => text(value);

  const messageKey = (message) =>
    [message.timestamp || "", message.role || "", message.kind || "", message.content || ""].join("|");

  const scrollFeed = (behavior = "smooth") => {
    window.requestAnimationFrame(() => {
      const target = document.documentElement.scrollHeight;
      window.scrollTo({ top: target, behavior });
    });
  };

  const setBusy = (busy, copy = "Understanding the request…") => {
    requestBusy = busy;
    if (send) send.disabled = busy;
    input.disabled = busy;
    if (thinking) thinking.hidden = !busy;
    if (thinkingCopy) thinkingCopy.textContent = copy;
    if (busy) scrollFeed();
  };

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

  const prettyState = (value) =>
    text(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const messageAvatar = (role) => (role === "user" ? "You" : "VH");

  const appendMessage = (message, { animate = false } = {}) => {
    if (!message || typeof message !== "object") return;
    const key = messageKey(message);
    if (renderedMessages.has(key)) return;
    renderedMessages.add(key);

    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    const role = message.role === "user" ? "user" : "assistant";
    const kind = text(message.kind || "text");
    article.classList.add(`is-${role}`, `is-${kind}`);
    avatar.textContent = messageAvatar(role);

    const content = escapeText(message.content || "");
    if (animate && role === "assistant" && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      copy.textContent = "";
      const words = content.split(" ");
      let index = 0;
      const interval = window.setInterval(() => {
        copy.textContent += `${index ? " " : ""}${words[index] || ""}`;
        index += 1;
        if (index >= words.length) window.clearInterval(interval);
      }, 22);
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

    feed.append(fragment);
    scrollFeed();
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

  const stageStatus = (run, key) => {
    const state = text(run.state);
    const terminalFailure = ["failed", "cancelled", "blocked", "denied", "timed_out", "readiness_blocked", "execution_blocked"].includes(state);
    const approved = ["approved", "consumed"].includes(text(run.approval_state));
    const hasArtifacts = Array.isArray(run.artifacts) && run.artifacts.length > 0;
    const hasVerification = Boolean(run.evaluation_result) || (Array.isArray(run.findings) && run.findings.length > 0);
    const executing = ["queued", "running", "executing", "evaluating"].includes(state);
    const completed = state === "completed";

    if (key === "scope") return "complete";
    if (key === "plan") return run.approval ? "complete" : terminalFailure ? "error" : "active";
    if (key === "approval") return approved ? "complete" : run.approval ? "active" : terminalFailure ? "error" : "waiting";
    if (key === "scanner") return completed ? "complete" : terminalFailure ? "error" : executing ? "active" : "waiting";
    if (key === "evidence") return hasArtifacts ? "complete" : terminalFailure ? "error" : completed ? "waiting" : "waiting";
    if (key === "verification") return hasVerification ? "complete" : terminalFailure ? "error" : completed ? "waiting" : "waiting";
    if (key === "complete") return completed ? "complete" : terminalFailure ? "error" : "waiting";
    return "waiting";
  };

  const renderStages = (card, run) => {
    const track = card.querySelector("[data-run-stages]");
    track.replaceChildren();
    stageDefinitions.forEach(([key, label], index) => {
      const status = stageStatus(run, key);
      const item = document.createElement("div");
      item.className = `vh-run-stage is-${status}`;
      const marker = document.createElement("span");
      marker.textContent = status === "complete" ? "✓" : status === "error" ? "!" : String(index + 1).padStart(2, "0");
      const body = document.createElement("span");
      const strong = document.createElement("strong");
      const small = document.createElement("small");
      strong.textContent = label;
      small.textContent = status === "complete" ? "Completed" : status === "active" ? "Working" : status === "error" ? "Stopped" : "Waiting";
      body.append(strong, small);
      item.append(marker, body);
      track.append(item);
    });
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

  const eventSummary = (event) => {
    if (!event || typeof event !== "object") return "Recorded assessment event";
    return text(event.summary || event.message || event.event_type || "Recorded assessment event");
  };

  const renderEvents = (card, run) => {
    const list = card.querySelector("[data-event-list]");
    const events = Array.isArray(run.events) ? run.events : [];
    list.replaceChildren();
    events.forEach((event) => {
      const item = document.createElement("li");
      const marker = document.createElement("span");
      const body = document.createElement("div");
      const strong = document.createElement("strong");
      const paragraph = document.createElement("p");
      const time = document.createElement("time");
      marker.className = "vh-event-marker";
      strong.textContent = prettyState(event.event_type || event.type || "Activity");
      paragraph.textContent = eventSummary(event);
      time.textContent = text(event.timestamp || event.created_at || "");
      body.append(strong, paragraph, time);
      item.append(marker, body);
      list.append(item);
    });
    if (!events.length) list.append(emptyBlock("Waiting for activity", "Recorded scanner transitions will appear here."));
    card.querySelector("[data-progress-count]").textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
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
    if (!findings.length) {
      container.append(
        emptyBlock(
          run.terminal ? "No persisted finding" : "Findings not ready",
          run.terminal ? "No evidence-backed finding was produced by this assessment." : "Candidate observations will be organised here after evidence verification."
        )
      );
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
    if (!artifacts.length) container.append(emptyBlock("No evidence yet", "Validated artifacts will appear after scanner execution."));
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
    } else {
      container.append(
        emptyBlock(
          run.terminal ? "No independent result recorded" : "Verification pending",
          run.terminal
            ? "Review candidate findings and evidence before treating them as confirmed."
            : "Evidence verification begins after Nuclei returns its observations."
        )
      );
    }
    const label = result ? prettyState(result) : run.terminal ? "Not recorded" : "Pending";
    card.querySelector("[data-verification-state]").textContent = label;
  };

  const renderGuidance = (card, run) => {
    const container = card.querySelector("[data-guidance-body]");
    const findings = Array.isArray(run.findings) ? run.findings : [];
    container.replaceChildren();
    if (!findings.length) {
      container.append(emptyBlock("Guidance follows findings", "Remediation guidance appears when a persisted finding is available."));
      return;
    }
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
    const approval = run.approval;
    panel.hidden = !approval;
    if (!approval) return;
    panel.dataset.requestId = text(approval.request_id);
    panel.dataset.planDigest = text(approval.plan_digest);
    panel.querySelector("[data-approval-summary]").textContent = text(approval.summary || "Review this exact plan.");
    panel.querySelector("[data-approval-target]").textContent = text(approval.target || run.target);
    panel.querySelector("[data-approval-profile]").textContent = prettyState(approval.profile || run.profile);
    panel.querySelector("[data-approval-scanner]").textContent = text(approval.scanner || run.scanner);
    panel.querySelector("[data-approval-digest]").textContent = text(approval.plan_digest || "");
    panel.querySelector("[data-approval-risk]").textContent = text(approval.risk_summary || "Execution remains bounded to this exact plan.");
  };

  const updateRunCard = (card, run) => {
    card.dataset.runId = text(run.run_id);
    card.className = `vh-run-card is-${text(run.state || "unknown")}`;
    card.querySelector("[data-run-state]").textContent = prettyState(run.state);
    card.querySelector("[data-run-target]").textContent = text(run.target || "Assessment");
    card.querySelector("[data-run-profile]").textContent = prettyState(run.profile);
    card.querySelector("[data-run-scanner]").textContent = text(run.scanner || "Nuclei");
    card.querySelector("[data-run-elapsed]").textContent = formatDuration(elapsedFrom(run.created_at));
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
  };

  const ensureRunCard = (run) => {
    if (!runCard || runCard.dataset.runId !== text(run.run_id)) {
      const fragment = runTemplate.content.cloneNode(true);
      runCard = fragment.querySelector("[data-run-card]");
      feed.append(fragment);
      bindRunControls(runCard);
    }
    updateRunCard(runCard, run);
    scrollFeed();
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
    setBusy(true, "Recording approval and signing the Nuclei job…");
    try {
      const data = await postForm(initial.approval_url, {
        request_id: panel.dataset.requestId,
        plan_digest: panel.dataset.planDigest,
        reason,
      });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.run) {
        activeRun = data.run;
        ensureRunCard(activeRun);
        beginPolling(activeRun);
      }
    } catch (error) {
      appendMessage({ role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() }, { animate: true });
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
        if (!detail.open || window.innerWidth > 700) return;
        card.querySelectorAll("details[open]").forEach((other) => {
          if (other !== detail) other.open = false;
        });
      });
    });
  };

  const fetchStatus = async (runId) => {
    const url = text(initial.status_url_template).replace("RUN_ID", encodeURIComponent(runId));
    const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Assessment status is unavailable.");
    return data.run;
  };

  const beginPolling = (run) => {
    if (pollTimer) window.clearTimeout(pollTimer);
    if (!run || run.terminal) return;
    const tick = async () => {
      try {
        activeRun = await fetchStatus(run.run_id);
        ensureRunCard(activeRun);
        if (!activeRun.terminal) pollTimer = window.setTimeout(tick, 1500);
      } catch (_error) {
        pollTimer = window.setTimeout(tick, 4000);
      }
    };
    pollTimer = window.setTimeout(tick, 1200);
  };

  const resizeInput = () => {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (requestBusy) return;
    const value = input.value.trim();
    if (!value) return;
    const userMessage = { role: "user", kind: "text", content: value, timestamp: new Date().toISOString() };
    appendMessage(userMessage);
    input.value = "";
    resizeInput();
    setBusy(true, "Understanding the request and checking authorised scope…");
    try {
      const data = await postForm(initial.message_url, { message: value });
      if (data.message) appendMessage(data.message, { animate: true });
      if (data.run) {
        activeRun = data.run;
        ensureRunCard(activeRun);
        beginPolling(activeRun);
      }
    } catch (error) {
      appendMessage({ role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() }, { animate: true });
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
      feed.replaceChildren();
      runCard = null;
      activeRun = null;
      (data.messages || []).forEach((message) => appendMessage(message));
    } catch (error) {
      appendMessage({ role: "assistant", kind: "error", content: error.message, timestamp: new Date().toISOString() });
    } finally {
      setBusy(false);
      input.focus();
    }
  });

  (initial.messages || []).forEach((message) => appendMessage(message));
  if (activeRun) {
    ensureRunCard(activeRun);
    beginPolling(activeRun);
  }
  resizeInput();
  input.focus({ preventScroll: true });

  window.setInterval(() => {
    if (!runCard || !activeRun) return;
    const elapsed = runCard.querySelector("[data-run-elapsed]");
    if (elapsed) elapsed.textContent = formatDuration(elapsedFrom(activeRun.created_at));
  }, 1000);
})();
