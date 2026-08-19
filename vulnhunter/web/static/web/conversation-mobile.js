(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = workspace?.querySelector("[data-conversation-form]");
  const feed = workspace?.querySelector("[data-conversation-feed]");
  const input = workspace?.querySelector("[data-conversation-input]");
  const send = workspace?.querySelector("[data-conversation-send]");
  const attachButton = workspace?.querySelector("[data-conversation-attach]");
  const fileInput = workspace?.querySelector("[data-conversation-file]");
  const tray = workspace?.querySelector("[data-attachment-tray]");
  const thinking = workspace?.querySelector("[data-conversation-thinking]");
  const thinkingCopy = workspace?.querySelector("[data-thinking-copy]");
  const reset = workspace?.querySelector("[data-conversation-reset]");
  const messageTemplate = document.getElementById("vh-message-template");
  if (!form || !feed || !input || !attachButton || !fileInput || !tray || !messageTemplate) return;

  const csrfToken = form.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  const attachmentUrl = form.dataset.attachmentUrl || "";
  const uploadStartUrl = form.dataset.uploadStartUrl || "";
  const mobileMessageUrl = form.dataset.mobileMessageUrl || "";
  const mobileActivityTemplate = form.dataset.mobileActivityStreamUrlTemplate || "";
  let activeAttachment = null;
  let mobileBusy = false;
  let mobileActivitySource = null;
  let mobileActivityReconnect = null;
  let mobileActivitySequence = 0;
  let mobileActivityRunId = "";
  const mobileActivityKeys = new Set();

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const scrollLatest = () => {
    const controller = window.VulnHunterConversationScroll;
    if (controller?.scrollToLatest) {
      controller.scrollToLatest({ behavior: "smooth", force: true });
      return;
    }
    window.requestAnimationFrame(() => feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" }));
  };

  const setBusy = (busy, copy) => {
    mobileBusy = busy;
    attachButton.disabled = busy;
    fileInput.disabled = busy;
    if (send) send.disabled = busy;
    if (thinking) thinking.hidden = !busy;
    if (thinkingCopy && copy) thinkingCopy.textContent = copy;
    if (busy) scrollLatest();
  };

  const readJson = async (response) => {
    try {
      return await response.json();
    } catch (_error) {
      return { detail: "The server returned an unreadable response." };
    }
  };

  const postForm = async (url, payload) => {
    const response = await fetch(url, {
      method: "POST",
      body: payload,
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken, Accept: "application/json" },
    });
    const data = await readJson(response);
    if (!response.ok) throw new Error(data.detail || data.message?.content || "The request failed.");
    return data;
  };

  const getJson = async (url) => {
    const response = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const data = await readJson(response);
    if (!response.ok) throw new Error(data.detail || "The status request failed.");
    return data;
  };

  const closeMobileActivityStream = () => {
    if (mobileActivityReconnect) window.clearTimeout(mobileActivityReconnect);
    mobileActivityReconnect = null;
    mobileActivitySource?.close();
    mobileActivitySource = null;
  };

  const appendMobileActivity = (event) => {
    if (!event || typeof event !== "object") return;
    const key = text(event.event_id || `${event.sequence}|${event.event_type}|${event.summary}`);
    if (mobileActivityKeys.has(key)) return;
    mobileActivityKeys.add(key);
    const detail = event.metadata?.reason ? ` ${text(event.metadata.reason)}` : "";
    appendMessage(
      {
        role: "assistant",
        kind: "activity",
        content: `${text(event.summary || "APK assessment activity.")}${detail}`,
        timestamp: event.timestamp,
      },
      { animate: true },
    );
  };

  const openMobileActivityStream = (runId) => {
    if (!mobileActivityTemplate || !runId || !("EventSource" in window)) return;
    if (mobileActivityRunId !== runId) {
      mobileActivityRunId = runId;
      mobileActivitySequence = 0;
      mobileActivityKeys.clear();
    }
    closeMobileActivityStream();
    const url = new URL(
      mobileActivityTemplate.replace("RUN_ID", encodeURIComponent(runId)),
      window.location.href,
    );
    url.searchParams.set("after_sequence", String(mobileActivitySequence));
    const source = new EventSource(url.toString(), { withCredentials: true });
    mobileActivitySource = source;
    source.addEventListener("activity", (message) => {
      if (mobileActivitySource !== source) return;
      try {
        const payload = JSON.parse(message.data);
        (Array.isArray(payload.events) ? payload.events : []).forEach(appendMobileActivity);
        mobileActivitySequence = Math.max(
          mobileActivitySequence,
          Number(payload.last_sequence || 0),
        );
        source.close();
        mobileActivitySource = null;
        if (!payload.terminal) {
          mobileActivityReconnect = window.setTimeout(
            () => openMobileActivityStream(runId),
            payload.events?.length ? 120 : 1500,
          );
        }
      } catch (_error) {
        source.close();
        mobileActivitySource = null;
        mobileActivityReconnect = window.setTimeout(() => openMobileActivityStream(runId), 1500);
      }
    });
    source.onerror = () => {
      if (mobileActivitySource !== source) return;
      source.close();
      mobileActivitySource = null;
      mobileActivityReconnect = window.setTimeout(() => openMobileActivityStream(runId), 1500);
    };
  };

  const attachmentCard = (attachment, { removable = false } = {}) => {
    const card = document.createElement("div");
    card.className = "vh-apk-attachment-card";
    const icon = document.createElement("span");
    icon.className = "vh-apk-attachment-icon";
    icon.textContent = "APK";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = text(attachment.original_filename || "Android application.apk");
    const detail = document.createElement("small");
    const native = Number(attachment.native_library_count || 0);
    detail.textContent = `${formatBytes(attachment.size_bytes)} · ${Number(attachment.dex_count || 0)} DEX${native ? ` · ${native} native` : ""}`;
    const digest = document.createElement("code");
    digest.textContent = `SHA-256 ${text(attachment.artifact_sha256).slice(0, 18)}…`;
    copy.append(title, detail, digest);
    card.append(icon, copy);
    if (removable) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "vh-apk-attachment-remove";
      remove.setAttribute("aria-label", "Remove APK attachment");
      remove.textContent = "×";
      remove.addEventListener("click", () => {
        activeAttachment = null;
        fileInput.value = "";
        tray.replaceChildren();
        tray.hidden = true;
        attachButton.focus();
      });
      card.append(remove);
    }
    return card;
  };

  const renderTray = (attachment) => {
    tray.replaceChildren(attachmentCard(attachment, { removable: true }));
    tray.hidden = false;
  };

  const renderUploadProgress = (file, received) => {
    const total = Math.max(1, Number(file.size) || 1);
    const transferred = Math.min(total, Math.max(0, Number(received) || 0));
    const shell = document.createElement("div");
    shell.className = "vh-apk-uploading";
    const marker = document.createElement("span");
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `Uploading ${file.name}`;
    const detail = document.createElement("small");
    detail.textContent = `${formatBytes(transferred)} of ${formatBytes(total)} · ${Math.floor((transferred / total) * 100)}%`;
    const progress = document.createElement("progress");
    progress.max = total;
    progress.value = transferred;
    copy.append(title, detail, progress);
    shell.append(marker, copy);
    tray.replaceChildren(shell);
    tray.hidden = false;
  };

  const appendMessage = (message, { attachment = null, plan = null, error = false } = {}) => {
    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const body = fragment.querySelector(".vh-message-body");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    const role = message.role === "user" ? "user" : "assistant";
    article.classList.add(`is-${role}`, error ? "is-error" : `is-${text(message.kind || "text")}`);
    avatar.textContent = role === "user" ? "You" : "VH";
    copy.textContent = text(message.content || "");
    if (attachment) body.insertBefore(attachmentCard(attachment), copy);

    let planCard = null;
    if (plan) {
      planCard = renderPlan(plan);
      body.append(planCard);
    }

    const suggestions = Array.isArray(message.metadata?.suggestions)
      ? message.metadata.suggestions
      : [];
    suggestions.forEach((suggestion) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vh-message-suggestion";
      button.textContent = text(suggestion.label || "Use suggestion");
      button.addEventListener("click", () => {
        input.value = text(suggestion.message || suggestion.label || "");
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
      });
      actions.append(button);
    });
    if (!suggestions.length) actions.remove();
    feed.append(fragment);
    scrollLatest();

    const execution = plan?.execution;
    if (plan?.run_id) openMobileActivityStream(plan.run_id);
    if (planCard && execution?.state === "queued" && execution.status_url) {
      window.setTimeout(() => watchMobileExecution(execution.status_url, planCard), 250);
    }
  };

  const executionPanel = (execution) => {
    const panel = document.createElement("section");
    panel.className = `vh-mobile-execution is-${text(execution?.state || "prepared")}`;
    panel.dataset.mobileExecution = "";
    const marker = document.createElement("span");
    marker.className = "vh-mobile-execution-dot";
    const content = document.createElement("div");
    const label = document.createElement("strong");
    label.dataset.mobileExecutionLabel = "";
    const detail = document.createElement("small");
    detail.dataset.mobileExecutionDetail = "";
    content.append(label, detail);
    panel.append(marker, content);
    updateExecutionPanel(panel, execution || { state: "prepared" });
    return panel;
  };

  const updateExecutionPanel = (panel, execution) => {
    const state = text(execution?.state || "unknown");
    panel.className = `vh-mobile-execution is-${state}`;
    const label = panel.querySelector("[data-mobile-execution-label]");
    const detail = panel.querySelector("[data-mobile-execution-detail]");
    const copy = {
      prepared: ["Plan prepared", "Tool execution is still governed by deployment policy."],
      gated: ["Static worker gated", text(execution.reason || "The worker is not activated here.")],
      queued: ["Queued for static inspection", "Waiting for the networkless mobile worker."],
      running: ["Static inspection running", "Fixed read-only tools are collecting bounded evidence."],
      completed: ["Static evidence collected", text(execution.reason || "Read-only inspection completed.")],
      blocked: ["Static inspection blocked", text(execution.reason || "Worker policy blocked execution.")],
      failed: ["Static inspection failed closed", text(execution.reason || "No unverified result was accepted.")],
      rejected: ["Static job rejected", text(execution.reason || "The signed job did not pass validation.")],
      unknown: ["Worker state unavailable", "The canonical evidence store remains unchanged."],
    };
    const selected = copy[state] || copy.unknown;
    label.textContent = selected[0];
    detail.textContent = selected[1];
  };

  const renderPlan = (plan) => {
    const card = document.createElement("section");
    card.className = "vh-mobile-hunt-card";
    card.dataset.mobileHuntCard = "";
    const header = document.createElement("header");
    const heading = document.createElement("div");
    const eyebrow = document.createElement("small");
    eyebrow.textContent = "Prepared Raptor-style mobile hunt";
    const title = document.createElement("strong");
    title.textContent = `${pretty(plan.profile)} · ${Number(plan.tool_count || 0)} tools`;
    const digest = document.createElement("code");
    digest.textContent = text(plan.plan_digest || "").slice(0, 24);
    heading.append(eyebrow, title);
    header.append(heading, digest);

    const tools = document.createElement("div");
    tools.className = "vh-mobile-tool-chips";
    (Array.isArray(plan.tools) ? plan.tools : []).forEach((tool) => {
      const chip = document.createElement("span");
      chip.textContent = text(tool.name || tool.tool_id);
      chip.title = `${pretty(tool.gate)} gate${tool.requires_isolation ? " · isolation required" : ""}`;
      tools.append(chip);
    });

    const rounds = document.createElement("ol");
    rounds.className = "vh-mobile-hunt-rounds";
    (Array.isArray(plan.rounds) ? plan.rounds : []).forEach((round, index) => {
      const item = document.createElement("li");
      item.className = `is-${text(round.status || "planned")}`;
      item.dataset.altitude = text(round.altitude || "unknown");
      const marker = document.createElement("span");
      marker.textContent = round.status === "blocked" ? "!" : String(index + 1);
      const content = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = text(round.label);
      const purpose = document.createElement("small");
      purpose.textContent = text(round.blocked_reason || round.purpose);
      content.append(label, purpose);
      item.append(marker, content);
      rounds.append(item);
      window.setTimeout(() => item.classList.add("is-visible"), 90 + index * 120);
    });

    const results = document.createElement("section");
    results.className = "vh-mobile-execution-results";
    results.dataset.mobileExecutionResults = "";
    results.hidden = true;

    const execution = plan.execution || {
      state: "prepared",
      reason: plan.dynamic_deferred
        ? "Static and native coverage is prepared. Runtime work remains separately gated."
        : "The plan is prepared; tool execution remains governed by worker policy.",
    };
    card.append(header, tools, rounds, executionPanel(execution), results);
    return card;
  };

  const markStaticCoverage = (card) => {
    for (const altitude of ["artifact", "attack_surface"]) {
      const round = card.querySelector(`[data-altitude='${altitude}']`);
      if (!round || round.classList.contains("is-blocked")) continue;
      round.classList.remove("is-planned", "is-in_progress");
      round.classList.add("is-covered", "is-visible");
      const marker = round.querySelector(":scope > span");
      if (marker) marker.textContent = "✓";
    }
  };

  const renderExecutionResults = (card, execution) => {
    const container = card.querySelector("[data-mobile-execution-results]");
    if (!container) return;
    container.replaceChildren();

    const receipt = execution?.receipt;
    if (!receipt || execution.state !== "completed") {
      container.hidden = true;
      return;
    }

    const captures = Array.isArray(receipt.captures) ? receipt.captures : [];
    const observations = Array.isArray(receipt.candidate_observations)
      ? receipt.candidate_observations
      : [];
    const heading = document.createElement("header");
    const title = document.createElement("strong");
    title.textContent = "Bounded evidence receipts";
    const count = document.createElement("small");
    count.textContent = `${captures.length} tool capture${captures.length === 1 ? "" : "s"} · ${observations.length} candidate observation${observations.length === 1 ? "" : "s"}`;
    heading.append(title, count);
    container.append(heading);

    if (captures.length) {
      const captureList = document.createElement("div");
      captureList.className = "vh-mobile-capture-list";
      captures.forEach((capture) => {
        const item = document.createElement("span");
        item.className = Number(capture.return_code) === 0 ? "is-success" : "is-warning";
        item.textContent = `${pretty(capture.tool)} · exit ${Number(capture.return_code)}`;
        item.title = `Evidence ${text(capture.output_sha256).slice(0, 24)}${capture.truncated ? " · bounded output" : ""}`;
        captureList.append(item);
      });
      container.append(captureList);
    }

    if (observations.length) {
      const list = document.createElement("ul");
      list.className = "vh-mobile-observation-list";
      observations.forEach((observation) => {
        const item = document.createElement("li");
        const label = document.createElement("strong");
        label.textContent = text(observation.title || "Candidate mobile observation");
        const state = document.createElement("small");
        state.textContent = pretty(observation.status || "candidate");
        item.append(label, state);
        list.append(item);
      });
      container.append(list);
    } else {
      const empty = document.createElement("p");
      empty.textContent = "The static tools completed without producing a candidate observation.";
      container.append(empty);
    }
    container.hidden = false;
    markStaticCoverage(card);
    scrollLatest();
  };

  const applyExecutionState = (card, execution) => {
    const panel = card.querySelector("[data-mobile-execution]");
    if (panel) updateExecutionPanel(panel, execution);
    card.classList.toggle("is-executing", ["queued", "running"].includes(execution.state));
    card.classList.toggle("is-complete", execution.state === "completed");
    card.classList.toggle(
      "is-failed",
      ["blocked", "failed", "rejected"].includes(execution.state),
    );
    renderExecutionResults(card, execution);
  };

  const watchMobileExecution = async (statusUrl, card) => {
    const terminal = new Set(["completed", "blocked", "failed", "rejected"]);
    let temporaryFailures = 0;
    for (let attempt = 0; attempt < 180 && card.isConnected; attempt += 1) {
      if (document.hidden) await sleep(1000);
      try {
        const payload = await getJson(statusUrl);
        const execution = payload.mobile_execution || { state: "unknown" };
        temporaryFailures = 0;
        applyExecutionState(card, execution);
        if (terminal.has(execution.state)) return;
      } catch (error) {
        temporaryFailures += 1;
        if (temporaryFailures >= 4) {
          applyExecutionState(card, {
            state: "unknown",
            reason: `Live status paused: ${error.message}`,
          });
          return;
        }
      }
      await sleep(1000);
    }
    if (card.isConnected) {
      applyExecutionState(card, {
        state: "queued",
        reason: "The worker is still queued. You can leave this page and return later.",
      });
    }
  };

  const consumeUploadResponse = (data) => {
    const attachment = data.attachment;
    if (!attachment) throw new Error("The server did not return the validated APK attachment.");
    const plan = data.mobile_plan || data.message?.metadata?.mobile_plan;
    if (plan || data.auto_started) {
      appendMessage(
        data.user_message || {
          role: "user",
          kind: "text",
          content: "Run a full automatic security analysis of this APK.",
        },
        { attachment },
      );
      appendMessage(
        data.message || {
          role: "assistant",
          kind: "mobile_plan",
          content: "The mobile hunt was prepared and queued.",
        },
        { attachment, plan },
      );
      if (plan?.run_id) openMobileActivityStream(plan.run_id);
      activeAttachment = null;
      fileInput.value = "";
      tray.replaceChildren();
      tray.hidden = true;
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    activeAttachment = attachment;
    renderTray(activeAttachment);
    if (!input.value.trim()) input.value = "Test this APK and find security weaknesses.";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const uploadInChunks = async (file) => {
    if (!uploadStartUrl) return null;
    const startPayload = new FormData();
    startPayload.append("filename", file.name);
    startPayload.append("size_bytes", String(file.size));
    const started = await postForm(uploadStartUrl, startPayload);
    const maximum = Number(started.maximum_bytes || 0);
    if (maximum && file.size > maximum) {
      throw new Error(`The APK exceeds the ${formatBytes(maximum)} upload limit.`);
    }
    const chunkBytes = Math.max(1024 * 1024, Number(started.chunk_bytes) || 8 * 1024 * 1024);
    const chunkUrl = text(started.chunk_url);
    if (!chunkUrl) throw new Error("The server did not return an APK chunk endpoint.");

    let offset = 0;
    let result = null;
    renderUploadProgress(file, 0);
    while (offset < file.size) {
      const end = Math.min(file.size, offset + chunkBytes);
      const payload = new FormData();
      payload.append("offset", String(offset));
      payload.append("chunk", file.slice(offset, end), `${file.name}.part`);
      result = await postForm(chunkUrl, payload);
      const nextOffset = Number(result.received_bytes ?? result.upload?.received_bytes);
      if (!Number.isFinite(nextOffset) || nextOffset <= offset || nextOffset > file.size) {
        throw new Error("The server returned an invalid APK upload offset.");
      }
      offset = nextOffset;
      renderUploadProgress(file, offset);
      setBusy(true, `Uploading APK… ${Math.floor((offset / file.size) * 100)}%`);
    }
    return result;
  };

  const uploadAttachment = async (file) => {
    if (!attachmentUrl && !uploadStartUrl) {
      throw new Error("The APK attachment endpoint is unavailable.");
    }
    setBusy(true, "Uploading and validating the APK…");
    renderUploadProgress(file, 0);
    try {
      let data = await uploadInChunks(file);
      if (!data) {
        const payload = new FormData();
        payload.append("attachment", file);
        payload.append("auto_start", "true");
        data = await postForm(attachmentUrl, payload);
      }
      consumeUploadResponse(data);
    } catch (error) {
      activeAttachment = null;
      fileInput.value = "";
      tray.replaceChildren();
      tray.hidden = true;
      appendMessage(
        { role: "assistant", kind: "error", content: error.message },
        { error: true },
      );
    } finally {
      setBusy(false);
      input.focus();
    }
  };

  attachButton.addEventListener("click", () => {
    if (!mobileBusy) fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    if (form.dataset.mobileUploadMode === "background") return;
    const file = fileInput.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      appendMessage(
        { role: "assistant", kind: "error", content: "Choose a file with the .apk extension." },
        { error: true },
      );
      fileInput.value = "";
      return;
    }
    uploadAttachment(file);
  });

  form.addEventListener(
    "submit",
    async (event) => {
      if (!activeAttachment) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      if (mobileBusy) return;
      const value = input.value.trim();
      if (!value) return;
      const attachment = activeAttachment;
      appendMessage(
        { role: "user", kind: "text", content: value },
        { attachment },
      );
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      setBusy(true, "Selecting governed tools and building multi-altitude hunt coverage…");
      try {
        const payload = new FormData();
        payload.append("message", value);
        payload.append("attachment_id", text(attachment.attachment_id));
        const data = await postForm(mobileMessageUrl, payload);
        const message = data.message || {
          role: "assistant",
          kind: "mobile_plan",
          content: "The mobile hunt plan is ready.",
        };
        const plan = data.mobile_plan || message.metadata?.mobile_plan;
        appendMessage(message, { attachment, plan });
        if (plan?.run_id) openMobileActivityStream(plan.run_id);
        activeAttachment = null;
        fileInput.value = "";
        tray.replaceChildren();
        tray.hidden = true;
      } catch (error) {
        appendMessage(
          { role: "assistant", kind: "error", content: error.message },
          { error: true },
        );
      } finally {
        setBusy(false);
        input.focus();
      }
    },
    true,
  );

  reset?.addEventListener("click", () => {
    activeAttachment = null;
    fileInput.value = "";
    tray.replaceChildren();
    tray.hidden = true;
  });
})();
