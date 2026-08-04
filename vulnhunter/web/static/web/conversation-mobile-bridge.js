(() => {
  "use strict";

  const originalFetch = window.fetch.bind(window);
  const retryUrl = "/workspace/mobile-retry/";
  const retryStoragePrefix = "vh-mobile-retry:";

  const setMobileNavigation = (visible) => {
    const navigation = document.querySelector("[data-mobile-workspace-nav]");
    if (navigation) navigation.hidden = !visible;
  };

  const emitSupportingState = (name, detail) => {
    if (["vh:mobile-attachment", "vh:mobile-plan", "vh:mobile-status"].includes(name)) {
      setMobileNavigation(true);
    }
    document.dispatchEvent(new CustomEvent(name, { detail }));
  };

  const withAssessmentStore = (callback) => {
    const store = window.vhSelectedAssessmentStore;
    if (store) {
      callback(store);
      return;
    }
    document.addEventListener(
      "vh:selected-assessment-store-ready",
      (event) => callback(event.detail),
      { once: true },
    );
  };

  const replaceSelectedAssessment = (payload) => {
    withAssessmentStore((store) => store.replace(payload || {}));
  };

  const clearSelectedAssessment = () => {
    setMobileNavigation(false);
    withAssessmentStore((store) => store.clear());
  };

  const classify = (url, method) => {
    const value = String(url || "");
    if (value.includes("/workspace/attachments/") && method === "POST") return "attachment";
    if (value.includes("/workspace/mobile-message/") && method === "POST") return "plan";
    if (value.includes("/workspace/mobile-followup/") && method === "POST") return "followup";
    if (value.includes("/workspace/mobile-context/") && method === "GET") return "context";
    if (value.includes("/workspace/mobile-status/") && method === "GET") return "status";
    if (value.includes("/workspace/mobile-retry/") && method === "GET") return "retry-read";
    if (value.includes("/workspace/mobile-retry/") && method === "POST") return "retry-write";
    if (value.includes("/workspace/mobile-context/reset/") && method === "POST") return "reset";
    return "";
  };

  const csrfToken = () => {
    const cookie = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    if (cookie) return decodeURIComponent(cookie[1]);
    return document.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  };

  const retryStorageKey = (assessmentId, scope) =>
    `${retryStoragePrefix}${String(assessmentId || "selected")}:${String(scope || "unknown")}`;

  const retryIdempotencyKey = (assessmentId, scope) => {
    const key = retryStorageKey(assessmentId, scope);
    const stored = window.sessionStorage.getItem(key);
    if (stored) return stored;
    const created = window.crypto?.randomUUID
      ? window.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    window.sessionStorage.setItem(key, created);
    return created;
  };

  const clearRetryIdempotencyKey = (assessmentId, scope) => {
    window.sessionStorage.removeItem(retryStorageKey(assessmentId, scope));
  };

  const retryCard = () => {
    const cards = document.querySelectorAll("[data-mobile-hunt-card]");
    return cards.length ? cards[cards.length - 1] : null;
  };

  const removeMobileProjectionControls = () => {
    document
      .querySelectorAll("[data-mobile-task-projection], [data-mobile-retry-control]")
      .forEach((item) => item.remove());
  };

  const readableStage = (value) =>
    String(value || "assessment")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const renderStageTimeline = (projection) => {
    const stages = Array.isArray(projection?.stages) ? projection.stages : [];
    if (!stages.length) return null;

    const details = document.createElement("details");
    details.dataset.mobileActivityTimeline = "";
    const summary = document.createElement("summary");
    summary.textContent = "Recorded stage timeline";
    const list = document.createElement("ol");
    list.setAttribute("aria-label", "Persisted assessment stages");

    stages.forEach((item) => {
      const stage = String(item?.stage || "").trim();
      const status = String(item?.status || "").trim();
      if (!stage || !status) return;
      const row = document.createElement("li");
      row.dataset.stageStatus = status;
      const name = document.createElement("strong");
      name.textContent = readableStage(stage);
      const state = document.createElement("span");
      state.textContent = readableStage(status);
      row.append(name, state);
      list.append(row);
    });

    if (!list.children.length) return null;
    details.append(summary, list);
    return details;
  };

  const renderTaskProjection = (snapshot) => {
    document.querySelectorAll("[data-mobile-task-projection]").forEach((item) => item.remove());
    const projection = snapshot?.assessment_projection;
    const taskCard = snapshot?.task_card;
    const card = retryCard();
    if (!card || !taskCard || taskCard.assessment_id !== projection?.assessment_id) return;

    const panel = document.createElement("section");
    panel.className = "vh-inline-approval";
    panel.dataset.mobileTaskProjection = "";
    panel.setAttribute("aria-label", "Assessment activity");

    const title = document.createElement("strong");
    title.textContent = "Assessment activity";
    const currentStage = taskCard.current_stage || {};
    const stage = document.createElement("p");
    stage.textContent = `${readableStage(currentStage.stage)} · ${readableStage(currentStage.status)}`;

    const progress = document.createElement("p");
    const completed = Number(taskCard.stage_progress?.completed);
    const total = Number(taskCard.stage_progress?.total);
    progress.textContent =
      Number.isInteger(completed) && Number.isInteger(total) && total >= completed
        ? `${completed} of ${total} recorded stages complete`
        : "Stage progress is not available yet.";

    const activity = taskCard.activity || {};
    const activityCopy = document.createElement("p");
    activityCopy.textContent = `${Number(activity.event_count) || 0} events · ${Number(activity.receipt_count) || 0} evidence receipts · ${Number(activity.candidate_count) || 0} candidates`;

    panel.append(title, stage, progress, activityCopy);

    const byteProgress = taskCard.byte_progress || {};
    const received = Number(byteProgress.received);
    const expected = Number(byteProgress.expected);
    if (Number.isFinite(received) && Number.isFinite(expected) && received >= 0 && expected > 0 && received <= expected) {
      const bytes = document.createElement("p");
      bytes.textContent = `${received.toLocaleString()} of ${expected.toLocaleString()} bytes received`;
      panel.append(bytes);
    }

    const latest = activity.latest_event;
    if (latest?.stage && latest?.status) {
      const latestCopy = document.createElement("small");
      latestCopy.textContent = `Latest: ${readableStage(latest.stage)} · ${readableStage(latest.status)}`;
      panel.append(latestCopy);
    }

    const timeline = renderStageTimeline(projection);
    if (timeline) panel.append(timeline);
    card.append(panel);
  };

  const renderRetryProjection = (snapshot) => {
    document.querySelectorAll("[data-mobile-retry-control]").forEach((item) => item.remove());
    const projection = snapshot?.assessment_projection;
    const taskCard = snapshot?.task_card;
    const retry = taskCard?.retry;
    const actions = Array.isArray(projection?.allowed_actions) ? projection.allowed_actions : [];
    const card = retryCard();
    if (!card || retry?.available !== true || !actions.includes("request_retry")) return;

    const assessmentId = String(taskCard.assessment_id || projection.assessment_id || "");
    const scope = String(retry.scope || "");
    if (!assessmentId || !scope) return;

    const panel = document.createElement("section");
    panel.className = "vh-inline-approval";
    panel.dataset.mobileRetryControl = "";
    panel.setAttribute("aria-live", "polite");
    const title = document.createElement("strong");
    title.textContent = "Retry this failed stage";
    const detail = document.createElement("p");
    detail.textContent = String(retry.user_action || "Retry the preserved assessment stage.");
    const status = document.createElement("small");
    status.dataset.mobileRetryStatus = "";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "vh-button-primary";
    button.dataset.mobileRetry = "";
    button.textContent = "Retry safely";

    button.addEventListener("click", async () => {
      if (button.disabled) return;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      status.textContent = "Retrying the preserved stage…";
      const idempotencyKey = retryIdempotencyKey(assessmentId, scope);
      const body = new FormData();
      body.append("retry_scope", scope);
      body.append("idempotency_key", idempotencyKey);
      try {
        const response = await originalFetch(retryUrl, {
          method: "POST",
          body,
          credentials: "same-origin",
          headers: { "X-CSRFToken": csrfToken(), Accept: "application/json" },
        });
        let data = {};
        try {
          data = await response.json();
        } catch (_error) {
          data = { detail: "The retry response could not be read." };
        }
        if (!response.ok) throw new Error(data.detail || "The retry could not be completed.");
        clearRetryIdempotencyKey(assessmentId, scope);
        status.textContent = "Retry accepted. Current assessment state has been refreshed.";
        emitSupportingState("vh:mobile-plan", data.mobile_plan || null);
        emitSupportingState("vh:mobile-status", data.mobile_execution || null);
        replaceSelectedAssessment(data);
      } catch (error) {
        status.textContent = error instanceof Error ? error.message : "The retry could not be completed.";
        button.disabled = false;
      } finally {
        button.removeAttribute("aria-busy");
      }
    });

    panel.append(title, detail, status, button);
    card.append(panel);
  };

  const renderSelectedAssessment = (snapshot) => {
    if (!snapshot) {
      removeMobileProjectionControls();
      return;
    }
    renderTaskProjection(snapshot);
    renderRetryProjection(snapshot);
  };

  const subscribeToSelectedAssessment = (store) => {
    renderSelectedAssessment(store.getSnapshot());
    store.subscribe(renderSelectedAssessment);
  };

  const refreshSelectedAssessment = async () => {
    if (!retryCard()) {
      clearSelectedAssessment();
      return;
    }
    try {
      const response = await originalFetch(retryUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (response.status === 404) {
        clearSelectedAssessment();
        return;
      }
      const payload = await response.json();
      if (response.ok) replaceSelectedAssessment(payload);
    } catch (_error) {
      return;
    }
  };

  window.fetch = async (input, init = {}) => {
    const request = input instanceof Request ? input : null;
    const url = request?.url || input;
    const method = String(init.method || request?.method || "GET").toUpperCase();
    const kind = classify(url, method);
    const response = await originalFetch(input, init);
    if (!kind) return response;

    response.clone().json().then((payload) => {
      if (!response.ok) {
        document.dispatchEvent(new CustomEvent("vh:mobile-error", { detail: { kind, payload, status: response.status } }));
        return;
      }
      if (kind === "attachment" && payload?.attachment) {
        emitSupportingState("vh:mobile-attachment", payload.attachment);
      } else if (kind === "plan") {
        emitSupportingState("vh:mobile-plan", payload?.mobile_plan || payload?.message?.metadata?.mobile_plan || null);
      } else if (kind === "context" && payload?.mobile_plan) {
        emitSupportingState("vh:mobile-plan", payload.mobile_plan);
      } else if (kind === "status" && payload?.mobile_execution) {
        emitSupportingState("vh:mobile-status", payload.mobile_execution);
      } else if (["retry-read", "retry-write"].includes(kind)) {
        replaceSelectedAssessment(payload);
      } else if (kind === "reset" || (kind === "followup" && payload?.handoff)) {
        clearSelectedAssessment();
      }
    }).catch(() => undefined);
    return response;
  };

  document.addEventListener("vh:mobile-plan", () => window.setTimeout(refreshSelectedAssessment, 0));
  document.addEventListener("vh:mobile-status", () => window.setTimeout(refreshSelectedAssessment, 0));

  withAssessmentStore(subscribeToSelectedAssessment);

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("[data-conversation-reset]")?.addEventListener("click", clearSelectedAssessment);
    document.querySelector("[data-attachment-tray]")?.addEventListener("click", (event) => {
      if (event.target.closest(".vh-apk-attachment-remove")) clearSelectedAssessment();
    });
    window.setTimeout(refreshSelectedAssessment, 0);
  });
})();
