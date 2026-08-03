(() => {
  "use strict";

  const originalFetch = window.fetch.bind(window);
  const retryUrl = "/workspace/mobile-retry/";
  const retryStoragePrefix = "vh-mobile-retry:";

  const setMobileNavigation = (visible) => {
    const navigation = document.querySelector("[data-mobile-workspace-nav]");
    if (navigation) navigation.hidden = !visible;
  };
  const emit = (name, detail) => {
    if (["vh:mobile-attachment", "vh:mobile-plan", "vh:mobile-status"].includes(name)) {
      setMobileNavigation(true);
    } else if (name === "vh:mobile-reset") {
      setMobileNavigation(false);
    }
    document.dispatchEvent(new CustomEvent(name, { detail }));
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

  const renderRetryProjection = (payload) => {
    document.querySelectorAll("[data-mobile-retry-control]").forEach((item) => item.remove());
    const projection = payload?.assessment_projection;
    const taskCard = payload?.task_card || projection?.task_card;
    const retry = taskCard?.retry;
    const actions = Array.isArray(projection?.allowed_actions)
      ? projection.allowed_actions
      : [];
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
        status.textContent = "Retry accepted. Authoritative state has been refreshed.";
        emit("vh:mobile-plan", data.mobile_plan || null);
        emit("vh:mobile-status", data.mobile_execution || null);
        emit("vh:mobile-projection", data);
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

  const refreshRetryProjection = async () => {
    if (!retryCard()) {
      renderRetryProjection(null);
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
        renderRetryProjection(null);
        return;
      }
      const payload = await response.json();
      if (!response.ok) return;
      emit("vh:mobile-projection", payload);
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

    response
      .clone()
      .json()
      .then((payload) => {
        if (!response.ok) {
          emit("vh:mobile-error", { kind, payload, status: response.status });
          return;
        }
        if (kind === "attachment" && payload?.attachment) {
          emit("vh:mobile-attachment", payload.attachment);
        } else if (kind === "plan") {
          emit("vh:mobile-plan", payload?.mobile_plan || payload?.message?.metadata?.mobile_plan || null);
        } else if (kind === "context" && payload?.mobile_plan) {
          emit("vh:mobile-plan", payload.mobile_plan);
        } else if (kind === "status" && payload?.mobile_execution) {
          emit("vh:mobile-status", payload.mobile_execution);
        } else if (["retry-read", "retry-write"].includes(kind)) {
          emit("vh:mobile-projection", payload);
        } else if (kind === "reset") {
          emit("vh:mobile-reset", {});
        } else if (kind === "followup" && payload?.handoff) {
          emit("vh:mobile-reset", {});
        }
      })
      .catch(() => undefined);
    return response;
  };

  document.addEventListener("vh:mobile-projection", (event) => {
    renderRetryProjection(event.detail);
  });
  document.addEventListener("vh:mobile-plan", () => {
    window.setTimeout(refreshRetryProjection, 0);
  });
  document.addEventListener("vh:mobile-status", () => {
    window.setTimeout(refreshRetryProjection, 0);
  });
  document.addEventListener("vh:mobile-reset", () => {
    renderRetryProjection(null);
  });

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("[data-conversation-reset]")?.addEventListener("click", () => {
      emit("vh:mobile-reset", {});
    });
    document.querySelector("[data-attachment-tray]")?.addEventListener("click", (event) => {
      if (event.target.closest(".vh-apk-attachment-remove")) emit("vh:mobile-reset", {});
    });
    window.setTimeout(refreshRetryProjection, 0);
  });
})();
