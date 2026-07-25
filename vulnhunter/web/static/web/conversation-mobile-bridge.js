(() => {
  "use strict";

  const originalFetch = window.fetch.bind(window);
  const emit = (name, detail) => {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  };

  const classify = (url, method) => {
    const value = String(url || "");
    if (value.includes("/workspace/attachments/") && method === "POST") return "attachment";
    if (value.includes("/workspace/mobile-message/") && method === "POST") return "plan";
    if (value.includes("/workspace/mobile-followup/") && method === "POST") return "followup";
    if (value.includes("/workspace/mobile-context/") && method === "GET") return "context";
    if (value.includes("/workspace/mobile-status/") && method === "GET") return "status";
    if (value.includes("/workspace/mobile-context/reset/") && method === "POST") return "reset";
    return "";
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
        } else if (kind === "reset") {
          emit("vh:mobile-reset", {});
        } else if (kind === "followup" && payload?.handoff) {
          emit("vh:mobile-reset", {});
        }
      })
      .catch(() => undefined);
    return response;
  };

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("[data-conversation-reset]")?.addEventListener("click", () => {
      emit("vh:mobile-reset", {});
    });
    document.querySelector("[data-attachment-tray]")?.addEventListener("click", (event) => {
      if (event.target.closest(".vh-apk-attachment-remove")) emit("vh:mobile-reset", {});
    });
  });
})();
