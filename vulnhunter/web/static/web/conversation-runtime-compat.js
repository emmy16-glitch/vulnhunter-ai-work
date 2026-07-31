(() => {
  "use strict";

  if (typeof String.prototype.join !== "function") {
    Object.defineProperty(String.prototype, "join", {
      configurable: true,
      writable: true,
      value(items) {
        return Array.isArray(items) ? items.join(String(this)) : String(items ?? "");
      },
    });
  }

  if (typeof document === "undefined" || typeof window === "undefined") return;
  const current = document.currentScript?.src;
  if (!current) return;

  const sourceHuntMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    if (/\bsource hunt\b/.test(text)) return true;
    const namesSource = /\b(source code|repository|repo)\b/.test(text);
    const requestsAction = /\b(scan|assess|analyse|analyze|review|hunt|status|progress|result|results|finding|findings|evidence|next step|what next)\b/.test(text);
    return namesSource && requestsAction;
  };

  const activeValidationMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    return /\b(active validation|adversary lab|synthetic lab|validation lab)\b/.test(text);
  };

  const remediationMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    const namesRemediation = /\b(remediation|remediate|fix plan|fix finding)\b/.test(text);
    const asksTrackedPlan = /\b(remediation plan|remediation status|remediation progress|remediation result|remediation next step)\b/.test(text);
    return namesRemediation || asksTrackedPlan;
  };

  const csrfToken = (form) => {
    const field = form.querySelector("input[name='csrfmiddlewaretoken']");
    if (field?.value) return field.value;
    const cookie = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return cookie ? decodeURIComponent(cookie[1]) : "";
  };

  document.addEventListener(
    "submit",
    async (event) => {
      const form = event.target instanceof HTMLFormElement ? event.target : null;
      if (!form?.matches("[data-conversation-form]")) return;
      const input = form.querySelector("[data-conversation-input]");
      const message = input?.value || "";
      const activeValidation = activeValidationMessage(message);
      const remediation = remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !remediation && !sourceHunt) return;

      event.preventDefault();
      event.stopImmediatePropagation();
      if (form.dataset.specialistBusy === "true") return;
      form.dataset.specialistBusy = "true";
      const send = form.querySelector("[data-conversation-send]");
      if (send) send.disabled = true;
      if (input) input.disabled = true;

      const workspace = document.querySelector("[data-conversation-workspace]");
      const threadId = workspace?.dataset.threadId || form.dataset.threadId || "";
      const payload = new FormData();
      payload.set("message", message);
      if (sourceHunt && !activeValidation && !remediation) payload.set("source_chat_bridge", "yes");
      if (threadId) payload.set("thread_id", threadId);
      const csrf = csrfToken(form);
      if (csrf) payload.set("csrfmiddlewaretoken", csrf);
      const endpoint = activeValidation
        ? "/workspace/active-validation/"
        : remediation
          ? "/workspace/remediation/"
          : "/source-hunt/";
      const label = activeValidation ? "Active Validation" : remediation ? "Remediation" : "Source Hunt";

      try {
        const headers = { Accept: "application/json" };
        if (threadId) headers["X-VulnHunter-Thread"] = threadId;
        const response = await fetch(endpoint, {
          method: "POST",
          body: payload,
          credentials: "same-origin",
          headers,
        });
        const body = await response.json();
        if (!response.ok) throw new Error(body.detail || `${label} request failed.`);
        if (body.redirect_url) {
          window.location.assign(body.redirect_url);
          return;
        }
        window.location.reload();
      } catch (error) {
        form.dataset.specialistBusy = "false";
        if (send) send.disabled = false;
        if (input) {
          input.disabled = false;
          input.focus();
        }
        window.alert(error instanceof Error ? error.message : `${label} request failed.`);
      }
    },
    true,
  );

  const loadScript = (filename, marker) => {
    if (document.querySelector(`script[${marker}]`)) return;
    const url = new URL(current, window.location.href);
    url.pathname = url.pathname.replace(/conversation-runtime-compat\.js$/, filename);
    url.search = "?v=20260731-remediation1";
    const script = document.createElement("script");
    script.src = url.toString();
    script.async = false;
    script.setAttribute(marker, "true");
    document.head.append(script);
  };

  const bindSourceHuntLinks = () => {
    const workspace = document.querySelector("[data-conversation-workspace]");
    const threadId = workspace?.dataset.threadId || "";
    if (!threadId) return;
    document.querySelectorAll("a[href]").forEach((anchor) => {
      const url = new URL(anchor.href, window.location.href);
      if (!url.pathname.endsWith("/source-hunt/")) return;
      url.searchParams.set("thread", threadId);
      anchor.href = url.toString();
    });
    const subtitle = workspace?.querySelector(".vh-chat-subtitle");
    if (subtitle) {
      subtitle.textContent =
        "Conversational analysis for authorised websites, APKs, source repositories, controlled validation and governed remediation";
    }
  };

  const loadWorkspaceBridges = () => {
    bindSourceHuntLinks();
    loadScript("workspace-state.js", "data-workspace-state-loader");
    loadScript("workspace-safety-polish.js", "data-workspace-safety-loader");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadWorkspaceBridges, { once: true });
  } else {
    loadWorkspaceBridges();
  }
})();
