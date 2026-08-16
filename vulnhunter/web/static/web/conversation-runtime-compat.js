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

  const siblingUrl = (filename, version = "20260816-termux-hardening1") => {
    const url = new URL(current, window.location.href);
    url.pathname = url.pathname.replace(/conversation-runtime-compat\.js$/, filename);
    url.search = `?v=${version}`;
    return url.toString();
  };

  const preloadCommandCenterStyles = () => {
    if (document.querySelector("link[data-command-center-styles]")) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = siblingUrl("conversation-command-center.css");
    link.dataset.commandCenterStyles = "true";
    document.head.append(link);
  };

  // This script is parser-blocking in the document head. Start loading the chat privacy
  // stylesheet before the conversation body is parsed so infrastructure-only runtime copy
  // is never presented as a user-facing product status.
  preloadCommandCenterStyles();

  const normalized = (value) => String(value || "").toLowerCase().replace(/\s+/g, " ").trim();

  const sourceHuntMessage = (value) => {
    const text = normalized(value);
    if (/\bsource hunt\b/.test(text)) return true;
    const namesSource = /\b(source code|repository|repo)\b/.test(text);
    const requestsAction = /\b(scan|assess|analyse|analyze|review|hunt|status|progress|result|results|finding|findings|evidence|next step|what next)\b/.test(text);
    return namesSource && requestsAction;
  };

  const activeValidationMessage = (value) =>
    /\b(active validation|adversary lab|synthetic lab|validation lab)\b/.test(normalized(value));

  const retestMessage = (value) =>
    /\b(retest|re-test|verify after fix|test the fix again)\b/.test(normalized(value));

  const finalReportMessage = (value) =>
    /\b(generate final report|create final report|open final report|final remediation report|export final report|build final report)\b/.test(normalized(value));

  const remediationReviewMessage = (value) =>
    /\b(independent remediation review|review remediation|review the remediation|review the fix|approve remediation review)\b/.test(normalized(value));

  const remediationMessage = (value) => {
    const text = normalized(value);
    const namesRemediation = /\b(remediation|remediate|fix plan|fix finding)\b/.test(text);
    const asksTrackedPlan = /\b(remediation plan|remediation status|remediation progress|remediation result|remediation next step)\b/.test(text);
    const submitsImplementation = /\b(record implementation|submit implementation|implementation handoff|verify remediation fix|submit fixed revision|record fixed revision)\b/.test(text);
    return namesRemediation || asksTrackedPlan || submitsImplementation;
  };

  const csrfToken = (form) => {
    const field = form.querySelector("input[name='csrfmiddlewaretoken']");
    if (field?.value) return field.value;
    const cookie = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return cookie ? decodeURIComponent(cookie[1]) : "";
  };

  const dispatch = (name, detail) => {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  };

  const setSpecialistThinking = (busy, label = "") => {
    const workspace = document.querySelector("[data-conversation-workspace]");
    const thinking = workspace?.querySelector("[data-conversation-thinking]");
    const copy = workspace?.querySelector("[data-thinking-copy]");
    if (thinking) thinking.hidden = !busy;
    if (copy && busy) copy.textContent = `${label || "Governed workflow"} · working…`;
  };

  document.addEventListener(
    "submit",
    async (event) => {
      const form = event.target instanceof HTMLFormElement ? event.target : null;
      if (!form?.matches("[data-conversation-form]")) return;
      const input = form.querySelector("[data-conversation-input]");
      const message = input?.value || "";
      const activeValidation = activeValidationMessage(message);
      const retest = retestMessage(message);
      const finalReport = finalReportMessage(message);
      const remediationReview = !finalReport && remediationReviewMessage(message);
      const remediation = !retest && !finalReport && !remediationReview && remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !retest && !finalReport && !remediationReview && !remediation && !sourceHunt) return;

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
      if (sourceHunt && !activeValidation && !retest && !finalReport && !remediationReview && !remediation) {
        payload.set("source_chat_bridge", "yes");
      }
      if (threadId) payload.set("thread_id", threadId);
      const csrf = csrfToken(form);
      if (csrf) payload.set("csrfmiddlewaretoken", csrf);

      const endpoint = activeValidation
        ? "/workspace/active-validation/"
        : retest
          ? "/workspace/retest/"
          : finalReport
            ? "/workspace/remediation-final-report/"
            : remediationReview
              ? "/workspace/remediation-review/"
              : remediation
                ? "/workspace/remediation/"
                : "/source-hunt/";
      const label = activeValidation
        ? "Active Validation"
        : retest
          ? "Governed Retest"
          : finalReport
            ? "Final Remediation Report"
            : remediationReview
              ? "Independent Remediation Review"
              : remediation
                ? "Remediation"
                : "Source Hunt";

      setSpecialistThinking(true, label);
      dispatch("vulnhunter:specialist-start", { label, message, endpoint });

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

        if (input) input.value = "";
        dispatch("vulnhunter:specialist-response", { label, message, endpoint, body });
      } catch (error) {
        dispatch("vulnhunter:specialist-error", {
          label,
          message: error instanceof Error ? error.message : `${label} request failed.`,
          endpoint,
        });
      } finally {
        setSpecialistThinking(false);
        form.dataset.specialistBusy = "false";
        if (send) send.disabled = false;
        if (input) {
          input.disabled = false;
          input.focus();
          input.dispatchEvent(new Event("input", { bubbles: true }));
        }
      }
    },
    true,
  );

  const loadScript = (filename, marker) => {
    if (document.querySelector(`script[${marker}]`)) return;
    const script = document.createElement("script");
    script.src = siblingUrl(filename);
    script.async = false;
    script.setAttribute(marker, "true");
    document.head.append(script);
  };

  const bindSourceHuntLinks = () => {
    const workspace = document.querySelector("[data-conversation-workspace]");
    const threadId = workspace?.dataset.threadId || "";
    if (threadId) {
      document.querySelectorAll("a[href]").forEach((anchor) => {
        let url;
        try { url = new URL(anchor.href, window.location.href); } catch (_error) { return; }
        if (!url.pathname.endsWith("/source-hunt/")) return;
        url.searchParams.set("thread", threadId);
        anchor.href = url.toString();
      });
    }
    const subtitle = workspace?.querySelector(".vh-chat-subtitle");
    if (subtitle) {
      subtitle.textContent =
        "Conversational command center for authorised websites, APKs, source repositories, controlled validation, remediation, retesting, review and final reporting";
    }
  };

  const bindProviderRuntime = () => {
    const runtime = document.querySelector("[data-provider-runtime]");
    if (!runtime) return;
    runtime.hidden = true;
    runtime.setAttribute("aria-hidden", "true");
    runtime.textContent = "Automatic routing";
    runtime.removeAttribute("title");
    runtime.classList.remove("is-ready", "is-warning", "is-offline");
  };

  const loadWorkspaceBridges = () => {
    bindSourceHuntLinks();
    bindProviderRuntime();
    loadScript("conversation-command-center.js", "data-command-center-loader");
    loadScript("conversation-provider-control.js", "data-provider-control-loader");
    loadScript("conversation-response-controls.js", "data-response-controls-loader");
    loadScript("workspace-state.js", "data-workspace-state-loader");
    loadScript("workspace-safety-polish.js", "data-workspace-safety-loader");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadWorkspaceBridges, { once: true });
  } else {
    loadWorkspaceBridges();
  }
})();
