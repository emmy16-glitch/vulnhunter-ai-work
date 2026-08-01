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

  const retestMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    return /\b(retest|re-test|verify after fix|test the fix again)\b/.test(text);
  };

  const finalReportMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    return /\b(generate final report|create final report|open final report|final remediation report|export final report|build final report)\b/.test(text);
  };

  const remediationReviewMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
    return /\b(independent remediation review|review remediation|review the remediation|review the fix|approve remediation review)\b/.test(text);
  };

  const remediationMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
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
    url.search = "?v=20260801-chat-controls1";
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
        "Conversational analysis for authorised websites, APKs, source repositories, controlled validation, remediation, retesting, independent review and final reporting";
    }
  };

  const providerName = (runtime) => {
    const detail = String(runtime?.getAttribute("title") || "");
    const hasGroq = /\bGroq\b/i.test(detail);
    const hasHuggingFace = /Hugging\s*Face/i.test(detail);
    if (hasHuggingFace && !hasGroq) return "Hugging Face";
    if (hasGroq && !hasHuggingFace) return "Groq";
    return "the AI provider";
  };

  const bindProviderRuntime = () => {
    const runtime = document.querySelector("[data-provider-runtime]");
    const detail = String(runtime?.getAttribute("title") || "");
    if (runtime) {
      const hasGroq = /\bGroq\b/i.test(detail);
      const hasHuggingFace = /Hugging\s*Face/i.test(detail);
      if (hasGroq && hasHuggingFace) runtime.textContent = "AI providers configured";
      else if (hasHuggingFace) runtime.textContent = "Hugging Face configured";
      else if (/Groq live conversation ready/i.test(detail)) runtime.textContent = "Groq live";
      else if (hasGroq) runtime.textContent = "Groq configured";
      else runtime.textContent = "AI unavailable";
    }

    const thinkingCopy = document.querySelector("[data-thinking-copy]");
    if (thinkingCopy) {
      const rewriteThinkingCopy = () => {
        const value = thinkingCopy.textContent || "";
        if (!value.startsWith("Asking Groq")) return;
        const name = providerName(runtime);
        thinkingCopy.textContent = value.replace("Asking Groq", `Asking ${name}`);
      };
      rewriteThinkingCopy();
      new MutationObserver(rewriteThinkingCopy).observe(thinkingCopy, {
        childList: true,
        characterData: true,
        subtree: true,
      });
    }

    const feed = document.querySelector("[data-conversation-feed]");
    if (feed) {
      const rewriteProviderBadges = () => {
        feed.querySelectorAll(".vh-message-reasoning").forEach((badge) => {
          const copy = badge.textContent || "";
          if (/\bHuggingface\b/i.test(copy)) {
            badge.textContent = copy.replace(/\bHuggingface\b/gi, "Hugging Face");
          }
          if (badge.dataset.providerFallbackRewritten === "true") return;
          const detailText = String(badge.getAttribute("title") || "");
          if (!/Groq|Hugging\s*Face/i.test(detailText)) return;
          if (!/Deterministic/i.test(badge.textContent || "")) return;
          badge.dataset.providerFallbackRewritten = "true";
          badge.classList.add("is-degraded");
          badge.textContent = (badge.textContent || "").replace(
            /Deterministic(?: fallback)?/i,
            "AI provider unavailable · deterministic fallback",
          );
        });
      };
      rewriteProviderBadges();
      new MutationObserver(rewriteProviderBadges).observe(feed, {
        childList: true,
        subtree: true,
      });
    }
  };

  const loadWorkspaceBridges = () => {
    bindSourceHuntLinks();
    bindProviderRuntime();
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