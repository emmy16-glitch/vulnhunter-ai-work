(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-response-controls-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-response-controls\.js$/,
      "conversation-response-controls.css",
    );
    styleUrl.search = "?v=20260816-termux-hardening1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.responseControlsStyles = "true";
    document.head.append(link);
  }
  if (current && !document.querySelector("script[data-rich-content-loader]")) {
    const richUrl = new URL(current, window.location.href);
    richUrl.pathname = richUrl.pathname.replace(
      /conversation-response-controls\.js$/,
      "conversation-rich-content.js",
    );
    richUrl.search = "?v=20260801-rich-content1";
    const script = document.createElement("script");
    script.src = richUrl.toString();
    script.async = false;
    script.dataset.richContentLoader = "true";
    document.head.append(script);
  }
  if (current && !document.querySelector("script[data-conversation-draft-loader]")) {
    const draftUrl = new URL(current, window.location.href);
    draftUrl.pathname = draftUrl.pathname.replace(
      /conversation-response-controls\.js$/,
      "conversation-draft.js",
    );
    draftUrl.search = "?v=20260816-termux-hardening1";
    const script = document.createElement("script");
    script.src = draftUrl.toString();
    script.async = false;
    script.dataset.conversationDraftLoader = "true";
    document.head.append(script);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const input = document.querySelector("[data-conversation-input]");
  const feed = document.querySelector("[data-conversation-feed]");
  const messageTemplate = document.getElementById("vh-message-template");
  if (!workspace || !dataElement || !form || !input || !feed || !messageTemplate) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const messageUrl = new URL(initial.message_url, window.location.href);
  const state = {
    controller: null,
    stopButton: null,
  };

  const setInputValue = (value, { submit = false } = {}) => {
    input.value = String(value || "");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
    if (submit && input.value.trim()) form.requestSubmit();
  };

  const appendLocalNotice = (copy) => {
    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const body = fragment.querySelector(".vh-message-body");
    const messageCopy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    article.classList.add("is-assistant", "is-status", "is-local-notice");
    avatar.textContent = "VH";
    messageCopy.textContent = copy;
    actions?.remove();
    const time = document.createElement("time");
    time.className = "vh-message-time";
    time.dateTime = new Date().toISOString();
    time.textContent = new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date());
    body.append(time);
    feed.append(fragment);
    feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" });
  };

  const updateStopButton = () => {
    if (!state.stopButton) return;
    state.stopButton.hidden = !state.controller;
    state.stopButton.disabled = !state.controller;
  };

  const stopCurrentResponse = () => {
    if (!state.controller) return false;
    const controller = state.controller;
    state.controller = null;
    updateStopButton();
    controller.abort("user-stopped-waiting");
    appendLocalNotice("Stopped waiting for this response. You can retry the last prompt.");
    input.disabled = false;
    input.focus();
    return true;
  };

  const stopButtonHost = () => {
    const requestProgress = workspace.querySelector(
      '[data-progress-source="request-state"], [data-progress-mode="validated-stages"]',
    );
    const progressHead = requestProgress?.querySelector(".vh-llm-progress-head");
    if (progressHead) return progressHead;

    // The legacy thinking node is intentionally visually suppressed when the
    // request-status component owns the user-facing progress state. Never put
    // the stop control inside that hidden subtree, otherwise the user cannot
    // cancel their local wait even though the request is still in flight.
    const thinkingNode = workspace.querySelector("[data-conversation-thinking]");
    return thinkingNode?.parentElement || form;
  };

  const installStopButton = () => {
    const host = stopButtonHost();
    if (!host) return;

    if (state.stopButton?.isConnected) {
      if (state.stopButton.parentElement !== host) host.append(state.stopButton);
      updateStopButton();
      return;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "vh-stop-response";
    button.dataset.stopResponse = "true";
    button.textContent = "Stop waiting";
    button.title =
      "Stop waiting for this response. The remote provider may already have received the request.";
    button.hidden = true;
    button.addEventListener("click", stopCurrentResponse);
    host.append(button);
    state.stopButton = button;
    updateStopButton();
  };

  const currentFetch = window.fetch.bind(window);
  window.fetch = async (resource, options = {}) => {
    let isMessageRequest = false;
    try {
      const requestUrl = new URL(
        typeof resource === "string"
          ? resource
          : resource instanceof Request
            ? resource.url
            : String(resource),
        window.location.href,
      );
      const method = String(
        options.method || (resource instanceof Request ? resource.method : "GET"),
      ).toUpperCase();
      isMessageRequest = method === "POST" && requestUrl.pathname === messageUrl.pathname;
    } catch (_error) {
      isMessageRequest = false;
    }

    if (!isMessageRequest) return currentFetch(resource, options);

    const controller = new AbortController();
    state.controller = controller;
    installStopButton();
    updateStopButton();
    try {
      return await currentFetch(resource, { ...options, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) {
        return new Response(JSON.stringify({ stopped: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      throw error;
    } finally {
      if (state.controller === controller) state.controller = null;
      updateStopButton();
    }
  };

  const copyText = async (value) => {
    const copy = String(value || "");
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(copy);
      return;
    }
    const proxy = document.createElement("textarea");
    proxy.className = "vh-clipboard-proxy";
    proxy.value = copy;
    proxy.setAttribute("readonly", "");
    document.body.append(proxy);
    proxy.select();
    document.execCommand("copy");
    proxy.remove();
  };

  const feedback = (button, label) => {
    const original = button.dataset.originalLabel || button.textContent;
    button.dataset.originalLabel = original;
    button.textContent = label;
    window.setTimeout(() => {
      if (button.isConnected) button.textContent = original;
    }, 1400);
  };

  const previousUserCopy = (article) => {
    let candidate = article.previousElementSibling;
    while (candidate) {
      if (candidate.matches?.(".vh-chat-message.is-user")) {
        return candidate.querySelector(".vh-message-copy")?.textContent?.trim() || "";
      }
      candidate = candidate.previousElementSibling;
    }
    return "";
  };

  const utilityButton = (label, action) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "vh-message-utility-button";
    button.textContent = label;
    button.addEventListener("click", action);
    return button;
  };

  const bindMessageActions = (article) => {
    if (!(article instanceof HTMLElement) || article.dataset.responseActionsBound === "true") return;
    const messageCopy = article.querySelector(".vh-message-copy");
    const body = article.querySelector(".vh-message-body");
    if (!messageCopy || !body) return;
    article.dataset.responseActionsBound = "true";

    const actions = document.createElement("div");
    actions.className = "vh-message-utility-actions";

    if (article.classList.contains("is-user")) {
      const edit = utilityButton("Edit", () => setInputValue(messageCopy.textContent || ""));
      edit.setAttribute("aria-label", "Edit this prompt in the composer");
      actions.append(edit);
    } else {
      const copy = utilityButton("Copy", async () => {
        try {
          await copyText(messageCopy.dataset.rawMessage || messageCopy.textContent || "");
          feedback(copy, "Copied");
        } catch (_error) {
          feedback(copy, "Copy failed");
        }
      });
      copy.setAttribute("aria-label", "Copy this answer");
      actions.append(copy);

      const prompt = previousUserCopy(article);
      if (prompt) {
        const retry = utilityButton("Retry", () => setInputValue(prompt, { submit: true }));
        retry.setAttribute("aria-label", "Retry the prompt that produced this answer");
        actions.append(retry);
      }
    }

    if (actions.childElementCount) body.append(actions);
  };

  const bindAllMessageActions = () => {
    feed.querySelectorAll(".vh-chat-message").forEach(bindMessageActions);
  };

  bindAllMessageActions();
  installStopButton();
  new MutationObserver(() => {
    bindAllMessageActions();
    installStopButton();
  }).observe(feed, { childList: true, subtree: true });

  // Provider control is dynamically loaded before this script, but keep a
  // bounded DOM observer so the stop control is re-homed if the request-status
  // node appears after initial installation in a slow browser.
  new MutationObserver(() => installStopButton()).observe(workspace, {
    childList: true,
    subtree: true,
  });

  window.VulnHunterResponseControls = Object.freeze({ stopCurrentResponse });
})();