(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-conversation-draft-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-draft\.js$/,
      "conversation-draft.css",
    );
    styleUrl.search = "?v=20260816-pending-state1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.conversationDraftStyles = "true";
    document.head.append(link);
  }
  if (current && !document.querySelector("script[data-conversation-search-loader]")) {
    const searchUrl = new URL(current, window.location.href);
    searchUrl.pathname = searchUrl.pathname.replace(
      /conversation-draft\.js$/,
      "conversation-search.js",
    );
    searchUrl.search = "?v=20260801-search1";
    const script = document.createElement("script");
    script.src = searchUrl.toString();
    script.async = false;
    script.dataset.conversationSearchLoader = "true";
    document.head.append(script);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = document.querySelector("[data-conversation-form]");
  const input = document.querySelector("[data-conversation-input]");
  const composerMeta = document.querySelector(".vh-chat-composer-meta");
  const reset = document.querySelector("[data-conversation-reset]");
  if (!workspace || !dataElement || !form || !input || !composerMeta) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const messageUrl = new URL(initial.message_url, window.location.href);
  const threadId = String(initial.thread_id || workspace.dataset.threadId || "new");
  const storageKey = `vulnhunter:conversation-draft:${window.location.pathname}:${threadId}`;
  const pendingStorageKey = `vulnhunter:conversation-pending:${window.location.pathname}:${threadId}`;
  const maximumLength = Math.min(input.maxLength > 0 ? input.maxLength : 20000, 20000);
  const state = {
    pendingPrompt: "",
    saveTimer: null,
    statusTimer: null,
    pageLeaving: false,
  };

  const status = document.createElement("span");
  status.className = "vh-draft-status";
  status.dataset.draftStatus = "true";
  status.hidden = true;
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  composerMeta.insertBefore(status, composerMeta.firstChild);

  const syncComposerClearance = () => {
    const height = Math.ceil(form.getBoundingClientRect().height);
    if (height > 0) {
      document.documentElement.style.setProperty("--vh-phone-composer-clearance", `${height}px`);
    }
  };

  syncComposerClearance();
  window.requestAnimationFrame(syncComposerClearance);
  if (typeof ResizeObserver === "function") {
    const composerObserver = new ResizeObserver(syncComposerClearance);
    composerObserver.observe(form);
  }
  window.addEventListener("resize", syncComposerClearance, { passive: true });
  window.visualViewport?.addEventListener("resize", syncComposerClearance, { passive: true });

  const storage = {
    read() {
      try {
        const raw = window.sessionStorage.getItem(storageKey);
        if (!raw) return "";
        const parsed = JSON.parse(raw);
        if (parsed?.version !== 1 || typeof parsed.value !== "string") return "";
        return parsed.value.slice(0, maximumLength);
      } catch (_error) {
        return "";
      }
    },
    write(value) {
      try {
        window.sessionStorage.setItem(
          storageKey,
          JSON.stringify({
            version: 1,
            value: String(value || "").slice(0, maximumLength),
            updated_at: new Date().toISOString(),
          }),
        );
        return true;
      } catch (_error) {
        return false;
      }
    },
    clear() {
      try {
        window.sessionStorage.removeItem(storageKey);
      } catch (_error) {
        // Session storage may be unavailable in hardened browser modes.
      }
    },
  };

  const pendingStorage = {
    read() {
      try {
        const raw = window.sessionStorage.getItem(pendingStorageKey);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        if (parsed?.version !== 1 || typeof parsed.value !== "string") return null;
        return {
          value: parsed.value.slice(0, maximumLength),
          submittedAt: String(parsed.submitted_at || ""),
        };
      } catch (_error) {
        return null;
      }
    },
    write(value) {
      try {
        window.sessionStorage.setItem(
          pendingStorageKey,
          JSON.stringify({
            version: 1,
            value: String(value || "").slice(0, maximumLength),
            submitted_at: new Date().toISOString(),
          }),
        );
        return true;
      } catch (_error) {
        return false;
      }
    },
    clear() {
      try {
        window.sessionStorage.removeItem(pendingStorageKey);
      } catch (_error) {
        // Session storage may be unavailable in hardened browser modes.
      }
    },
  };

  const announce = (copy, stateName = "saved", duration = 1800) => {
    if (state.statusTimer) window.clearTimeout(state.statusTimer);
    status.textContent = copy;
    status.dataset.state = stateName;
    status.hidden = false;
    syncComposerClearance();
    if (duration > 0) {
      state.statusTimer = window.setTimeout(() => {
        status.hidden = true;
        status.textContent = "";
        delete status.dataset.state;
        syncComposerClearance();
      }, duration);
    }
  };

  const setInputValue = (value) => {
    const next = String(value || "").slice(0, maximumLength);
    input.value = next;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  };

  const saveDraft = ({ quiet = false } = {}) => {
    if (state.pendingPrompt || pendingStorage.read()?.value) return;
    const value = String(input.value || "").slice(0, maximumLength);
    if (!value.trim()) {
      storage.clear();
      if (!quiet) announce("Draft cleared", "cleared", 1000);
      return;
    }
    const saved = storage.write(value);
    if (!quiet) {
      announce(saved ? "Draft saved" : "Draft unavailable", saved ? "saved" : "unavailable");
    }
  };

  const restorePrompt = (copy = "Prompt restored") => {
    const pending = pendingStorage.read();
    const value = state.pendingPrompt || pending?.value || storage.read();
    if (!value) return;
    pendingStorage.clear();
    state.pendingPrompt = "";
    storage.write(value);
    window.queueMicrotask(() => {
      if (!input.value.trim()) setInputValue(value);
      announce(copy, "restored", 2200);
    });
  };

  const restored = storage.read();
  const previousPending = pendingStorage.read();
  if (restored && !input.value.trim()) {
    setInputValue(restored);
    announce("Draft restored", "restored", 2400);
  } else if (previousPending?.value && !input.value.trim()) {
    announce(
      "Previous request was already submitted. Check the conversation before retrying.",
      "pending",
      4200,
    );
  }

  input.addEventListener("input", () => {
    if (state.saveTimer) window.clearTimeout(state.saveTimer);
    state.saveTimer = window.setTimeout(() => saveDraft(), 350);
  });

  form.addEventListener(
    "submit",
    () => {
      const value = String(input.value || "").slice(0, maximumLength);
      if (!value.trim()) return;
      if (state.saveTimer) window.clearTimeout(state.saveTimer);
      state.saveTimer = null;
      state.pendingPrompt = value;
      storage.clear();
      pendingStorage.write(value);
      announce("Sending…", "sending", 0);
    },
    true,
  );

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

    try {
      const response = await currentFetch(resource, options);
      let body = {};
      try {
        body = await response.clone().json();
      } catch (_error) {
        body = {};
      }
      if (body.stopped === true) {
        restorePrompt("Prompt restored after stopping");
      } else if (response.ok) {
        storage.clear();
        pendingStorage.clear();
        state.pendingPrompt = "";
        announce("Sent", "sent", 1000);
      } else {
        pendingStorage.clear();
        restorePrompt("Draft kept after the failed request");
      }
      return response;
    } catch (error) {
      if (!state.pageLeaving) {
        pendingStorage.clear();
        restorePrompt("Draft kept after the connection error");
      }
      throw error;
    }
  };

  reset?.addEventListener("click", () => {
    storage.clear();
    pendingStorage.clear();
    state.pendingPrompt = "";
    announce("Draft cleared", "cleared", 1000);
  });

  window.addEventListener("pagehide", () => {
    state.pageLeaving = true;
    if (!state.pendingPrompt && !pendingStorage.read()?.value) saveDraft({ quiet: true });
  });

  window.VulnHunterConversationDraft = Object.freeze({
    storageKey,
    pendingStorageKey,
    restore: () => restorePrompt("Draft restored"),
    restorePending: () => restorePrompt("Submitted prompt restored for retry"),
    clear: () => {
      storage.clear();
      pendingStorage.clear();
      state.pendingPrompt = "";
    },
  });
})();
