(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const form = workspace?.querySelector("[data-conversation-form]");
  const input = workspace?.querySelector("[data-conversation-input]");
  const send = workspace?.querySelector("[data-conversation-send]");
  const feed = workspace?.querySelector("[data-conversation-feed]");
  if (!workspace || !dataElement || !form || !input || !send || !feed) return;

  let initial;
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    return;
  }

  const messageUrl = new URL(initial.message_url || form.action, window.location.href).href;
  const threadId = workspace.dataset.threadId || "default";
  const draftKey = `vh:conversation-draft:${threadId}`;
  const nativeFetch = window.fetch.bind(window);
  const stableAssistantMessages = [];
  const stableCopies = new WeakMap();
  let activeSend = null;
  let retrySeed = null;

  const createMessageId = () => {
    if (window.crypto?.randomUUID) return `msg:${window.crypto.randomUUID()}`;
    const random = window.crypto?.getRandomValues
      ? Array.from(window.crypto.getRandomValues(new Uint32Array(4)), (value) => value.toString(16)).join("")
      : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
    return `msg:${random}`;
  };

  const safeStorage = {
    read() {
      try {
        return window.sessionStorage.getItem(draftKey) || "";
      } catch (_error) {
        return "";
      }
    },
    write(value) {
      try {
        if (value) window.sessionStorage.setItem(draftKey, value);
        else window.sessionStorage.removeItem(draftKey);
      } catch (_error) {
        // Draft continuity is optional when browser storage is unavailable.
      }
    },
  };

  const deliveryNode = (article) => {
    let node = article.querySelector("[data-message-delivery]");
    if (node) return node;
    node = document.createElement("div");
    node.className = "vh-message-delivery";
    node.dataset.messageDelivery = "true";
    node.setAttribute("role", "status");
    node.setAttribute("aria-live", "polite");
    article.querySelector(".vh-message-body")?.append(node);
    return node;
  };

  const markArticle = (article, state, copy, { retry = false } = {}) => {
    if (!(article instanceof HTMLElement)) return;
    article.dataset.deliveryState = state;
    article.classList.toggle("is-sending", state === "sending");
    article.classList.toggle("is-send-failed", state === "failed");
    article.classList.toggle("is-send-accepted", state === "accepted");
    const node = deliveryNode(article);
    node.replaceChildren();
    const label = document.createElement("span");
    label.textContent = copy;
    node.append(label);
    if (retry) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vh-message-retry";
      button.textContent = "Retry";
      button.addEventListener("click", () => {
        if (activeSend) return;
        retrySeed = {
          id: article.dataset.clientMessageId,
          value: article.dataset.messageCopy || "",
        };
        article.remove();
        input.value = retrySeed.value;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        form.requestSubmit();
      });
      node.append(button);
    }
  };

  const bindOptimisticArticle = () => {
    if (!activeSend) return;
    const candidates = [
      ...feed.querySelectorAll(".vh-chat-message.is-user:not([data-client-message-id])"),
    ];
    const article = candidates.at(-1);
    if (!(article instanceof HTMLElement)) return;
    article.dataset.clientMessageId = activeSend.id;
    article.dataset.messageCopy = activeSend.value;
    activeSend.article = article;
    markArticle(article, "sending", "Sending…");
  };

  const keepComposerEditable = () => {
    if (!activeSend || !input.disabled) return;
    input.disabled = false;
  };

  const responsePayload = async (response) => {
    try {
      const payload = await response.clone().json();
      return payload && typeof payload === "object" ? payload : null;
    } catch (_error) {
      return null;
    }
  };

  const finalizeResponse = async (response, messageId) => {
    const payload = await responsePayload(response);
    if (payload?.message?.role !== "user" && typeof payload?.message?.content === "string") {
      stableAssistantMessages.push(payload.message.content);
    }
    if (!activeSend || activeSend.id !== messageId) return response;
    activeSend.fetchAttempts += 1;
    bindOptimisticArticle();
    if (response.ok) {
      markArticle(activeSend.article, "accepted", "Sent");
      activeSend = null;
      return response;
    }
    if (response.status === 403 && activeSend.fetchAttempts === 1) {
      markArticle(activeSend.article, "sending", "Refreshing session…");
      return response;
    }
    const detail = payload?.detail || payload?.message?.content || "The server rejected this request.";
    markArticle(activeSend.article, "failed", detail);
    activeSend = null;
    return response;
  };

  window.fetch = async (resource, options = {}) => {
    const url = new URL(
      typeof resource === "string" ? resource : resource?.url || String(resource),
      window.location.href,
    ).href;
    const method = String(options.method || (resource instanceof Request ? resource.method : "GET")).toUpperCase();
    const body = options.body;
    const isConversationMessage =
      url === messageUrl && method === "POST" && body instanceof FormData && body.has("message");
    if (!isConversationMessage || !activeSend) return nativeFetch(resource, options);

    body.set("client_message_id", activeSend.id);
    const messageId = activeSend.id;
    try {
      const response = await nativeFetch(resource, options);
      return await finalizeResponse(response, messageId);
    } catch (error) {
      if (activeSend?.id === messageId) {
        bindOptimisticArticle();
        markArticle(
          activeSend.article,
          "failed",
          "Connection interrupted before the response was confirmed.",
          { retry: true },
        );
        activeSend = null;
      }
      throw error;
    }
  };

  form.addEventListener(
    "submit",
    () => {
      if (activeSend || send.disabled) return;
      const value = input.value.trim();
      if (!value) return;
      const seed = retrySeed;
      retrySeed = null;
      activeSend = {
        id: seed?.id || createMessageId(),
        value: seed?.value || value,
        article: null,
        fetchAttempts: 0,
      };
      safeStorage.write("");
      queueMicrotask(() => {
        bindOptimisticArticle();
        keepComposerEditable();
      });
    },
    true,
  );

  input.addEventListener("input", () => {
    safeStorage.write(input.value);
  });

  const disabledObserver = new MutationObserver(() => keepComposerEditable());
  disabledObserver.observe(input, { attributes: true, attributeFilter: ["disabled"] });

  const feedObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof Element)) continue;
        const articles = node.matches(".vh-chat-message")
          ? [node]
          : [...node.querySelectorAll(".vh-chat-message")];
        for (const article of articles) {
          if (!article.classList.contains("is-assistant") || !stableAssistantMessages.length) continue;
          const copy = article.querySelector(".vh-message-copy");
          if (!(copy instanceof HTMLElement)) continue;
          const expected = stableAssistantMessages.shift();
          if (copy.childElementCount > 0) {
            stableCopies.delete(copy);
            continue;
          }
          stableCopies.set(copy, expected);
          copy.textContent = expected;
          article.classList.add("vh-motion-enter");
        }
      }
      const target = mutation.target instanceof Text ? mutation.target.parentElement : mutation.target;
      if (!(target instanceof HTMLElement)) continue;
      const copy = target.closest?.(".vh-message-copy") || (target.matches?.(".vh-message-copy") ? target : null);
      if (!(copy instanceof HTMLElement)) continue;
      if (copy.childElementCount > 0) {
        stableCopies.delete(copy);
        continue;
      }
      const expected = stableCopies.get(copy);
      if (expected !== undefined && copy.textContent !== expected) copy.textContent = expected;
    }
  });
  feedObserver.observe(feed, { childList: true, subtree: true, characterData: true });

  const restoredDraft = safeStorage.read();
  if (!input.value && restoredDraft) {
    input.value = restoredDraft;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  window.VulnHunterConversationContinuity = Object.freeze({
    activeMessageId: () => activeSend?.id || null,
    draftKey: () => draftKey,
  });
})();
