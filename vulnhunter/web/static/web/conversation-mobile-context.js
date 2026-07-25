(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = workspace?.querySelector("[data-conversation-form]");
  const feed = workspace?.querySelector("[data-conversation-feed]");
  const input = workspace?.querySelector("[data-conversation-input]");
  const send = workspace?.querySelector("[data-conversation-send]");
  const thinking = workspace?.querySelector("[data-conversation-thinking]");
  const thinkingCopy = workspace?.querySelector("[data-thinking-copy]");
  const reset = workspace?.querySelector("[data-conversation-reset]");
  const fileInput = workspace?.querySelector("[data-conversation-file]");
  const messageTemplate = document.getElementById("vh-message-template");
  if (!form || !feed || !input || !messageTemplate) return;

  const csrfToken = form.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  const followupUrl = form.dataset.mobileFollowupUrl || "";
  const contextUrl = form.dataset.mobileContextUrl || "";
  const resetUrl = form.dataset.mobileResetUrl || "";
  let activeMobilePlan = null;
  let bypassMobileFollowup = false;
  let contextBusy = false;

  const text = (value) => (value === null || value === undefined ? "" : String(value));

  const scrollLatest = () => {
    const controller = window.VulnHunterConversationScroll;
    if (controller?.scrollToLatest) {
      controller.scrollToLatest({ behavior: "smooth", force: true });
      return;
    }
    window.requestAnimationFrame(() => feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" }));
  };

  const readJson = async (response) => {
    try {
      return await response.json();
    } catch (_error) {
      return { detail: "The server returned an unreadable response." };
    }
  };

  const getJson = async (url) => {
    const response = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const data = await readJson(response);
    if (!response.ok) throw new Error(data.detail || "The mobile context request failed.");
    return data;
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

  const setBusy = (busy, copy) => {
    contextBusy = busy;
    if (send) send.disabled = busy;
    if (thinking) thinking.hidden = !busy;
    if (thinkingCopy && copy) thinkingCopy.textContent = copy;
    if (busy) scrollLatest();
  };

  const appendMessage = (message, { error = false } = {}) => {
    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    const role = message.role === "user" ? "user" : "assistant";
    article.classList.add(`is-${role}`, error ? "is-error" : `is-${text(message.kind || "text")}`);
    avatar.textContent = role === "user" ? "You" : "VH";
    copy.textContent = text(message.content || "");

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
  };

  const restoreContext = async () => {
    if (!contextUrl) return;
    try {
      const payload = await getJson(contextUrl);
      activeMobilePlan = payload.mobile_plan || null;
    } catch (_error) {
      activeMobilePlan = null;
    }
  };

  const observeMobilePlan = () => {
    const observer = new MutationObserver((mutations) => {
      const planAdded = mutations.some((mutation) =>
        [...mutation.addedNodes].some(
          (node) =>
            node instanceof Element &&
            (node.matches("[data-mobile-hunt-card]") ||
              node.querySelector("[data-mobile-hunt-card]")),
        ),
      );
      if (planAdded) window.setTimeout(restoreContext, 100);
    });
    observer.observe(feed, { childList: true, subtree: true });
  };

  const clearContext = async () => {
    activeMobilePlan = null;
    if (!resetUrl) return;
    const payload = new FormData();
    try {
      await postForm(resetUrl, payload);
    } catch (_error) {
      // The normal reset still clears the visible conversation. Context remains fail-closed.
    }
  };

  form.addEventListener(
    "submit",
    async (event) => {
      if (bypassMobileFollowup) {
        bypassMobileFollowup = false;
        return;
      }
      if (!activeMobilePlan || fileInput?.files?.length) return;
      if (contextBusy) {
        event.preventDefault();
        event.stopImmediatePropagation();
        return;
      }
      const value = input.value.trim();
      if (!value || !followupUrl) return;

      event.preventDefault();
      event.stopImmediatePropagation();
      setBusy(true, "Reasoning over the selected APK plan and current evidence…");
      try {
        const payload = new FormData();
        payload.append("message", value);
        const data = await postForm(followupUrl, payload);
        if (data.handoff) {
          activeMobilePlan = null;
          bypassMobileFollowup = true;
          form.requestSubmit();
          return;
        }

        appendMessage({ role: "user", kind: "text", content: value });
        input.value = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        activeMobilePlan = data.mobile_plan || activeMobilePlan;
        appendMessage(
          data.message || {
            role: "assistant",
            kind: "text",
            content: "The mobile hunt context is available.",
          },
        );
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

  reset?.addEventListener("click", clearContext);
  observeMobilePlan();
  restoreContext();
})();
