(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src || "";
  const workspace = document.querySelector("[data-conversation-workspace]");
  const feed = document.querySelector("[data-conversation-feed]");
  const form = document.querySelector("[data-conversation-form]");
  const input = document.querySelector("[data-conversation-input]");
  const thinking = document.querySelector("[data-conversation-thinking]");
  const thinkingCopy = document.querySelector("[data-thinking-copy]");
  const providerRuntime = document.querySelector("[data-provider-runtime]");

  if (!workspace || !feed || !form || !input) return;

  const loadStyles = () => {
    if (!current || document.querySelector("link[data-command-center-styles]")) return;
    const href = new URL("./conversation-command-center.css", current).toString();
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    link.dataset.commandCenterStyles = "true";
    document.head.append(link);
  };

  const scrollToLatest = () => {
    window.requestAnimationFrame(() => {
      feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" });
    });
  };

  const submitCommand = (message) => {
    const value = String(message || "").trim();
    if (!value || input.disabled) return;
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    form.requestSubmit();
  };

  const makeButton = (label, command, className = "") => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    if (className) button.className = className;
    button.addEventListener("click", () => submitCommand(command));
    return button;
  };

  const makeEmptyState = () => {
    const section = document.createElement("section");
    section.className = "vh-chat-empty-state";
    section.dataset.chatEmptyState = "true";
    section.setAttribute("aria-label", "Start a VulnHunter conversation");

    const mark = document.createElement("div");
    mark.className = "vh-chat-empty-mark";
    mark.textContent = "VH";
    mark.setAttribute("aria-hidden", "true");

    const heading = document.createElement("h2");
    heading.textContent = "VulnHunter Workspace";

    const copy = document.createElement("p");
    copy.textContent =
      "Ask a security question, provide an authorised target, upload an APK, or continue a governed assessment. You speak first; every operational step stays in this conversation.";

    const actions = document.createElement("div");
    actions.className = "vh-chat-empty-actions";
    actions.append(
      makeButton("Assess a website", "I want to assess an authorised website"),
      makeButton("Analyse an APK", "I want to analyse an APK"),
      makeButton("Review findings", "Show me all findings in this workspace"),
      makeButton("Source Hunt", "Open Source Hunt in this conversation"),
    );

    section.append(mark, heading, copy, actions);
    return section;
  };

  const syncEmptyState = () => {
    const hasConversation = Boolean(
      feed.querySelector(".vh-chat-message, [data-run-card], .vh-chat-action-card:not([data-empty-helper])"),
    );
    const existing = feed.querySelector("[data-chat-empty-state]");
    if (hasConversation) {
      existing?.remove();
      return;
    }
    if (!existing) feed.append(makeEmptyState());
  };

  const sanitizeRuntime = () => {
    if (!providerRuntime) return;
    const detail = String(providerRuntime.getAttribute("title") || "");
    const unavailable = /unavailable|disabled|not configured/i.test(detail);
    providerRuntime.textContent = unavailable ? "AI reasoning unavailable" : "AI reasoning ready";
    providerRuntime.setAttribute(
      "title",
      unavailable
        ? "High-reasoning conversational assistance is currently unavailable."
        : "High reasoning with automatic provider routing is ready.",
    );
  };

  const activityCopy = (value) => {
    const text = String(value || "").toLowerCase();
    if (/confirmation|approval|recording/.test(text)) return "Recording the governed confirmation…";
    if (/authori[sz]|scope|target/.test(text)) return "Checking authorisation and scope…";
    if (/scanner|assessment|running|execution/.test(text)) return "Running the authorised assessment…";
    if (/evidence|artifact/.test(text)) return "Collecting governed evidence…";
    if (/verif|validation/.test(text)) return "Verifying observations…";
    if (/clean conversation|reset/.test(text)) return "Starting a clean conversation…";
    if (/result|report|summar/.test(text)) return "Preparing the response…";
    return "Reviewing the request and workspace context…";
  };

  const sanitizeThinking = () => {
    if (thinking) thinking.classList.add("is-command-center-active");
    if (!thinkingCopy) return;
    const safe = activityCopy(thinkingCopy.textContent);
    if (thinkingCopy.textContent !== safe) thinkingCopy.textContent = safe;
  };

  const sanitizeReasoningBadges = () => {
    feed.querySelectorAll(".vh-message-reasoning").forEach((badge) => {
      badge.classList.add("is-command-center-reasoning");
      if (badge.textContent !== "High reasoning · governed context") {
        badge.textContent = "High reasoning · governed context";
      }
      badge.removeAttribute("title");
    });
  };

  const decorateRunCards = () => {
    feed.querySelectorAll("[data-run-card]").forEach((card) => {
      card.classList.add("is-command-center-run");
    });
  };

  const renderMessage = ({ role = "assistant", content = "", kind = "status" }) => {
    const value = String(content || "").trim();
    if (!value) return null;
    const article = document.createElement("article");
    article.className = `vh-chat-message is-${role}`;
    article.dataset.commandCenterMessage = "true";
    article.dataset.kind = kind;

    const avatar = document.createElement("div");
    avatar.className = "vh-message-avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = role === "user" ? "YOU" : "VH";

    const body = document.createElement("div");
    body.className = "vh-message-body";
    const copy = document.createElement("div");
    copy.className = "vh-message-copy";
    copy.textContent = value;
    body.append(copy);

    article.append(avatar, body);
    feed.append(article);
    syncEmptyState();
    scrollToLatest();
    return article;
  };

  const removeTransientCards = (type) => {
    feed.querySelectorAll(`.vh-chat-action-card[data-action-type="${type}"]`).forEach((item) => item.remove());
  };

  const actionCard = ({ type, label, title, copy, tone = "", actions = [] }) => {
    removeTransientCards(type);
    const card = document.createElement("section");
    card.className = `vh-chat-action-card${tone ? ` ${tone}` : ""}`;
    card.dataset.actionType = type;

    const heading = document.createElement("div");
    heading.className = "vh-chat-action-heading";
    const icon = document.createElement("span");
    icon.className = "vh-chat-action-icon";
    icon.textContent = type === "cancel" ? "!" : type === "protected" ? "◆" : "→";
    icon.setAttribute("aria-hidden", "true");
    const headingText = document.createElement("div");
    const small = document.createElement("small");
    small.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = title;
    headingText.append(small, strong);
    heading.append(icon, headingText);

    const paragraph = document.createElement("p");
    paragraph.textContent = copy;
    const controls = document.createElement("div");
    controls.className = "vh-chat-action-actions";
    actions.forEach((item) => controls.append(item));
    card.append(heading, paragraph, controls);
    feed.append(card);
    syncEmptyState();
    scrollToLatest();
    return card;
  };

  const confirmCancelInChat = (button) => {
    const card = button.closest("[data-run-card]");
    const target = card?.querySelector("[data-run-target]")?.textContent?.trim() || "the current assessment";
    const keep = document.createElement("button");
    keep.type = "button";
    keep.textContent = "Keep running";
    keep.addEventListener("click", () => removeTransientCards("cancel"));

    const confirm = document.createElement("button");
    confirm.type = "button";
    confirm.className = "is-danger";
    confirm.textContent = "Confirm cancel";
    confirm.addEventListener("click", () => {
      removeTransientCards("cancel");
      submitCommand(`Cancel the current assessment for ${target}`);
    });

    actionCard({
      type: "cancel",
      label: "Governed action",
      title: "Cancel this assessment?",
      copy: `No additional scanner work will be started for ${target}. Completed evidence remains in governed state.`,
      actions: [keep, confirm],
    });
  };

  const routeOperationalLink = (anchor) => {
    if (!(anchor instanceof HTMLAnchorElement)) return false;
    if (anchor.matches(".vh-thread-item")) return false;
    if (anchor.hasAttribute("download") || anchor.target === "_blank") return false;

    let url;
    try {
      url = new URL(anchor.href, window.location.href);
    } catch (_error) {
      return false;
    }
    if (url.origin !== window.location.origin) return false;

    let command = "";
    const path = url.pathname.toLowerCase();
    if (anchor.matches("[data-run-detail-link]")) command = "Show the current assessment details in this conversation";
    else if (anchor.matches("[data-findings-link], .vh-chat-history-link")) command = "Show me all findings in this workspace";
    else if (path.includes("source-hunt")) command = "Open Source Hunt in this conversation";
    else if (anchor.closest(".vh-finding-row") || /\/findings?\//.test(path)) {
      const id = path.split("/").filter(Boolean).pop();
      command = id && id !== "findings"
        ? `Explain finding ${id} with its evidence, verification state and remediation`
        : "Show me all findings in this workspace";
    } else if (anchor.matches(".vh-chat-history-item")) {
      const target = anchor.querySelector("strong")?.textContent?.trim();
      command = target
        ? `Show the assessment history and current results for ${target} in this conversation`
        : "Show my recent assessments in this conversation";
    } else if (/\/runs?\//.test(path) || path.includes("scan-run")) {
      command = "Show the current assessment details in this conversation";
    }

    if (!command) return false;
    anchor.dataset.chatRouted = "true";
    submitCommand(command);
    return true;
  };

  const renderProtectedStep = (label, redirectUrl, copy) => {
    const continueButton = document.createElement("button");
    continueButton.type = "button";
    continueButton.className = "is-primary";
    continueButton.textContent = "Continue protected step";
    continueButton.addEventListener("click", () => {
      // Password re-authentication and provider-processing consent must never be put in chat text.
      window.location.assign(redirectUrl);
    });
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = "Keep chatting";
    dismiss.addEventListener("click", () => removeTransientCards("protected"));
    actionCard({
      type: "protected",
      label: "Protected security step",
      title: `${label} needs explicit re-authentication`,
      copy,
      tone: "is-protected",
      actions: [dismiss, continueButton],
    });
  };

  const handleSpecialistStart = (event) => {
    const detail = event.detail || {};
    renderMessage({ role: "user", content: detail.message || "", kind: "text" });
  };

  const handleSpecialistResponse = (event) => {
    const detail = event.detail || {};
    const body = detail.body || {};
    if (body.message?.content) {
      renderMessage({
        role: body.message.role || "assistant",
        kind: body.message.kind || "status",
        content: body.message.content,
      });
    } else {
      renderMessage({
        role: "assistant",
        kind: "status",
        content: `${detail.label || "Governed workflow"} updated in this workspace.`,
      });
    }
    if (body.redirect_url) {
      renderProtectedStep(
        detail.label || "This workflow",
        body.redirect_url,
        "This step collects credentials or explicit processing consent. It is intentionally isolated from ordinary chat history; return here immediately after completing it.",
      );
    }
  };

  const handleSpecialistError = (event) => {
    const detail = event.detail || {};
    actionCard({
      type: "specialist-error",
      label: "Workflow issue",
      title: `${detail.label || "Governed workflow"} could not complete`,
      copy: detail.message || "The request could not be completed. You can adjust the request and try again in this conversation.",
      tone: "is-error",
      actions: [makeButton("Ask what happened", "Explain what blocked the last governed action and what I should do next")],
    });
  };

  const markOperationalLinks = () => {
    document.querySelectorAll("a[href]").forEach((anchor) => {
      let url;
      try { url = new URL(anchor.href, window.location.href); } catch (_error) { return; }
      const path = url.pathname.toLowerCase();
      if (
        anchor.matches("[data-run-detail-link], [data-findings-link], .vh-chat-history-link, .vh-chat-history-item") ||
        path.includes("source-hunt") ||
        /\/findings?\//.test(path) ||
        /\/runs?\//.test(path)
      ) anchor.dataset.chatRouted = "true";
    });
  };

  document.addEventListener(
    "click",
    (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      const cancel = target.closest("[data-run-cancel], [data-approval-cancel]");
      if (cancel) {
        event.preventDefault();
        event.stopImmediatePropagation();
        confirmCancelInChat(cancel);
        return;
      }
      const anchor = target.closest("a[href]");
      if (anchor && routeOperationalLink(anchor)) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    },
    true,
  );

  document.addEventListener("vulnhunter:specialist-start", handleSpecialistStart);
  document.addEventListener("vulnhunter:specialist-response", handleSpecialistResponse);
  document.addEventListener("vulnhunter:specialist-error", handleSpecialistError);

  const reconcile = () => {
    sanitizeRuntime();
    sanitizeThinking();
    sanitizeReasoningBadges();
    decorateRunCards();
    markOperationalLinks();
    syncEmptyState();
  };

  loadStyles();
  reconcile();
  new MutationObserver(reconcile).observe(feed, { childList: true, subtree: true });
  if (thinkingCopy) {
    new MutationObserver(sanitizeThinking).observe(thinkingCopy, {
      childList: true,
      characterData: true,
      subtree: true,
    });
  }

  window.VulnHunterChatCommandCenter = Object.freeze({
    submitCommand,
    syncEmptyState,
    renderMessage,
  });
})();
