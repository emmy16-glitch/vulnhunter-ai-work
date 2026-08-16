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
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = new URL("./conversation-command-center.css", current).toString();
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
      makeButton("Review findings", "Show me the findings for the current assessment"),
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
    } else if (!existing) {
      feed.append(makeEmptyState());
    }
  };

  const sanitizeRuntime = () => {
    if (!providerRuntime) return;
    providerRuntime.hidden = true;
    providerRuntime.setAttribute("aria-hidden", "true");
    providerRuntime.textContent = "Automatic routing";
    providerRuntime.removeAttribute("title");
    providerRuntime.classList.remove("is-ready", "is-warning", "is-offline");
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
    thinking?.classList.add("is-command-center-active");
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
      if (badge.hasAttribute("title")) badge.removeAttribute("title");
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

  const confirmNewAssessmentInChat = (trigger) => {
    const stay = document.createElement("button");
    stay.type = "button";
    stay.textContent = "Stay here";
    stay.addEventListener("click", () => removeTransientCards("new-assessment"));

    const confirm = document.createElement("button");
    confirm.type = "button";
    confirm.className = "is-primary";
    confirm.textContent = "Start new assessment";
    confirm.addEventListener("click", () => {
      removeTransientCards("new-assessment");
      const resetTarget = trigger.matches(".vh-new-assessment")
        ? workspace.querySelector("[data-conversation-reset]")
        : trigger;
      if (!resetTarget) return;
      resetTarget.dataset.commandCenterConfirmed = "true";
      resetTarget.click();
    });

    actionCard({
      type: "new-assessment",
      label: "Conversation action",
      title: "Start a clean assessment thread?",
      copy: "This changes the active conversation context. It does not authorise a target, start a scanner, or cancel a running assessment by itself.",
      actions: [stay, confirm],
    });
  };

  const runIdFromUrl = (url) => {
    const parts = url.pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
    const markers = new Set(["run", "runs", "agent-run", "agent-runs", "scan-run", "scan-runs"]);
    for (let index = 0; index < parts.length - 1; index += 1) {
      if (markers.has(parts[index].toLowerCase())) return parts[index + 1];
    }
    return "";
  };

  const exactRunCommand = (url, fallback) => {
    const runId = runIdFromUrl(url);
    return runId ? `${fallback} for assessment run ${runId}` : fallback;
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
    if (anchor.matches(".vh-chat-history-item")) {
      command = exactRunCommand(url, "Show me the findings and current status");
    } else if (anchor.matches("[data-run-detail-link]")) {
      command = exactRunCommand(url, "Show the assessment details in this conversation");
    } else if (anchor.matches("[data-findings-link], .vh-chat-history-link")) {
      command = "Show me the findings for the current assessment";
    } else if (path.includes("source-hunt")) {
      command = "Open Source Hunt in this conversation";
    } else if (path.includes("active-validation")) {
      command = "Open Active Validation for the current assessment in this conversation";
    } else if (path.includes("remediation-final-report")) {
      command = "Open the final remediation report in this conversation";
    } else if (path.includes("remediation-review")) {
      command = "Review remediation independently in this conversation";
    } else if (path.includes("retest")) {
      command = "Show the governed retest status and verification result in this conversation";
    } else if (path.includes("remediation")) {
      command = "Show remediation status and the next governed step in this conversation";
    } else if (anchor.closest(".vh-finding-row") || /\/findings?\//.test(path)) {
      const id = path.split("/").filter(Boolean).pop();
      command = id && id !== "findings"
        ? `Explain finding ${id} with its evidence, verification state and remediation`
        : "Show me the findings for the current assessment";
    } else if (/\/runs?\//.test(path) || path.includes("scan-run")) {
      command = exactRunCommand(url, "Show the assessment details in this conversation");
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
        content: `${detail.label || "Governed workflow"} completed. Ask for its status, evidence, findings or next governed step here.`,
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
      actions: [
        makeButton(
          "Ask what happened",
          "Explain what blocked the last governed action and what I should do next",
        ),
      ],
    });
  };

  const markOperationalLinks = () => {
    document.querySelectorAll("a[href]").forEach((anchor) => {
      let url;
      try {
        url = new URL(anchor.href, window.location.href);
      } catch (_error) {
        return;
      }
      const path = url.pathname.toLowerCase();
      if (
        anchor.matches("[data-run-detail-link], [data-findings-link], .vh-chat-history-link, .vh-chat-history-item") ||
        path.includes("source-hunt") ||
        path.includes("active-validation") ||
        path.includes("remediation") ||
        path.includes("retest") ||
        /\/findings?\//.test(path) ||
        /\/runs?\//.test(path)
      ) {
        anchor.dataset.chatRouted = "true";
      }
    });
  };

  document.addEventListener(
    "click",
    (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;

      const reset = target.closest("[data-conversation-reset], [data-thread-create], .vh-new-assessment");
      if (reset) {
        if (reset.dataset.commandCenterConfirmed === "true") {
          delete reset.dataset.commandCenterConfirmed;
        } else {
          event.preventDefault();
          event.stopImmediatePropagation();
          confirmNewAssessmentInChat(reset);
          return;
        }
      }

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

  let reconcileFrame = 0;
  const queueReconcile = () => {
    if (reconcileFrame) return;
    reconcileFrame = window.requestAnimationFrame(() => {
      reconcileFrame = 0;
      reconcile();
    });
  };

  loadStyles();
  reconcile();

  // Only top-level feed changes need reconciliation. Observing every descendant mutation
  // can starve message submission when several existing conversation helpers also observe
  // the feed. Dynamic clicks are routed at the document level, so this stays fully functional.
  new MutationObserver(queueReconcile).observe(feed, { childList: true });

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
