(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = workspace?.querySelector("[data-conversation-form]");
  const feed = workspace?.querySelector("[data-conversation-feed]");
  const input = workspace?.querySelector("[data-conversation-input]");
  const send = workspace?.querySelector("[data-conversation-send]");
  const attachButton = workspace?.querySelector("[data-conversation-attach]");
  const fileInput = workspace?.querySelector("[data-conversation-file]");
  const tray = workspace?.querySelector("[data-attachment-tray]");
  const thinking = workspace?.querySelector("[data-conversation-thinking]");
  const thinkingCopy = workspace?.querySelector("[data-thinking-copy]");
  const reset = workspace?.querySelector("[data-conversation-reset]");
  const messageTemplate = document.getElementById("vh-message-template");
  if (!form || !feed || !input || !attachButton || !fileInput || !tray || !messageTemplate) return;

  const csrfToken = form.querySelector("input[name='csrfmiddlewaretoken']")?.value || "";
  const attachmentUrl = form.dataset.attachmentUrl || "";
  const mobileMessageUrl = form.dataset.mobileMessageUrl || "";
  let activeAttachment = null;
  let mobileBusy = false;

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value)
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const formatBytes = (value) => {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const scrollLatest = () => {
    const controller = window.VulnHunterConversationScroll;
    if (controller?.scrollToLatest) {
      controller.scrollToLatest({ behavior: "smooth", force: true });
      return;
    }
    window.requestAnimationFrame(() => feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" }));
  };

  const setBusy = (busy, copy) => {
    mobileBusy = busy;
    attachButton.disabled = busy;
    fileInput.disabled = busy;
    if (send) send.disabled = busy;
    if (thinking) thinking.hidden = !busy;
    if (thinkingCopy && copy) thinkingCopy.textContent = copy;
    if (busy) scrollLatest();
  };

  const readJson = async (response) => {
    try {
      return await response.json();
    } catch (_error) {
      return { detail: "The server returned an unreadable response." };
    }
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

  const attachmentCard = (attachment, { removable = false } = {}) => {
    const card = document.createElement("div");
    card.className = "vh-apk-attachment-card";
    const icon = document.createElement("span");
    icon.className = "vh-apk-attachment-icon";
    icon.textContent = "APK";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = text(attachment.original_filename || "Android application.apk");
    const detail = document.createElement("small");
    const native = Number(attachment.native_library_count || 0);
    detail.textContent = `${formatBytes(attachment.size_bytes)} · ${Number(attachment.dex_count || 0)} DEX${native ? ` · ${native} native` : ""}`;
    const digest = document.createElement("code");
    digest.textContent = `SHA-256 ${text(attachment.artifact_sha256).slice(0, 18)}…`;
    copy.append(title, detail, digest);
    card.append(icon, copy);
    if (removable) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "vh-apk-attachment-remove";
      remove.setAttribute("aria-label", "Remove APK attachment");
      remove.textContent = "×";
      remove.addEventListener("click", () => {
        activeAttachment = null;
        fileInput.value = "";
        tray.replaceChildren();
        tray.hidden = true;
        attachButton.focus();
      });
      card.append(remove);
    }
    return card;
  };

  const renderTray = (attachment) => {
    tray.replaceChildren(attachmentCard(attachment, { removable: true }));
    tray.hidden = false;
  };

  const appendMessage = (message, { attachment = null, plan = null, error = false } = {}) => {
    const fragment = messageTemplate.content.cloneNode(true);
    const article = fragment.querySelector(".vh-chat-message");
    const avatar = fragment.querySelector(".vh-message-avatar");
    const body = fragment.querySelector(".vh-message-body");
    const copy = fragment.querySelector(".vh-message-copy");
    const actions = fragment.querySelector(".vh-message-actions");
    const role = message.role === "user" ? "user" : "assistant";
    article.classList.add(`is-${role}`, error ? "is-error" : `is-${text(message.kind || "text")}`);
    avatar.textContent = role === "user" ? "You" : "VH";
    copy.textContent = text(message.content || "");
    if (attachment) body.insertBefore(attachmentCard(attachment), copy);
    if (plan) body.append(renderPlan(plan));

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

  const renderPlan = (plan) => {
    const card = document.createElement("section");
    card.className = "vh-mobile-hunt-card";
    const header = document.createElement("header");
    const heading = document.createElement("div");
    const eyebrow = document.createElement("small");
    eyebrow.textContent = "Prepared Raptor-style mobile hunt";
    const title = document.createElement("strong");
    title.textContent = `${pretty(plan.profile)} · ${Number(plan.tool_count || 0)} tools`;
    const digest = document.createElement("code");
    digest.textContent = text(plan.plan_digest || "").slice(0, 24);
    heading.append(eyebrow, title);
    header.append(heading, digest);

    const tools = document.createElement("div");
    tools.className = "vh-mobile-tool-chips";
    (Array.isArray(plan.tools) ? plan.tools : []).forEach((tool) => {
      const chip = document.createElement("span");
      chip.textContent = text(tool.name || tool.tool_id);
      chip.title = `${pretty(tool.gate)} gate${tool.requires_isolation ? " · isolation required" : ""}`;
      tools.append(chip);
    });

    const rounds = document.createElement("ol");
    rounds.className = "vh-mobile-hunt-rounds";
    (Array.isArray(plan.rounds) ? plan.rounds : []).forEach((round, index) => {
      const item = document.createElement("li");
      item.className = `is-${text(round.status || "planned")}`;
      const marker = document.createElement("span");
      marker.textContent = round.status === "blocked" ? "!" : String(index + 1);
      const content = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = text(round.label);
      const purpose = document.createElement("small");
      purpose.textContent = text(round.blocked_reason || round.purpose);
      content.append(label, purpose);
      item.append(marker, content);
      rounds.append(item);
      window.setTimeout(() => item.classList.add("is-visible"), 90 + index * 120);
    });

    const footer = document.createElement("footer");
    footer.textContent = plan.dynamic_deferred
      ? "Static and native coverage is prepared. Runtime work remains separately gated."
      : "The plan is prepared; tool execution remains governed by worker policy and exact approvals.";
    card.append(header, tools, rounds, footer);
    return card;
  };

  const uploadAttachment = async (file) => {
    if (!attachmentUrl) throw new Error("The APK attachment endpoint is unavailable.");
    const payload = new FormData();
    payload.append("attachment", file);
    setBusy(true, "Validating the APK archive and computing its content hash…");
    tray.hidden = false;
    tray.innerHTML = '<div class="vh-apk-uploading"><span></span><strong>Checking APK structure…</strong></div>';
    try {
      const data = await postForm(attachmentUrl, payload);
      activeAttachment = data.attachment;
      renderTray(activeAttachment);
      if (!input.value.trim()) input.value = "Test this APK and find security weaknesses.";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
    } catch (error) {
      activeAttachment = null;
      fileInput.value = "";
      tray.replaceChildren();
      tray.hidden = true;
      appendMessage(
        { role: "assistant", kind: "error", content: error.message },
        { error: true },
      );
    } finally {
      setBusy(false);
    }
  };

  attachButton.addEventListener("click", () => {
    if (!mobileBusy) fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      appendMessage(
        { role: "assistant", kind: "error", content: "Choose a file with the .apk extension." },
        { error: true },
      );
      fileInput.value = "";
      return;
    }
    uploadAttachment(file);
  });

  form.addEventListener(
    "submit",
    async (event) => {
      if (!activeAttachment) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      if (mobileBusy) return;
      const value = input.value.trim();
      if (!value) return;
      const attachment = activeAttachment;
      appendMessage(
        { role: "user", kind: "text", content: value },
        { attachment },
      );
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      setBusy(true, "Selecting governed tools and building multi-altitude hunt coverage…");
      try {
        const payload = new FormData();
        payload.append("message", value);
        payload.append("attachment_id", text(attachment.attachment_id));
        const data = await postForm(mobileMessageUrl, payload);
        const message = data.message || {
          role: "assistant",
          kind: "mobile_plan",
          content: "The mobile hunt plan is ready.",
        };
        appendMessage(message, {
          attachment,
          plan: data.mobile_plan || message.metadata?.mobile_plan,
        });
        activeAttachment = null;
        fileInput.value = "";
        tray.replaceChildren();
        tray.hidden = true;
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

  reset?.addEventListener("click", () => {
    activeAttachment = null;
    fileInput.value = "";
    tray.replaceChildren();
    tray.hidden = true;
  });
})();
