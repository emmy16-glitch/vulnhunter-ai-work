(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-conversation-export-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(/conversation-export\.js$/, "conversation-export.css");
    styleUrl.search = "?v=20260812-ui2";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.conversationExportStyles = "true";
    document.head.append(link);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const actionMenu = workspace?.querySelector(".vh-task-menu-popover");
  const feed = document.querySelector("[data-conversation-feed]");
  if (!workspace || !actionMenu || !feed) return;

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "vh-task-menu-action vh-conversation-export-trigger";
  trigger.dataset.conversationExportTrigger = "true";
  trigger.textContent = "Export conversation";
  trigger.title = "Copy or download this conversation as Markdown";
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("aria-controls", "vh-conversation-export");
  actionMenu.append(trigger);

  const panel = document.createElement("section");
  panel.id = "vh-conversation-export";
  panel.className = "vh-conversation-export";
  panel.dataset.conversationExport = "true";
  panel.hidden = true;
  panel.setAttribute("aria-label", "Export this conversation");

  const heading = document.createElement("div");
  heading.className = "vh-conversation-export-heading";
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "Current conversation";
  const title = document.createElement("strong");
  title.textContent = "Export conversation";
  const description = document.createElement("small");
  description.textContent = "Exports only messages already visible in this workspace. It does not publish findings or change governance state.";
  heading.append(eyebrow, title, description);

  const actions = document.createElement("div");
  actions.className = "vh-conversation-export-actions";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.dataset.conversationExportCopy = "true";
  copy.textContent = "Copy Markdown";
  const download = document.createElement("button");
  download.type = "button";
  download.dataset.conversationExportDownload = "true";
  download.textContent = "Download .md";
  const close = document.createElement("button");
  close.type = "button";
  close.dataset.conversationExportClose = "true";
  close.textContent = "×";
  close.setAttribute("aria-label", "Close conversation export");
  actions.append(copy, download, close);
  panel.append(heading, actions);
  workspace.append(panel);

  function threadTitle() {
    const value = document.querySelector("#vh-chat-title")?.textContent?.trim();
    return (value || "VulnHunter Conversation").replace(/\s+/g, " ").trim();
  }

  function messageContent(message) {
    const copyElement = message.querySelector(".vh-message-copy");
    if (!copyElement) return "";
    return String(copyElement.dataset.rawMessage || copyElement.textContent || "")
      .replaceAll("\r\n", "\n")
      .trim();
  }

  function buildMarkdown() {
    const sections = [`# ${threadTitle()}`, "", "_Exported from VulnHunter._"];
    feed.querySelectorAll(".vh-chat-message").forEach((message) => {
      if (message.classList.contains("is-local-notice")) return;
      const role = message.classList.contains("is-user")
        ? "You"
        : message.classList.contains("is-assistant")
          ? "VulnHunter"
          : "";
      const content = messageContent(message);
      if (!role || !content) return;
      sections.push("", `## ${role}`, "", content);
    });
    return `${sections.join("\n").trim()}\n`;
  }

  function slug(value) {
    const result = String(value || "conversation")
      .toLocaleLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 72);
    return result || "vulnhunter-conversation";
  }

  async function copyText(value) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const proxy = document.createElement("textarea");
    proxy.className = "vh-clipboard-proxy";
    proxy.value = value;
    proxy.setAttribute("readonly", "");
    document.body.append(proxy);
    proxy.select();
    document.execCommand("copy");
    proxy.remove();
  }

  function temporaryLabel(button, value) {
    const original = button.dataset.originalLabel || button.textContent;
    button.dataset.originalLabel = original;
    button.textContent = value;
    window.setTimeout(() => {
      if (button.isConnected) button.textContent = original;
    }, 1400);
  }

  function downloadMarkdown() {
    const blob = new Blob([buildMarkdown()], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${slug(threadTitle())}.md`;
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function open() {
    panel.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    trigger.closest("details")?.removeAttribute("open");
    window.requestAnimationFrame(() => copy.focus());
  }

  function closePanel({ focusTrigger = true } = {}) {
    panel.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (focusTrigger) trigger.focus({ preventScroll: true });
  }

  trigger.addEventListener("click", open);
  close.addEventListener("click", () => closePanel());
  copy.addEventListener("click", async () => {
    try {
      await copyText(buildMarkdown());
      temporaryLabel(copy, "Copied");
    } catch (_error) {
      temporaryLabel(copy, "Copy failed");
    }
  });
  download.addEventListener("click", downloadMarkdown);
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || panel.hidden) return;
    event.preventDefault();
    closePanel();
  });
  document.addEventListener("pointerdown", (event) => {
    if (panel.hidden || panel.contains(event.target) || trigger.contains(event.target)) return;
    closePanel({ focusTrigger: false });
  });

  window.VulnHunterConversationExport = Object.freeze({
    buildMarkdown,
    copy: () => copyText(buildMarkdown()),
    download: downloadMarkdown,
    open,
    close: closePanel,
  });
})();
