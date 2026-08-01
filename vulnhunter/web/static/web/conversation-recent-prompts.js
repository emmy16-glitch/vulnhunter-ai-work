(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-recent-prompts-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-recent-prompts\.js$/,
      "conversation-recent-prompts.css",
    );
    styleUrl.search = "?v=20260801-recent-prompts1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.recentPromptsStyles = "true";
    document.head.append(link);
  }
  if (current && !document.querySelector("script[data-conversation-export-loader]")) {
    const exportUrl = new URL(current, window.location.href);
    exportUrl.pathname = exportUrl.pathname.replace(
      /conversation-recent-prompts\.js$/,
      "conversation-export.js",
    );
    exportUrl.search = "?v=20260801-export1";
    const script = document.createElement("script");
    script.src = exportUrl.toString();
    script.async = false;
    script.dataset.conversationExportLoader = "true";
    document.head.append(script);
  }

  const feed = document.querySelector("[data-conversation-feed]");
  const list = document.querySelector(".vh-composer-prompt-list");
  const empty = list?.querySelector("[data-composer-prompt-empty]");
  if (!feed || !list || !empty) return;

  const maximumPrompts = 5;
  const maximumValueLength = 4000;
  let renderScheduled = false;

  const section = document.createElement("section");
  section.className = "vh-composer-recent-prompts";
  section.dataset.recentPrompts = "true";
  section.hidden = true;

  const heading = document.createElement("div");
  heading.className = "vh-composer-recent-heading";
  const title = document.createElement("strong");
  title.textContent = "Recent prompts";
  const description = document.createElement("small");
  description.textContent = "Reuse a prompt from this conversation";
  heading.append(title, description);

  const options = document.createElement("div");
  options.className = "vh-composer-recent-options";
  section.append(heading, options);
  list.insertBefore(section, empty);

  const promptValues = () => {
    const seen = new Set();
    const values = [];
    const messages = [...feed.querySelectorAll(".vh-chat-message.is-user")].reverse();
    for (const message of messages) {
      const copy = message.querySelector(".vh-message-copy")?.textContent?.trim() || "";
      const normalized = copy.replace(/\s+/g, " ").trim();
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      values.push(copy.slice(0, maximumValueLength));
      if (values.length >= maximumPrompts) break;
    }
    return values;
  };

  const shortLabel = (value) => {
    const normalized = String(value || "").replace(/\s+/g, " ").trim();
    if (normalized.length <= 72) return normalized;
    return `${normalized.slice(0, 69).trimEnd()}…`;
  };

  const render = () => {
    renderScheduled = false;
    const values = promptValues();
    options.replaceChildren();
    values.forEach((value, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vh-composer-prompt-option vh-composer-recent-option";
      button.dataset.promptValue = value;
      button.dataset.promptSearch = "recent previous history";
      button.setAttribute("aria-label", `Reuse recent prompt ${index + 1}: ${shortLabel(value)}`);
      const label = document.createElement("strong");
      label.textContent = shortLabel(value);
      const meta = document.createElement("small");
      meta.textContent = index === 0 ? "Most recent" : `${index + 1} prompts ago`;
      button.append(label, meta);
      options.append(button);
    });
    section.hidden = values.length === 0;
  };

  const scheduleRender = () => {
    if (renderScheduled) return;
    renderScheduled = true;
    window.requestAnimationFrame(render);
  };

  new MutationObserver(scheduleRender).observe(feed, {
    childList: true,
    subtree: true,
    characterData: true,
  });

  render();
  window.VulnHunterRecentPrompts = Object.freeze({ refresh: render });
})();