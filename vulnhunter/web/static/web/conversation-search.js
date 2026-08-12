(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-conversation-search-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(/conversation-search\.js$/, "conversation-search.css");
    styleUrl.search = "?v=20260812-ui3";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.conversationSearchStyles = "true";
    document.head.append(link);
  }
  if (current && !document.querySelector("script[data-composer-tools-loader]")) {
    const toolsUrl = new URL(current, window.location.href);
    toolsUrl.pathname = toolsUrl.pathname.replace(
      /conversation-search\.js$/,
      "conversation-composer-tools.js",
    );
    toolsUrl.search = "?v=20260812-ui3";
    const script = document.createElement("script");
    script.src = toolsUrl.toString();
    script.async = false;
    script.dataset.composerToolsLoader = "true";
    document.head.append(script);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const feed = document.querySelector("[data-conversation-feed]");
  const actionMenu = workspace?.querySelector(".vh-task-menu-popover");
  if (!workspace || !feed || !actionMenu) return;

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "vh-task-menu-action vh-conversation-search-toggle";
  toggle.dataset.conversationSearchToggle = "true";
  toggle.textContent = "Search conversation";
  toggle.setAttribute("aria-expanded", "false");
  actionMenu.prepend(toggle);

  const panel = document.createElement("section");
  panel.className = "vh-conversation-search-panel";
  panel.dataset.conversationSearchPanel = "true";
  panel.hidden = true;
  panel.innerHTML = `
    <div class="vh-conversation-search-box">
      <label class="vh-visually-hidden" for="vh-conversation-search-input">Search this conversation</label>
      <input id="vh-conversation-search-input" type="search" autocomplete="off" placeholder="Search messages, findings and task activity" data-conversation-search-input>
      <span data-conversation-search-status aria-live="polite">Type to search this workspace</span>
      <button type="button" data-conversation-search-close aria-label="Close conversation search">×</button>
    </div>
    <div class="vh-conversation-search-results" data-conversation-search-results hidden>
      <button type="button" data-conversation-search-previous>Previous</button>
      <span data-conversation-search-position>0 of 0</span>
      <button type="button" data-conversation-search-next>Next</button>
      <button type="button" data-conversation-search-clear>Clear</button>
    </div>
  `;
  workspace.append(panel);

  const input = panel.querySelector("[data-conversation-search-input]");
  const close = panel.querySelector("[data-conversation-search-close]");
  const results = panel.querySelector("[data-conversation-search-results]");
  const previous = panel.querySelector("[data-conversation-search-previous]");
  const next = panel.querySelector("[data-conversation-search-next]");
  const clear = panel.querySelector("[data-conversation-search-clear]");
  const position = panel.querySelector("[data-conversation-search-position]");
  const status = panel.querySelector("[data-conversation-search-status]");

  let matches = [];
  let activeIndex = -1;

  function searchableBlocks() {
    return [
      ...feed.querySelectorAll(
        ".vh-chat-message .vh-message-copy, .vh-run-card [data-run-target], .vh-run-card [data-run-live-copy], .vh-run-card [data-summary-body], .vh-run-card [data-findings-list], .vh-run-card [data-evidence-list], .vh-run-card [data-verification-body], .vh-run-card [data-guidance-body], .vh-run-card [data-technical-body]",
      ),
    ];
  }

  function clearMarkers() {
    feed
      .querySelectorAll("mark[data-vh-search-match]")
      .forEach((marker) => marker.replaceWith(document.createTextNode(marker.textContent || "")));
    feed
      .querySelectorAll(".is-vh-search-active")
      .forEach((node) => node.classList.remove("is-vh-search-active"));
    matches = [];
    activeIndex = -1;
    if (position) position.textContent = "0 of 0";
  }

  function activate(index) {
    if (!matches.length) return;
    matches.forEach((match) => match.classList.remove("is-vh-search-active"));
    activeIndex = (index + matches.length) % matches.length;
    const match = matches[activeIndex];
    match.classList.add("is-vh-search-active");
    match.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "center",
    });
    if (position) position.textContent = `${activeIndex + 1} of ${matches.length}`;
  }

  function markMatches(query) {
    clearMarkers();
    const needle = String(query || "").trim();
    if (!needle) {
      if (status) status.textContent = "Type to search this workspace";
      if (results) results.hidden = true;
      return;
    }
    const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const expression = new RegExp(`(${escaped})`, "gi");
    searchableBlocks().forEach((node) => {
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, {
        acceptNode(textNode) {
          const value = String(textNode.nodeValue || "");
          if (!value.toLocaleLowerCase().includes(needle.toLocaleLowerCase())) {
            return NodeFilter.FILTER_REJECT;
          }
          if (textNode.parentElement?.closest("mark[data-vh-search-match]")) {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        },
      });
      const textNodes = [];
      while (walker.nextNode()) textNodes.push(walker.currentNode);
      textNodes.forEach((textNode) => {
        const value = String(textNode.nodeValue || "");
        const fragment = document.createDocumentFragment();
        let lastIndex = 0;
        value.replace(expression, (match, _group, offset) => {
          fragment.append(document.createTextNode(value.slice(lastIndex, offset)));
          const mark = document.createElement("mark");
          mark.dataset.vhSearchMatch = "true";
          mark.textContent = match;
          fragment.append(mark);
          matches.push(mark);
          lastIndex = offset + match.length;
          return match;
        });
        fragment.append(document.createTextNode(value.slice(lastIndex)));
        textNode.replaceWith(fragment);
      });
    });
    if (status) {
      status.textContent = matches.length
        ? `${matches.length} result${matches.length === 1 ? "" : "s"}`
        : "No matches";
    }
    if (results) results.hidden = matches.length === 0;
    if (matches.length) activate(0);
  }

  function overflowSummary() {
    return toggle.closest("details")?.querySelector("summary") || null;
  }

  function restoreMenuFocus() {
    const summary = overflowSummary();
    if (summary instanceof HTMLElement) summary.focus({ preventScroll: true });
    else toggle.focus({ preventScroll: true });
  }

  function openPanel() {
    panel.hidden = false;
    toggle.setAttribute("aria-expanded", "true");
    toggle.closest("details")?.removeAttribute("open");
    window.requestAnimationFrame(() => input?.focus());
  }

  function closePanel({ restoreFocus = true } = {}) {
    panel.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    clearMarkers();
    if (input) input.value = "";
    if (restoreFocus) restoreMenuFocus();
  }

  toggle.addEventListener("click", openPanel);
  close?.addEventListener("click", () => closePanel());
  input?.addEventListener("input", () => markMatches(input.value));
  next?.addEventListener("click", () => activate(activeIndex + 1));
  previous?.addEventListener("click", () => activate(activeIndex - 1));
  clear?.addEventListener("click", () => {
    if (input) input.value = "";
    clearMarkers();
    if (status) status.textContent = "Type to search this workspace";
    if (results) results.hidden = true;
    input?.focus();
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "f") {
      if (!workspace.contains(document.activeElement) && !workspace.matches(":hover")) return;
      event.preventDefault();
      if (panel.hidden) openPanel();
      else input?.focus();
    }
    if (event.key === "Escape" && !panel.hidden) {
      event.preventDefault();
      closePanel();
    }
  });

  window.VulnHunterConversationSearch = Object.freeze({
    open: openPanel,
    close: closePanel,
  });
})();
