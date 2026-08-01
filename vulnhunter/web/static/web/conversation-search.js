(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-conversation-search-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-search\.js$/,
      "conversation-search.css",
    );
    styleUrl.search = "?v=20260801-search1";
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
    toolsUrl.search = "?v=20260801-composer-tools1";
    const script = document.createElement("script");
    script.src = toolsUrl.toString();
    script.async = false;
    script.dataset.composerToolsLoader = "true";
    document.head.append(script);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const headerActions = document.querySelector(".vh-chat-runtime");
  const feed = document.querySelector("[data-conversation-feed]");
  if (!workspace || !headerActions || !feed) return;

  const state = {
    matches: [],
    activeIndex: -1,
    query: "",
  };

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "vh-chat-history-toggle vh-conversation-search-trigger";
  trigger.dataset.conversationSearchTrigger = "true";
  trigger.textContent = "Search";
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("aria-controls", "vh-conversation-search");
  trigger.title = "Search this conversation (Ctrl or Command + F)";
  headerActions.insertBefore(trigger, headerActions.querySelector("[data-history-toggle]"));

  const panel = document.createElement("section");
  panel.id = "vh-conversation-search";
  panel.className = "vh-conversation-search";
  panel.dataset.conversationSearch = "true";
  panel.hidden = true;
  panel.setAttribute("aria-label", "Search this conversation");
  panel.innerHTML = `
    <label>
      <span class="vh-visually-hidden">Search conversation</span>
      <input type="search" autocomplete="off" spellcheck="false" placeholder="Search prompts, answers, findings, or code" data-conversation-search-input>
    </label>
    <output data-conversation-search-count>0 results</output>
    <div class="vh-conversation-search-actions">
      <button type="button" data-conversation-search-previous aria-label="Previous search result">↑</button>
      <button type="button" data-conversation-search-next aria-label="Next search result">↓</button>
      <button type="button" data-conversation-search-close aria-label="Close conversation search">×</button>
    </div>
  `;
  workspace.append(panel);

  const input = panel.querySelector("[data-conversation-search-input]");
  const count = panel.querySelector("[data-conversation-search-count]");
  const previous = panel.querySelector("[data-conversation-search-previous]");
  const next = panel.querySelector("[data-conversation-search-next]");
  const close = panel.querySelector("[data-conversation-search-close]");

  const candidateMessages = () =>
    [...feed.querySelectorAll(".vh-chat-message")].filter(
      (message) => !message.classList.contains("is-local-notice"),
    );

  const clearHighlights = () => {
    feed.querySelectorAll(".is-search-match, .is-search-active").forEach((message) => {
      message.classList.remove("is-search-match", "is-search-active");
      message.removeAttribute("aria-current");
    });
  };

  const updateCount = () => {
    if (!state.query) {
      count.textContent = "0 results";
    } else if (!state.matches.length) {
      count.textContent = "No results";
    } else {
      count.textContent = `${state.activeIndex + 1} of ${state.matches.length}`;
    }
    const disabled = state.matches.length < 2;
    previous.disabled = disabled;
    next.disabled = disabled;
  };

  const activate = (index, { behavior = "smooth" } = {}) => {
    if (!state.matches.length) {
      state.activeIndex = -1;
      updateCount();
      return;
    }
    const normalized = ((index % state.matches.length) + state.matches.length) % state.matches.length;
    state.matches.forEach((message, candidateIndex) => {
      const active = candidateIndex === normalized;
      message.classList.toggle("is-search-active", active);
      if (active) message.setAttribute("aria-current", "true");
      else message.removeAttribute("aria-current");
    });
    state.activeIndex = normalized;
    updateCount();
    state.matches[normalized].scrollIntoView({ behavior, block: "center" });
  };

  const search = ({ preserveIndex = false } = {}) => {
    const query = input.value.trim().toLocaleLowerCase();
    const previousActive = preserveIndex ? state.matches[state.activeIndex] : null;
    clearHighlights();
    state.query = query;
    state.matches = [];
    state.activeIndex = -1;
    if (!query) {
      updateCount();
      return;
    }
    state.matches = candidateMessages().filter((message) =>
      String(message.textContent || "").toLocaleLowerCase().includes(query),
    );
    state.matches.forEach((message) => message.classList.add("is-search-match"));
    if (!state.matches.length) {
      updateCount();
      return;
    }
    const preserved = previousActive ? state.matches.indexOf(previousActive) : -1;
    activate(preserved >= 0 ? preserved : 0, { behavior: preserveIndex ? "auto" : "smooth" });
  };

  const open = ({ select = false } = {}) => {
    panel.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    window.requestAnimationFrame(() => {
      input.focus();
      if (select) input.select();
    });
  };

  const closePanel = () => {
    panel.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    clearHighlights();
    state.matches = [];
    state.activeIndex = -1;
    trigger.focus();
  };

  trigger.addEventListener("click", () => {
    if (panel.hidden) open({ select: true });
    else closePanel();
  });
  close.addEventListener("click", closePanel);
  previous.addEventListener("click", () => activate(state.activeIndex - 1));
  next.addEventListener("click", () => activate(state.activeIndex + 1));
  input.addEventListener("input", () => search());
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      activate(state.activeIndex + (event.shiftKey ? -1 : 1));
    } else if (event.key === "Escape") {
      event.preventDefault();
      closePanel();
    }
  });

  document.addEventListener("keydown", (event) => {
    const findShortcut = (event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === "f";
    if (findShortcut) {
      event.preventDefault();
      open({ select: true });
      return;
    }
    if (event.key === "Escape" && !panel.hidden) {
      event.preventDefault();
      closePanel();
    }
  });

  new MutationObserver(() => {
    if (!panel.hidden && state.query) search({ preserveIndex: true });
  }).observe(feed, { childList: true, characterData: true, subtree: true });

  window.VulnHunterConversationSearch = Object.freeze({
    open,
    close: closePanel,
    search: (value) => {
      input.value = String(value || "");
      open();
      search();
    },
  });
})();