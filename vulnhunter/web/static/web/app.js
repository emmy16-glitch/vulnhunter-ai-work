(() => {
  "use strict";

  const productStyles = document.querySelector('link[href*="/product.css"]');
  if (productStyles && !document.querySelector('link[href*="/product-wide.css"]')) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = productStyles.href.replace("product.css", "product-wide.css");
    document.head.append(link);
  }

  const sidebar = document.querySelector("[data-sidebar]");
  const navToggle = document.querySelector("[data-nav-toggle]");
  const navClose = document.querySelector("[data-nav-close]");

  function setNavigation(open) {
    if (!sidebar || !navToggle || !navClose) {
      return;
    }
    sidebar.classList.toggle("is-open", open);
    navToggle.setAttribute("aria-expanded", String(open));
    navToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    navClose.hidden = !open;
    document.body.classList.toggle("vh-nav-open", open);
    if (!open) {
      navToggle.focus({ preventScroll: true });
    }
  }

  navToggle?.addEventListener("click", () => {
    setNavigation(navToggle.getAttribute("aria-expanded") !== "true");
  });
  navClose?.addEventListener("click", () => setNavigation(false));

  const contextMenus = [...document.querySelectorAll(".vh-context-menu")];
  contextMenus.forEach((menu) => {
    menu.addEventListener("toggle", () => {
      if (!menu.open) return;
      contextMenus.forEach((otherMenu) => {
        if (otherMenu !== menu) otherMenu.open = false;
      });
    });
  });
  document.addEventListener("click", (event) => {
    contextMenus.forEach((menu) => {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
  });

  sidebar?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.matchMedia("(max-width: 1023px)").matches) {
        setNavigation(false);
      }
    });
  });

  const commandDialog = document.querySelector("#vh-command-dialog");
  const searchToggle = document.querySelector("[data-search-toggle]");
  const commandInput = document.querySelector("[data-command-input]");
  const commandItems = [...document.querySelectorAll("[data-command-results] li")];

  function openSearch() {
    if (!(commandDialog instanceof HTMLDialogElement)) {
      return;
    }
    commandDialog.showModal();
    searchToggle?.setAttribute("aria-expanded", "true");
    window.requestAnimationFrame(() => commandInput?.focus());
  }

  searchToggle?.addEventListener("click", openSearch);
  commandDialog?.addEventListener("close", () => {
    searchToggle?.setAttribute("aria-expanded", "false");
    commandInput.value = "";
    commandItems.forEach((item) => { item.hidden = false; });
    searchToggle?.focus({ preventScroll: true });
  });
  commandInput?.addEventListener("input", () => {
    const query = commandInput.value.trim().toLocaleLowerCase();
    commandItems.forEach((item) => {
      item.hidden = Boolean(query) && !item.textContent.toLocaleLowerCase().includes(query);
    });
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    }
    if (event.key === "Escape" && sidebar?.classList.contains("is-open")) {
      setNavigation(false);
    }
    if (event.key === "Escape") {
      contextMenus.forEach((menu) => { menu.open = false; });
    }
  });

  document.querySelectorAll("[data-ui-tabs]").forEach((root) => {
    const tabList = root.querySelector(":scope > [role='tablist']");
    const tabs = tabList ? [...tabList.querySelectorAll(":scope > [role='tab']")] : [];
    const panels = [...root.querySelectorAll(":scope > [role='tabpanel']")];

    function selectTab(tab, moveFocus = false) {
      tabs.forEach((item) => {
        const selected = item === tab;
        item.classList.toggle("is-active", selected);
        item.setAttribute("aria-selected", String(selected));
        item.tabIndex = selected ? 0 : -1;
      });
      panels.forEach((panel) => {
        panel.hidden = panel.id !== tab.dataset.tabTarget;
      });
      if (moveFocus) {
        tab.focus();
      }
    }

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => selectTab(tab));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
          return;
        }
        event.preventDefault();
        let nextIndex = index;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        if (event.key === "Home") nextIndex = 0;
        if (event.key === "End") nextIndex = tabs.length - 1;
        selectTab(tabs[nextIndex], true);
      });
    });
    if (tabs[0]) {
      selectTab(tabs.find((tab) => tab.getAttribute("aria-selected") === "true") || tabs[0]);
    }
  });

  document.querySelectorAll("[data-tab-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      const tab = document.getElementById(button.dataset.tabJump || "");
      if (!(tab instanceof HTMLElement)) return;
      tab.click();
      tab.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  });

  document.querySelectorAll("[data-attack-path]").forEach((root) => {
    const nodes = [...root.querySelectorAll("[data-attack-node]")];
    const label = root.querySelector("[data-attack-detail-label]");
    const state = root.querySelector("[data-attack-detail-state]");
    const source = root.querySelector("[data-attack-detail-source]");
    const reference = root.querySelector("[data-attack-detail-reference]");

    function selectNode(node) {
      nodes.forEach((item) => {
        const selected = item === node;
        item.classList.toggle("is-selected", selected);
        item.setAttribute("aria-pressed", String(selected));
      });
      if (label) label.textContent = node.dataset.label || "Not available";
      if (state) state.textContent = node.dataset.state || "Not available";
      if (source) source.textContent = node.dataset.source || "Persisted evidence";
      if (reference) reference.textContent = node.dataset.reference || "No reference";
    }

    nodes.forEach((node) => node.addEventListener("click", () => selectNode(node)));
    if (nodes[0]) selectNode(nodes[0]);
  });

  const approvalDialog = document.querySelector("[data-approval-dialog]");
  const approvalOpeners = [...document.querySelectorAll("[data-approval-open]")];
  const approvalCloser = document.querySelector("[data-approval-close]");

  function openApprovalDialog() {
    if (!(approvalDialog instanceof HTMLDialogElement) || approvalDialog.open) return;
    approvalDialog.showModal();
    window.requestAnimationFrame(() => {
      approvalDialog.querySelector("textarea, button, a")?.focus();
    });
  }

  approvalOpeners.forEach((button) => button.addEventListener("click", openApprovalDialog));
  approvalCloser?.addEventListener("click", () => approvalDialog?.close());
  approvalDialog?.addEventListener("click", (event) => {
    if (event.target === approvalDialog) approvalDialog.close();
  });
  approvalDialog?.addEventListener("cancel", () => {
    approvalOpeners[0]?.focus({ preventScroll: true });
  });
  if (approvalDialog?.dataset.autoOpen === "true") {
    window.requestAnimationFrame(openApprovalDialog);
  }

  const disclosureRoute = document.body.dataset.route || "page";
  const disclosures = [...document.querySelectorAll(".vh-stage-disclosure, [data-persist-disclosure]")];
  disclosures.forEach((details, index) => {
    const keyPart = details.dataset.disclosureKey || details.id || String(index);
    const storageKey = `vh-disclosure:${disclosureRoute}:${keyPart}`;
    let saved = null;
    try {
      saved = window.sessionStorage.getItem(storageKey);
    } catch (_error) {
      saved = null;
    }
    if (saved === "open") details.open = true;
    if (saved === "closed") details.open = false;
    if (saved === null && details.dataset.autoOpen === "true") details.open = true;
    details.addEventListener("toggle", () => {
      try {
        window.sessionStorage.setItem(storageKey, details.open ? "open" : "closed");
      } catch (_error) {
        // Disclosure state remains usable when session storage is unavailable.
      }
      if (!details.open || !window.matchMedia("(max-width: 767px)").matches) return;
      const group = details.closest("[data-disclosure-group], .vh-stage-list, .vh-trial-list");
      group?.querySelectorAll("details[open]").forEach((other) => {
        if (other !== details) other.open = false;
      });
    });
  });

  function formatElapsed(totalSeconds) {
    const bounded = Math.max(0, Number(totalSeconds) || 0);
    const hours = Math.floor(bounded / 3600);
    const minutes = Math.floor((bounded % 3600) / 60);
    const seconds = Math.floor(bounded % 60);
    return [hours, minutes, seconds].map((value) => String(value).padStart(2, "0")).join(":");
  }

  document.querySelectorAll("[data-operational-stream]").forEach((root) => {
    const url = root.dataset.operationalStream;
    if (!url || !("EventSource" in window)) return;
    const copy = root.querySelector("[data-operational-copy]");
    const state = document.querySelector("[data-operational-state]");
    const trial = document.querySelector("[data-operational-trial]");
    const confirmed = document.querySelector("[data-operational-confirmed]");
    const elapsed = root.querySelector("[data-operational-elapsed]");
    const log = document.querySelector("[data-live-events]");
    let lastSequence = Number(root.dataset.lastSequence || 0);
    let elapsedSeconds = 0;
    const startedAt = Date.parse(root.dataset.startedAt || "");
    if (Number.isFinite(startedAt)) {
      elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    }
    if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);

    function appendEvent(event) {
      if (!log || log.querySelector(`[data-event-sequence="${event.sequence}"]`)) return;
      log.querySelector("[data-empty-events]")?.remove();
      const line = document.createElement("div");
      line.className = "vh-log-line is-new";
      line.dataset.eventSequence = String(event.sequence);
      const prefix = document.createElement("span");
      prefix.className = "vh-log-prefix";
      prefix.textContent = `[${event.event_type}]`;
      const time = document.createElement("time");
      time.textContent = event.timestamp || "";
      const summary = document.createElement("span");
      summary.textContent = event.summary || "Recorded activity";
      const reference = document.createElement("code");
      reference.textContent = event.event_sha256 ? `${event.event_sha256.slice(0, 16)}…` : "";
      line.append(prefix, time, summary, reference);
      log.append(line);
      window.setTimeout(() => line.classList.remove("is-new"), 1200);
    }

    const source = new EventSource(`${url}?after_sequence=${lastSequence}`);
    source.addEventListener("activity", (message) => {
      let payload;
      try {
        payload = JSON.parse(message.data);
      } catch (_error) {
        return;
      }
      const events = Array.isArray(payload.events) ? payload.events : [];
      events.forEach(appendEvent);
      const latest = events.at(-1);
      if (latest?.summary && copy) copy.textContent = latest.summary;
      if (!latest?.summary && payload.active_summary && copy) copy.textContent = payload.active_summary;
      lastSequence = Math.max(lastSequence, Number(payload.last_sequence || 0));
      root.dataset.lastSequence = String(lastSequence);
      if (state && payload.run_state) state.textContent = payload.run_state;
      if (trial && payload.maximum_trials !== undefined) {
        trial.textContent = `Trial ${payload.current_trial || 0}/${payload.maximum_trials}`;
      }
      if (confirmed && payload.confirmed_trials !== undefined) {
        confirmed.textContent = String(payload.confirmed_trials);
      }
      if (payload.elapsed_seconds !== undefined) {
        elapsedSeconds = Number(payload.elapsed_seconds) || elapsedSeconds;
        if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
      }
      const terminal = Boolean(payload.terminal);
      root.classList.toggle("is-active", !terminal);
      root.classList.toggle("is-terminal", terminal);
      if (terminal) {
        source.close();
      }
    });
    source.addEventListener("error", () => {
      root.classList.add("is-reconnecting");
      window.setTimeout(() => root.classList.remove("is-reconnecting"), 1200);
    });
  });
})();
