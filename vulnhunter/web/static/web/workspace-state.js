(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const dataElement = document.getElementById("vh-conversation-data");
  const inspector = document.querySelector("[data-analysis-inspector]");
  if (!workspace || !dataElement || !inspector) return;

  let initial = {};
  try {
    initial = JSON.parse(dataElement.textContent || "{}");
  } catch (_error) {
    initial = {};
  }

  const feed = workspace.querySelector("[data-conversation-feed]");
  const mobileSummary = workspace.querySelector("[data-mobile-status-copy]");
  const stateAuthorization = workspace.querySelector("[data-state-authorization]");
  const stateScope = workspace.querySelector("[data-state-scope]");
  const stateApproval = workspace.querySelector("[data-state-approval]");
  const stateActive = workspace.querySelector("[data-state-active]");
  const closeButton = inspector.querySelector("[data-analysis-inspector-close]");
  const tabs = Array.from(inspector.querySelectorAll("[data-inspector-tab]"));
  const panels = Array.from(inspector.querySelectorAll("[data-inspector-panel]"));
  let opener = null;

  const text = (value) => (value === null || value === undefined ? "" : String(value));
  const pretty = (value) =>
    text(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

  const setText = (selector, value, fallback = "Not available") => {
    const node = inspector.querySelector(selector);
    if (node) node.textContent = text(value).trim() || fallback;
  };

  const currentCard = () => feed?.querySelector("[data-run-card]") || null;

  const runFromDom = () => {
    const card = currentCard();
    if (!card) return initial.active_run || null;
    const findings = Array.from(card.querySelectorAll(".vh-finding-row"));
    const artifacts = Array.from(card.querySelectorAll(".vh-evidence-row"));
    const events = Array.from(card.querySelectorAll("[data-event-list] li"));
    return {
      run_id: card.dataset.runId || "",
      target: card.querySelector("[data-run-target]")?.textContent || "",
      state: card.querySelector("[data-run-state]")?.textContent || "",
      profile: card.querySelector("[data-run-profile]")?.textContent || "",
      scanner: card.querySelector("[data-run-scanner]")?.textContent || "",
      approval_state: card.querySelector("[data-summary-approval]")?.textContent || "",
      current_step: card.querySelector("[data-run-live-copy]")?.textContent || "",
      findings,
      artifacts,
      events,
    };
  };

  const copyRows = (sourceRows, targetSelector, emptySelector) => {
    const target = inspector.querySelector(targetSelector);
    const empty = inspector.querySelector(emptySelector);
    if (!target) return;
    target.replaceChildren();
    sourceRows.forEach((source) => {
      const copy = source.cloneNode(true);
      copy.removeAttribute("id");
      target.append(copy);
    });
    if (empty) empty.hidden = sourceRows.length > 0;
  };

  const populateTimeline = (run) => {
    const target = inspector.querySelector("[data-inspector-events]");
    if (!target) return;
    target.replaceChildren();
    const events = Array.isArray(run?.events) ? run.events : [];
    events.slice(-8).forEach((source) => {
      const item = document.createElement("li");
      item.className = "vh-inspector-event";
      item.textContent = source.textContent?.trim() || "Recorded assessment activity";
      target.append(item);
    });
    if (!events.length) {
      const item = document.createElement("li");
      item.className = "vh-inspector-empty";
      item.textContent = run ? "Waiting for persisted assessment activity." : "No assessment activity is selected.";
      target.append(item);
    }
  };

  const populateTools = (run) => {
    const target = inspector.querySelector("[data-inspector-tools]");
    if (!target) return;
    target.replaceChildren();
    const rows = run
      ? [
          ["Mode", /apk|mobile/i.test(text(run.scanner)) ? "APK" : "Website"],
          ["Profile", run.profile || "Not recorded"],
          ["Toolchain", run.scanner || "Not selected"],
          ["State", run.state || "Unknown"],
        ]
      : [["State", "No active assessment"]];
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "vh-inspector-tool-row";
      const small = document.createElement("small");
      small.textContent = label;
      const strong = document.createElement("strong");
      strong.textContent = pretty(value);
      row.append(small, strong);
      target.append(row);
    });
    const worker = inspector.querySelector("[data-inspector-worker]");
    if (worker) {
      worker.textContent = run
        ? "Worker readiness remains governed by the server policy and current run receipts."
        : "No worker is assigned to the current view.";
    }
  };

  const update = () => {
    const run = runFromDom();
    const target = text(run?.target).trim();
    const state = text(run?.state).trim();
    const approval = text(run?.approval_state).trim();
    const mode = /apk|mobile/i.test(text(run?.scanner)) ? "APK" : "Website";

    if (stateAuthorization) stateAuthorization.textContent = run ? "Bound to authorised run" : "Not selected";
    if (stateScope) stateScope.textContent = target || "No target selected";
    if (stateApproval) stateApproval.textContent = run ? pretty(approval || "not required") : "Not required";
    if (stateActive) stateActive.textContent = run ? pretty(state || "preparing") : "Idle";
    if (mobileSummary) {
      mobileSummary.textContent = run
        ? `${pretty(state || "preparing")} · ${target || "assessment"}`
        : "Ready for an authorised target";
    }

    setText("[data-inspector-state]", run ? pretty(state || "preparing") : "Ready");
    setText(
      "[data-inspector-stage]",
      run?.current_step || (run ? "Waiting for the next authoritative run receipt." : "Select or start an assessment to view authoritative details."),
    );
    setText("[data-inspector-target]", target || "No active assessment");
    setText("[data-inspector-run-id]", run?.run_id || "Pending");
    setText("[data-inspector-mode]", run ? mode : "Website or APK");
    setText("[data-inspector-scope]", target || "Waiting for an authorised target or validated APK");

    const progress = inspector.querySelector("[data-inspector-progress-value]");
    if (progress) {
      progress.textContent = "—";
      progress.setAttribute("aria-label", "A genuine numeric progress value is unavailable");
    }

    populateTools(run);
    populateTimeline(run);
    copyRows(run?.findings || [], "[data-inspector-findings]", "[data-inspector-empty-findings]");
    copyRows(run?.artifacts || [], "[data-inspector-artifacts]", "[data-inspector-empty-artifacts]");

    const findingCount = inspector.querySelector("[data-inspector-findings-count]");
    const artifactCount = inspector.querySelector("[data-inspector-artifacts-count]");
    const graphCount = inspector.querySelector("[data-inspector-graph-count]");
    if (findingCount) findingCount.textContent = String(run?.findings?.length || 0);
    if (artifactCount) artifactCount.textContent = String(run?.artifacts?.length || 0);
    if (graphCount) graphCount.textContent = "0";
  };

  const selectTab = (name) => {
    tabs.forEach((tab) => {
      const selected = tab.dataset.inspectorTab === name;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.inspectorPanel !== name;
    });
  };

  const openInspector = (source, tab = "overview") => {
    opener = source || document.activeElement;
    update();
    selectTab(tab);
    inspector.hidden = false;
    inspector.classList.add("is-open");
    closeButton?.focus({ preventScroll: true });
  };

  const closeInspector = () => {
    if (window.matchMedia("(min-width: 1280px)").matches) return;
    inspector.hidden = true;
    inspector.classList.remove("is-open");
    if (opener instanceof HTMLElement) opener.focus({ preventScroll: true });
  };

  document.querySelectorAll("[data-analysis-inspector-open]").forEach((button) => {
    button.addEventListener("click", () => openInspector(button));
  });
  closeButton?.addEventListener("click", closeInspector);

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab.dataset.inspectorTab || "overview"));
    tab.addEventListener("keydown", (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      tabs[next].focus();
      selectTab(tabs[next].dataset.inspectorTab || "overview");
    });
  });

  document.querySelectorAll("[data-mobile-workspace-view]").forEach((button) => {
    if (button === workspace) return;
    button.addEventListener("click", () => {
      const view = button.dataset.mobileWorkspaceView || "chat";
      if (view === "chat") {
        closeInspector();
        return;
      }
      openInspector(button, view === "analysis" ? "overview" : view === "findings" ? "findings" : "graph");
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !inspector.hidden) closeInspector();
  });

  if (feed) {
    const observer = new MutationObserver(update);
    observer.observe(feed, { childList: true, subtree: true, characterData: true, attributes: true });
  }

  update();
})();
