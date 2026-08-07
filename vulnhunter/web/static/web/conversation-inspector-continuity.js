(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const inspector = workspace?.querySelector("[data-analysis-inspector]");
  const feed = workspace?.querySelector("[data-conversation-feed]");
  const analysisButton = workspace?.querySelector('[data-mobile-workspace-view="analysis"]');
  if (!workspace || !inspector || !feed || !analysisButton) return;

  const tabs = new Map(
    [...inspector.querySelectorAll("[data-inspector-tab]")]
      .map((tab) => [tab.dataset.inspectorTab, tab])
      .filter(([name]) => Boolean(name)),
  );
  const tabAliases = Object.freeze({
    summary: "overview",
    overview: "overview",
    activity: "activity",
    finding: "findings",
    findings: "findings",
    evidence: "artifacts",
    artifact: "artifacts",
    artifacts: "artifacts",
    report: "reports",
    reports: "reports",
  });
  const readingState = {
    feedScrollTop: null,
    returnFocus: null,
  };

  const selectedAssessmentId = () => {
    const snapshot = window.vhSelectedAssessmentStore?.getSnapshot?.();
    return String(snapshot?.assessment_projection?.assessment_id || "").trim();
  };

  const resolveTab = (requested) => {
    const canonical = tabAliases[String(requested || "overview").toLowerCase()] || "overview";
    return tabs.has(canonical) ? canonical : "overview";
  };

  const rememberReadingPosition = (trigger) => {
    if (!inspector.hidden || readingState.feedScrollTop !== null) return;
    readingState.feedScrollTop = feed.scrollTop;
    readingState.returnFocus = trigger instanceof HTMLElement ? trigger : document.activeElement;
  };

  const restoreReadingPosition = () => {
    const scrollTop = readingState.feedScrollTop;
    const returnFocus = readingState.returnFocus;
    readingState.feedScrollTop = null;
    readingState.returnFocus = null;
    if (scrollTop === null) return;

    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        feed.scrollTop = scrollTop;
        if (returnFocus instanceof HTMLElement && returnFocus.isConnected) {
          returnFocus.focus({ preventScroll: true });
        }
      });
    });
  };

  const openInspector = ({ tab = "overview", trigger = null } = {}) => {
    if (!selectedAssessmentId()) return false;
    rememberReadingPosition(trigger);
    const target = resolveTab(tab);
    analysisButton.click();
    window.queueMicrotask(() => tabs.get(target)?.click());
    return true;
  };

  workspace.addEventListener("click", (event) => {
    const trigger = event.target instanceof Element
      ? event.target.closest("[data-analysis-inspector-open]")
      : null;
    if (!(trigger instanceof HTMLElement)) return;
    const requestedTab = trigger.dataset.inspectorContext || trigger.dataset.inspectorTab || "overview";
    openInspector({ tab: requestedTab, trigger });
  });

  document.addEventListener("vh:open-assessment-inspector", (event) => {
    const detail = event.detail && typeof event.detail === "object" ? event.detail : {};
    openInspector({
      tab: detail.tab || detail.context || "overview",
      trigger: detail.trigger instanceof HTMLElement ? detail.trigger : null,
    });
  });

  const hiddenObserver = new MutationObserver(() => {
    if (inspector.hidden) restoreReadingPosition();
  });
  hiddenObserver.observe(inspector, { attributes: true, attributeFilter: ["hidden"] });

  window.VulnHunterInspectorContinuity = Object.freeze({
    open: openInspector,
    selectedAssessmentId,
  });
})();
