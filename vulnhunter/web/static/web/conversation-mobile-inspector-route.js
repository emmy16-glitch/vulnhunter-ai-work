(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const inspector = workspace?.querySelector("[data-analysis-inspector]");
  if (!workspace || !inspector) return;

  const analysisButton = workspace.querySelector('[data-mobile-workspace-view="analysis"]');
  const chatButton = workspace.querySelector('[data-mobile-workspace-view="chat"]');
  const closeButton = inspector.querySelector("[data-analysis-inspector-close]");
  const tabs = [...inspector.querySelectorAll("[data-inspector-tab]")];
  const allowedTabs = new Set(tabs.map((tab) => tab.dataset.inspectorTab).filter(Boolean));
  const routeKeys = ["assessment", "inspector"];
  let selectedAssessmentId = "";
  let restoringRoute = false;
  let unsubscribe = null;

  const isMobile = () => window.matchMedia("(max-width: 767px)").matches;
  const route = () => {
    const url = new URL(window.location.href);
    return {
      assessmentId: url.searchParams.get("assessment") || "",
      tab: url.searchParams.get("inspector") || "",
    };
  };

  const writeRoute = ({ assessmentId = "", tab = "" } = {}) => {
    const url = new URL(window.location.href);
    routeKeys.forEach((key) => url.searchParams.delete(key));
    if (assessmentId && allowedTabs.has(tab)) {
      url.searchParams.set("assessment", assessmentId);
      url.searchParams.set("inspector", tab);
    }
    window.history.replaceState(window.history.state, "", url);
  };

  const activeTab = () =>
    tabs.find((tab) => tab.getAttribute("aria-selected") === "true")?.dataset.inspectorTab ||
    "overview";

  const clearRoute = () => {
    if (restoringRoute) return;
    const current = route();
    if (current.assessmentId || current.tab) writeRoute();
  };

  const publishCurrentRoute = () => {
    if (restoringRoute || !isMobile() || inspector.hidden || !selectedAssessmentId) return;
    writeRoute({ assessmentId: selectedAssessmentId, tab: activeTab() });
  };

  const restoreRoute = () => {
    if (!isMobile()) return;
    const current = route();
    if (!current.assessmentId && !current.tab) return;
    if (
      !selectedAssessmentId ||
      current.assessmentId !== selectedAssessmentId ||
      !allowedTabs.has(current.tab)
    ) {
      writeRoute();
      return;
    }

    restoringRoute = true;
    analysisButton?.click();
    tabs.find((tab) => tab.dataset.inspectorTab === current.tab)?.click();
    restoringRoute = false;
    publishCurrentRoute();
  };

  const applySelectedAssessment = (snapshot) => {
    selectedAssessmentId = String(snapshot?.assessment_projection?.assessment_id || "").trim();
    const current = route();
    if (!selectedAssessmentId && (current.assessmentId || current.tab)) {
      writeRoute();
      return;
    }
    restoreRoute();
  };

  const bindStore = (store = window.vhSelectedAssessmentStore) => {
    if (!store || typeof store.subscribe !== "function" || unsubscribe) return;
    unsubscribe = store.subscribe(applySelectedAssessment);
    applySelectedAssessment(store.getSnapshot());
  };

  analysisButton?.addEventListener("click", () => window.queueMicrotask(publishCurrentRoute));
  chatButton?.addEventListener("click", () => window.queueMicrotask(clearRoute));
  closeButton?.addEventListener("click", () => window.queueMicrotask(clearRoute));
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => window.queueMicrotask(publishCurrentRoute));
  });

  window.addEventListener("popstate", () => window.queueMicrotask(restoreRoute));
  window.addEventListener("resize", () => {
    if (!isMobile()) clearRoute();
  });
  document.addEventListener("vh:selected-assessment-store-ready", (event) => bindStore(event.detail));

  bindStore();
})();
