(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const inspector = workspace?.querySelector("[data-analysis-inspector]");
  if (!workspace || !inspector) return;

  const analysisButton = workspace.querySelector('[data-mobile-workspace-view="analysis"]');
  const chatButton = workspace.querySelector('[data-mobile-workspace-view="chat"]');
  const closeButton = inspector.querySelector("[data-analysis-inspector-close]");
  const tabs = [...inspector.querySelectorAll("[data-inspector-tab]")];
  const specialistButtons = [...workspace.querySelectorAll("[data-mobile-specialist-tab]")];
  const navDestinations = [...workspace.querySelectorAll("[data-mobile-nav-destination]")];
  const allowedTabs = new Set(tabs.map((tab) => tab.dataset.inspectorTab).filter(Boolean));
  const routeKeys = ["assessment", "inspector"];
  const routeStateKey = "vhMobileInspector";
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

  const destinationForTab = (tab) => {
    if (tab === "activity") return "activity";
    if (tab === "findings") return "findings";
    return "more";
  };

  const activateNavigation = (destination) => {
    navDestinations.forEach((item) => {
      const selected = item.dataset.mobileNavDestination === destination;
      item.classList.toggle("is-active", selected);
      item.setAttribute("aria-current", selected ? "page" : "false");
    });
  };

  const writeRoute = (
    { assessmentId = "", tab = "" } = {},
    { mode = "replace" } = {},
  ) => {
    const url = new URL(window.location.href);
    routeKeys.forEach((key) => url.searchParams.delete(key));
    const hasRoute = Boolean(assessmentId && allowedTabs.has(tab));
    if (hasRoute) {
      url.searchParams.set("assessment", assessmentId);
      url.searchParams.set("inspector", tab);
    }
    if (url.href === window.location.href) return;
    const state = { ...(window.history.state || {}), [routeStateKey]: hasRoute };
    const method = mode === "push" ? "pushState" : "replaceState";
    window.history[method](state, "", url);
  };

  const activeTab = () =>
    tabs.find((tab) => tab.getAttribute("aria-selected") === "true")?.dataset.inspectorTab ||
    "overview";

  const showChatWithoutPublishing = () => {
    if (!inspector.hidden) {
      restoringRoute = true;
      chatButton?.click();
      restoringRoute = false;
    }
    activateNavigation("chat");
  };

  const clearRoute = () => {
    activateNavigation("chat");
    if (restoringRoute) return;
    const current = route();
    if (!current.assessmentId && !current.tab) return;
    if (window.history.state?.[routeStateKey] === true) {
      window.history.back();
      return;
    }
    writeRoute();
  };

  const publishCurrentRoute = () => {
    if (restoringRoute || !isMobile() || inspector.hidden || !selectedAssessmentId) return;
    const tab = activeTab();
    activateNavigation(destinationForTab(tab));
    const next = { assessmentId: selectedAssessmentId, tab };
    const current = route();
    if (current.assessmentId === next.assessmentId && current.tab === next.tab) return;
    writeRoute(next, { mode: "push" });
  };

  const openSpecialist = (tab) => {
    if (!allowedTabs.has(tab) || !selectedAssessmentId) return;
    restoringRoute = true;
    analysisButton?.click();
    tabs.find((item) => item.dataset.inspectorTab === tab)?.click();
    restoringRoute = false;
    activateNavigation(destinationForTab(tab));
    publishCurrentRoute();
  };

  const restoreRoute = () => {
    if (!isMobile()) return;
    const current = route();
    if (!current.assessmentId && !current.tab) {
      showChatWithoutPublishing();
      return;
    }
    if (
      !selectedAssessmentId ||
      current.assessmentId !== selectedAssessmentId ||
      !allowedTabs.has(current.tab)
    ) {
      writeRoute();
      showChatWithoutPublishing();
      return;
    }

    restoringRoute = true;
    analysisButton?.click();
    tabs.find((tab) => tab.dataset.inspectorTab === current.tab)?.click();
    restoringRoute = false;
    activateNavigation(destinationForTab(current.tab));
  };

  const applySelectedAssessment = (snapshot) => {
    selectedAssessmentId = String(snapshot?.assessment_projection?.assessment_id || "").trim();
    const current = route();
    if (!selectedAssessmentId && (current.assessmentId || current.tab)) {
      writeRoute();
      showChatWithoutPublishing();
      return;
    }
    restoreRoute();
  };

  const bindStore = (store = window.vhSelectedAssessmentStore) => {
    if (!store || typeof store.subscribe !== "function" || unsubscribe) return;
    unsubscribe = store.subscribe(applySelectedAssessment);
    applySelectedAssessment(store.getSnapshot());
  };

  analysisButton?.addEventListener("click", () => {
    if (restoringRoute) return;
    const requestedTab = analysisButton.dataset.mobileSpecialistTab || "activity";
    window.queueMicrotask(() => {
      tabs.find((tab) => tab.dataset.inspectorTab === requestedTab)?.click();
      activateNavigation(destinationForTab(requestedTab));
      publishCurrentRoute();
    });
  });
  chatButton?.addEventListener("click", () => window.queueMicrotask(clearRoute));
  closeButton?.addEventListener("click", () => window.queueMicrotask(clearRoute));
  specialistButtons
    .filter((button) => button !== analysisButton)
    .forEach((button) => {
      button.addEventListener("click", () => openSpecialist(button.dataset.mobileSpecialistTab || "overview"));
    });
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => window.queueMicrotask(publishCurrentRoute));
  });

  window.addEventListener("popstate", () => window.queueMicrotask(restoreRoute));
  window.addEventListener("resize", () => {
    if (!isMobile()) {
      writeRoute();
      showChatWithoutPublishing();
    }
  });
  document.addEventListener("vh:selected-assessment-store-ready", (event) => bindStore(event.detail));

  activateNavigation("chat");
  bindStore();
})();
