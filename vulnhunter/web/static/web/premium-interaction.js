(() => {
  "use strict";

  const root = document.documentElement;
  const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const overlayStack = [];
  const overlayConfigs = new WeakMap();
  let overlaySequence = 0;

  const applyMotionPreference = () => {
    const motion = motionQuery.matches ? "reduced" : "full";
    if (root.dataset.motion === motion) return;
    root.dataset.motion = motion;
    window.dispatchEvent(
      new CustomEvent("vh:motion-preference-change", {
        detail: Object.freeze({ motion }),
      }),
    );
  };

  const topOverlay = () => overlayStack.at(-1) || null;

  const updateOverlayState = () => {
    const open = overlayStack.some((dialog) => dialog.open);
    document.body?.classList.toggle("vh-overlay-open", open);
    root.dataset.overlayCount = String(overlayStack.filter((dialog) => dialog.open).length);
  };

  const restoreFocus = (config) => {
    const target = config?.returnFocus;
    if (!(target instanceof HTMLElement) || !target.isConnected) return;
    window.requestAnimationFrame(() => target.focus({ preventScroll: true }));
  };

  const removeFromStack = (dialog) => {
    const index = overlayStack.lastIndexOf(dialog);
    if (index >= 0) overlayStack.splice(index, 1);
  };

  const closeDirect = (dialog, returnValue = "") => {
    const config = overlayConfigs.get(dialog);
    if (config) config.closingFromHistory = true;
    if (dialog.open) dialog.close(returnValue);
  };

  const requestClose = (dialog, reason = "programmatic", returnValue = "") => {
    if (!(dialog instanceof HTMLDialogElement) || !dialog.open) return false;
    const config = overlayConfigs.get(dialog);
    if (!config) {
      dialog.close(returnValue);
      return true;
    }
    if (reason !== "programmatic" && config.dismissible === false) return false;
    if (config.historyKey && window.history.state?.vhOverlay === config.historyKey) {
      config.pendingReturnValue = returnValue;
      window.history.back();
      return true;
    }
    closeDirect(dialog, returnValue);
    return true;
  };

  const registerOverlay = (dialog, options = {}) => {
    if (!(dialog instanceof HTMLDialogElement)) return null;
    const existing = overlayConfigs.get(dialog);
    if (existing) {
      Object.assign(existing, options);
      return existing;
    }

    const config = {
      backdropClose: false,
      dismissible: true,
      history: true,
      initialFocus: null,
      returnFocus: null,
      historyKey: null,
      closingFromHistory: false,
      pendingReturnValue: "",
      ...options,
    };
    overlayConfigs.set(dialog, config);

    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      requestClose(dialog, "escape");
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog && config.backdropClose) {
        requestClose(dialog, "backdrop");
      }
    });
    dialog.addEventListener("close", () => {
      const shouldPopHistory =
        config.historyKey &&
        !config.closingFromHistory &&
        window.history.state?.vhOverlay === config.historyKey;
      removeFromStack(dialog);
      updateOverlayState();
      restoreFocus(config);
      const detail = Object.freeze({ dialog, returnValue: dialog.returnValue || "" });
      window.dispatchEvent(new CustomEvent("vh:overlay-close", { detail }));
      config.historyKey = null;
      config.closingFromHistory = false;
      config.pendingReturnValue = "";
      if (shouldPopHistory) window.history.back();
    });
    return config;
  };

  const openOverlay = (dialog, options = {}) => {
    if (!(dialog instanceof HTMLDialogElement) || dialog.open) return false;
    const config = registerOverlay(dialog, options);
    Object.assign(config, options);
    config.returnFocus = options.trigger instanceof HTMLElement ? options.trigger : document.activeElement;
    config.closingFromHistory = false;
    config.pendingReturnValue = "";

    dialog.showModal();
    removeFromStack(dialog);
    overlayStack.push(dialog);
    if (config.history !== false) {
      overlaySequence += 1;
      config.historyKey = `vh-overlay-${overlaySequence}`;
      const currentState =
        window.history.state && typeof window.history.state === "object" ? window.history.state : {};
      window.history.pushState({ ...currentState, vhOverlay: config.historyKey }, "", window.location.href);
    }
    updateOverlayState();

    const initialFocus =
      options.initialFocus instanceof HTMLElement
        ? options.initialFocus
        : dialog.querySelector("[autofocus], input, textarea, select, button, a[href], [tabindex]:not([tabindex='-1'])");
    window.requestAnimationFrame(() => initialFocus?.focus({ preventScroll: true }));
    window.dispatchEvent(
      new CustomEvent("vh:overlay-open", {
        detail: Object.freeze({ dialog }),
      }),
    );
    return true;
  };

  window.addEventListener("popstate", () => {
    const dialog = topOverlay();
    if (!(dialog instanceof HTMLDialogElement) || !dialog.open) return;
    const config = overlayConfigs.get(dialog);
    if (!config?.historyKey) return;
    closeDirect(dialog, config.pendingReturnValue || "");
  });

  applyMotionPreference();
  motionQuery.addEventListener("change", applyMotionPreference);

  window.VulnHunterInteraction = Object.freeze({
    motion: Object.freeze({
      reduced: () => motionQuery.matches,
    }),
    overlays: Object.freeze({
      register: registerOverlay,
      open: openOverlay,
      close: requestClose,
      top: topOverlay,
    }),
  });
  window.dispatchEvent(new CustomEvent("vh:interaction-ready"));
})();
