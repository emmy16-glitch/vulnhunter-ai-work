(() => {
  "use strict";

  const root = document.documentElement;
  const query = window.matchMedia("(prefers-reduced-motion: reduce)");
  const overlayStack = [];
  const overlayConfigs = new WeakMap();
  const shellNavigationStorageKey = "vh:shell-navigation";
  let overlaySequence = 0;

  const applyMotionPreference = () => {
    const motion = query.matches ? "reduced" : "full";
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

  const currentLocationKey = () => `${window.location.pathname}${window.location.search}`;

  const readShellNavigation = () => {
    try {
      const raw = window.sessionStorage.getItem(shellNavigationStorageKey);
      if (!raw) return null;
      const value = JSON.parse(raw);
      if (!value || typeof value !== "object" || typeof value.destination !== "string") return null;
      return value;
    } catch (_error) {
      return null;
    }
  };

  const clearShellNavigation = () => {
    try {
      window.sessionStorage.removeItem(shellNavigationStorageKey);
    } catch (_error) {
      // Navigation remains functional when session storage is unavailable.
    }
    root.dataset.shellNavigation = "ready";
    document.querySelectorAll("[data-shell-navigation-pending]").forEach((link) => {
      link.removeAttribute("data-shell-navigation-pending");
      link.removeAttribute("aria-busy");
    });
  };

  const writeShellNavigation = (navigation) => {
    try {
      window.sessionStorage.setItem(shellNavigationStorageKey, JSON.stringify(navigation));
    } catch (_error) {
      // Immediate visual acknowledgement still works without persisted continuity.
    }
  };

  const isShellNavigationLink = (link) => {
    if (!(link instanceof HTMLAnchorElement)) return false;
    if (!link.matches(".vh-brand, [data-sidebar] a, .vh-topbar a")) return false;
    if (link.target && link.target !== "_self") return false;
    if (link.hasAttribute("download")) return false;
    const destination = new URL(link.href, window.location.href);
    if (destination.origin !== window.location.origin) return false;
    if (destination.pathname === window.location.pathname && destination.search === window.location.search) {
      return destination.hash !== window.location.hash;
    }
    return true;
  };

  const acknowledgeShellNavigation = (link, input) => {
    if (!isShellNavigationLink(link)) return;
    const destination = new URL(link.href, window.location.href);
    const destinationKey = `${destination.pathname}${destination.search}`;
    writeShellNavigation({
      destination: destinationKey,
      input,
      sourceRoute: document.body?.dataset.route || "page",
    });
    root.dataset.shellNavigation = "pending";
    link.setAttribute("data-shell-navigation-pending", "true");
    link.setAttribute("aria-busy", "true");
    window.dispatchEvent(
      new CustomEvent("vh:shell-navigation-start", {
        detail: Object.freeze({ destination: destinationKey }),
      }),
    );
  };

  const restoreShellNavigation = () => {
    const navigation = readShellNavigation();
    clearShellNavigation();
    if (!navigation || navigation.destination !== currentLocationKey()) return;
    window.dispatchEvent(
      new CustomEvent("vh:shell-navigation-ready", {
        detail: Object.freeze({ destination: navigation.destination }),
      }),
    );
    if (navigation.input !== "keyboard") return;
    const main = document.querySelector("#main-content");
    if (!(main instanceof HTMLElement)) return;
    window.requestAnimationFrame(() => main.focus({ preventScroll: true }));
  };

  const loginForm = document.querySelector("[data-login-form]");
  const loginSubmit = loginForm?.querySelector("[data-login-submit]");
  const loginSubmitLabel = loginSubmit?.querySelector("[data-login-submit-label]");

  const restoreLoginSubmit = () => {
    if (!(loginSubmit instanceof HTMLButtonElement)) return;
    loginSubmit.disabled = false;
    loginSubmit.removeAttribute("aria-busy");
    loginSubmit.dataset.interactionState = "idle";
    if (loginSubmitLabel) {
      loginSubmitLabel.textContent = loginSubmit.dataset.idleLabel || "Sign in securely";
    }
  };

  loginForm?.addEventListener("submit", (event) => {
    if (!(loginSubmit instanceof HTMLButtonElement)) return;
    if (loginSubmit.getAttribute("aria-busy") === "true") {
      event.preventDefault();
      return;
    }
    loginSubmit.setAttribute("aria-busy", "true");
    loginSubmit.dataset.interactionState = "loading";
    loginSubmit.disabled = true;
    if (loginSubmitLabel) loginSubmitLabel.textContent = "Signing in…";
  });

  const loginError = document.querySelector("[data-login-error]");
  if (loginError instanceof HTMLElement) {
    window.requestAnimationFrame(() => loginError.focus({ preventScroll: true }));
  }

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    const link = event.target instanceof Element ? event.target.closest("a") : null;
    acknowledgeShellNavigation(link, event.detail === 0 ? "keyboard" : "pointer");
  });

  window.addEventListener("pageshow", restoreShellNavigation);
  window.addEventListener("pageshow", restoreLoginSubmit);

  window.addEventListener("popstate", () => {
    const dialog = topOverlay();
    if (!(dialog instanceof HTMLDialogElement) || !dialog.open) return;
    const config = overlayConfigs.get(dialog);
    if (!config?.historyKey) return;
    closeDirect(dialog, config.pendingReturnValue || "");
  });

  applyMotionPreference();
  query.addEventListener("change", applyMotionPreference);
  restoreShellNavigation();
  restoreLoginSubmit();

  window.VulnHunterInteraction = Object.freeze({
    motion: Object.freeze({
      reduced: () => query.matches,
    }),
    overlays: Object.freeze({
      register: registerOverlay,
      open: openOverlay,
      close: requestClose,
      top: topOverlay,
    }),
    shell: Object.freeze({
      acknowledgeNavigation: acknowledgeShellNavigation,
      restoreNavigation: restoreShellNavigation,
    }),
    login: Object.freeze({
      restoreSubmit: restoreLoginSubmit,
    }),
  });
  window.dispatchEvent(new CustomEvent("vh:interaction-ready"));
})();
