(() => {
  "use strict";

  if (typeof String.prototype.join !== "function") {
    Object.defineProperty(String.prototype, "join", {
      configurable: true,
      writable: true,
      value(items) {
        return Array.isArray(items) ? items.join(String(this)) : String(items ?? "");
      },
    });
  }

  if (typeof document === "undefined" || typeof window === "undefined") return;
  const current = document.currentScript?.src;
  if (!current) return;

  const loadScript = (filename, marker) => {
    if (document.querySelector(`script[${marker}]`)) return;
    const url = new URL(current, window.location.href);
    url.pathname = url.pathname.replace(/conversation-runtime-compat\.js$/, filename);
    url.search = "?v=20260725-consolidate3";
    const script = document.createElement("script");
    script.src = url.toString();
    script.async = false;
    script.setAttribute(marker, "true");
    document.head.append(script);
  };

  const loadWorkspaceBridges = () => {
    loadScript("workspace-state.js", "data-workspace-state-loader");
    loadScript("workspace-safety-polish.js", "data-workspace-safety-loader");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadWorkspaceBridges, { once: true });
  } else {
    loadWorkspaceBridges();
  }
})();
