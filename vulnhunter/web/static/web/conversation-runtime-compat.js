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

  const current = document.currentScript?.src;
  if (!current || document.querySelector("script[data-workspace-state-loader]")) return;
  const url = new URL(current, window.location.href);
  url.pathname = url.pathname.replace(
    /conversation-runtime-compat\.js$/,
    "workspace-state.js",
  );
  url.search = "?v=20260725-consolidate1";
  const script = document.createElement("script");
  script.src = url.toString();
  script.async = false;
  script.dataset.workspaceStateLoader = "true";
  document.head.append(script);
})();
