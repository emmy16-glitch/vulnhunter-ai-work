(() => {
  "use strict";

  if (typeof String.prototype.join === "function") return;

  Object.defineProperty(String.prototype, "join", {
    configurable: true,
    writable: true,
    value(items) {
      return Array.isArray(items) ? items.join(String(this)) : String(items ?? "");
    },
  });
})();
