(() => {
  "use strict";

  const workspace = document.querySelector("[data-conversation-workspace]");
  const controller = workspace?.querySelector("[data-analysis-inspector-controller]");
  const close = workspace?.querySelector("[data-analysis-inspector-close]");
  if (!workspace || !controller) return;

  let returnFocus = null;

  const restoreFocus = () => {
    if (!(returnFocus instanceof HTMLElement) || !returnFocus.isConnected) return;
    returnFocus.focus({ preventScroll: true });
    returnFocus = null;
  };

  workspace.addEventListener("click", (event) => {
    const trigger = event.target.closest?.("[data-analysis-inspector-open]");
    if (!(trigger instanceof HTMLElement)) return;
    returnFocus = trigger;
    controller.click();
  });

  close?.addEventListener("click", () => window.queueMicrotask(restoreFocus));
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !returnFocus) return;
    window.queueMicrotask(restoreFocus);
  });
})();
