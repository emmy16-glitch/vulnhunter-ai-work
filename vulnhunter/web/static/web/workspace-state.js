(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  // progress_percent is intentionally not consumed. Genuine progress exists only
  // when the authoritative task card supplies measured persisted stages or bytes.
  const listeners = new Set();
  let snapshot = null;

  const clone = (value) => {
    if (value === null || value === undefined) return null;
    if (typeof window.structuredClone === "function") return window.structuredClone(value);
    return JSON.parse(JSON.stringify(value));
  };

  const authoritativeSnapshot = (payload) => {
    const projection = payload?.assessment_projection || null;
    const taskCard = payload?.task_card || projection?.task_card || null;
    const assessmentId = String(projection?.assessment_id || "").trim();
    if (!assessmentId || String(taskCard?.assessment_id || "").trim() !== assessmentId) {
      return null;
    }
    return {
      assessment_projection: projection,
      task_card: taskCard,
      mobile_plan: payload?.mobile_plan || null,
      mobile_execution: payload?.mobile_execution || null,
    };
  };

  const publish = (next) => {
    snapshot = clone(next);
    listeners.forEach((listener) => listener(clone(snapshot)));
    document.dispatchEvent(
      new CustomEvent("vh:selected-assessment-change", { detail: clone(snapshot) }),
    );
  };

  const store = Object.freeze({
    getSnapshot() {
      return clone(snapshot);
    },
    replace(payload) {
      publish(authoritativeSnapshot(payload));
      return clone(snapshot);
    },
    clear() {
      publish(null);
    },
    subscribe(listener) {
      if (typeof listener !== "function") return () => undefined;
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  });

  Object.defineProperty(window, "vhSelectedAssessmentStore", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: store,
  });

  document.dispatchEvent(new CustomEvent("vh:selected-assessment-store-ready", { detail: store }));
})();
