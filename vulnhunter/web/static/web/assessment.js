(() => {
  "use strict";

  const dialog = document.querySelector("[data-launch-dialog]");
  const openButtons = Array.from(document.querySelectorAll("[data-launch-open]"));
  const closeButtons = dialog
    ? Array.from(dialog.querySelectorAll("[data-launch-close]"))
    : [];
  let returnFocus = null;

  const restoreFocus = () => {
    if (returnFocus instanceof HTMLElement) returnFocus.focus();
    returnFocus = null;
  };

  const closeDialog = () => {
    if (!dialog || !dialog.hasAttribute("open")) return;
    if (typeof dialog.close === "function") {
      dialog.close();
    } else {
      dialog.removeAttribute("open");
      restoreFocus();
    }
  };

  const openDialog = (trigger) => {
    if (!dialog) return;
    returnFocus = trigger instanceof HTMLElement ? trigger : null;
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }

    const firstField = dialog.querySelector("select, textarea, input, button");
    if (firstField instanceof HTMLElement) firstField.focus();
  };

  openButtons.forEach((button) => {
    button.addEventListener("click", () => openDialog(button));
  });

  closeButtons.forEach((button) => {
    button.addEventListener("click", closeDialog);
  });

  if (dialog) {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeDialog();
    });

    dialog.addEventListener("close", restoreFocus);
  }

  const formatExpiry = (rawValue) => {
    if (!rawValue) return "—";
    const date = new Date(rawValue);
    if (Number.isNaN(date.getTime())) return rawValue;
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(date);
  };

  document.querySelectorAll("[data-assessment-form]").forEach((form) => {
    const authorizationSelect = form.querySelector("[data-authorization-select]");
    if (!(authorizationSelect instanceof HTMLSelectElement)) return;

    const targetOutput = form.querySelector("[data-selected-target]");
    const scopeOutput = form.querySelector("[data-selected-scope]");
    const ownerOutput = form.querySelector("[data-selected-owner]");
    const expiryOutput = form.querySelector("[data-selected-expiry]");

    const updateScopePreview = () => {
      const option = authorizationSelect.selectedOptions[0];
      const hasSelection = Boolean(option && option.value);

      if (targetOutput) {
        targetOutput.textContent = hasSelection
          ? option.dataset.target || "Unavailable"
          : "Choose a record";
      }
      if (scopeOutput) {
        scopeOutput.textContent = hasSelection
          ? option.dataset.scope || "Unavailable"
          : "Not bound";
      }
      if (ownerOutput) {
        ownerOutput.textContent = hasSelection
          ? option.dataset.owner || "—"
          : "—";
      }
      if (expiryOutput) {
        expiryOutput.textContent = hasSelection
          ? formatExpiry(option.dataset.expires)
          : "—";
      }
    };

    authorizationSelect.addEventListener("change", updateScopePreview);
    updateScopePreview();

    form.addEventListener("submit", () => {
      if (!form.checkValidity()) return;
      const submitButton = form.querySelector('button[type="submit"]');
      if (!(submitButton instanceof HTMLButtonElement)) return;
      submitButton.disabled = true;
      submitButton.setAttribute("aria-busy", "true");
      submitButton.textContent = "Creating request…";
    });
  });
})();
