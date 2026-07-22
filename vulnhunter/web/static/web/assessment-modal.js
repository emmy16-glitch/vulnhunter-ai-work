(() => {
  "use strict";

  const dialog = document.querySelector("[data-assessment-dialog]");
  if (!(dialog instanceof HTMLDialogElement)) return;

  const status = dialog.querySelector("[data-assessment-status]");
  const authorizationSelect = dialog.querySelector("[data-authorization-select]");
  const targetSelect = dialog.querySelector("[data-target-select]");
  const protocolSelect = dialog.querySelector("[data-protocol-select]");
  const portSelect = dialog.querySelector("[data-port-select]");
  const profileSelect = dialog.querySelector("[data-profile-select]");
  const engineSelect = dialog.querySelector("[data-engine-select]");
  const submit = dialog.querySelector("[data-assessment-submit]");
  let records = [];
  let loaded = false;

  function replaceOptions(select, label, values) {
    if (!(select instanceof HTMLSelectElement)) return;
    select.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = label;
    select.append(placeholder);
    for (const value of values) {
      const option = document.createElement("option");
      option.value = String(value);
      option.textContent = String(value);
      select.append(option);
    }
    select.disabled = values.length === 0;
  }

  function selectedRecord() {
    return records.find((record) => record.authorization_id === authorizationSelect?.value);
  }

  function updateSubmit() {
    if (!(submit instanceof HTMLButtonElement)) return;
    submit.disabled = ![
      authorizationSelect,
      targetSelect,
      protocolSelect,
      portSelect,
      profileSelect,
      engineSelect,
    ].every((select) => select instanceof HTMLSelectElement && select.value);
  }

  function updateChoices() {
    const record = selectedRecord();
    replaceOptions(targetSelect, "Select target", record?.approved_targets || []);
    replaceOptions(protocolSelect, "Select protocol", record?.approved_protocols || []);
    replaceOptions(portSelect, "Select port", record?.approved_ports || []);
    replaceOptions(profileSelect, "Select profile", record?.approved_profiles || []);
    if (status) {
      status.textContent = record
        ? `Authorization expires ${record.expires_at}. The backend will revalidate every value.`
        : "Select an active authorization.";
    }
    updateSubmit();
  }

  async function loadAuthorizations() {
    if (loaded) return;
    if (status) status.textContent = "Loading active authorizations…";
    if (authorizationSelect instanceof HTMLSelectElement) authorizationSelect.disabled = true;
    try {
      const response = await fetch(dialog.dataset.authorizationsUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (response.status === 403) {
        throw new Error("This account reviews existing assessments and cannot create new plans.");
      }
      if (!response.ok) {
        throw new Error("The authorization service is temporarily unavailable.");
      }
      const payload = await response.json();
      records = Array.isArray(payload.authorizations) ? payload.authorizations : [];
      if (authorizationSelect instanceof HTMLSelectElement) {
        authorizationSelect.replaceChildren();
        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = "Select authorization";
        authorizationSelect.append(placeholder);
        for (const record of records) {
          const option = document.createElement("option");
          option.value = String(record.authorization_id);
          option.textContent = String(record.display_label);
          authorizationSelect.append(option);
        }
        authorizationSelect.disabled = records.length === 0;
      }
      loaded = true;
      if (status) {
        status.textContent = records.length
          ? "Select an active authorization. Approval and execution will continue in this control centre."
          : "No active authorization is available for this operator account.";
      }
    } catch (error) {
      if (status) {
        status.textContent = error instanceof Error
          ? error.message
          : "Active authorizations could not be loaded safely.";
      }
    }
  }

  function openDialog() {
    if (!dialog.open) dialog.showModal();
    loadAuthorizations();
  }

  document.querySelectorAll("[data-assessment-open]").forEach((button) => {
    button.addEventListener("click", openDialog);
  });
  dialog.querySelectorAll("[data-assessment-close]").forEach((button) => {
    button.addEventListener("click", () => dialog.close());
  });
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  authorizationSelect?.addEventListener("change", updateChoices);
  [targetSelect, protocolSelect, portSelect, profileSelect, engineSelect].forEach((select) => {
    select?.addEventListener("change", updateSubmit);
  });
})();
