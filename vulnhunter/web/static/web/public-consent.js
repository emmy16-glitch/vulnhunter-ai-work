(() => {
  "use strict";

  const form = document.querySelector("[data-public-consent-form]");
  if (!form) return;

  const submit = form.querySelector("[data-public-consent-submit]");
  const status = form.querySelector("[data-public-consent-status]");
  const csrf = form.querySelector("[name=csrfmiddlewaretoken]")?.value || "";

  // The form uses implicit wrapping labels, which are valid HTML. Add stable
  // explicit accessible names as well so browser/tooling audits and assistive
  // technology receive the same concise field names regardless of layout.
  const fieldNames = {
    challenge_token: "Published challenge token",
    owner: "Owner or organization",
    approved_by: "Approving person",
    expires_at: "Authorization expires",
  };
  Object.entries(fieldNames).forEach(([name, label]) => {
    const field = form.querySelector(`[name="${name}"]`);
    if (field && !field.getAttribute("aria-label") && !field.getAttribute("aria-labelledby")) {
      field.setAttribute("aria-label", label);
    }
  });

  const setStatus = (message, kind = "") => {
    status.textContent = message;
    status.classList.toggle("is-success", kind === "success");
    status.classList.toggle("is-error", kind === "error");
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;

    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    setStatus("Checking the HTTPS origin and consent challenge…");

    try {
      const response = await fetch(form.action, {
        method: "POST",
        headers: {
          "X-CSRFToken": csrf,
          Accept: "application/json",
        },
        credentials: "same-origin",
        body: new FormData(form),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Consent verification was rejected safely.");
      }

      const authorization = payload.authorization || {};
      setStatus(
        `Verified for passive mapping: ${authorization.target_url || "target"} · expires ${authorization.expires_at || "recorded"}`,
        "success",
      );
      form.dispatchEvent(new CustomEvent("publicconsentverified", { bubbles: true, detail: payload }));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Consent verification failed safely.", "error");
    } finally {
      submit.disabled = false;
      submit.removeAttribute("aria-busy");
    }
  });
})();