from __future__ import annotations

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "vulnhunter/web/static/web/app.js"
text = path.read_text(encoding="utf-8")
if "const disclosureRoute" in text:
    raise SystemExit(0)
if not text.endswith("})();\n"):
    raise RuntimeError("app.js closure marker changed")
addition = r"""

  const disclosureRoute = document.body.dataset.route || "page";
  const disclosures = [...document.querySelectorAll(".vh-stage-disclosure, [data-persist-disclosure]")];
  disclosures.forEach((details, index) => {
    const keyPart = details.dataset.disclosureKey || details.id || String(index);
    const storageKey = `vh-disclosure:${disclosureRoute}:${keyPart}`;
    let saved = null;
    try {
      saved = window.sessionStorage.getItem(storageKey);
    } catch (_error) {
      saved = null;
    }
    if (saved === "open") details.open = true;
    if (saved === "closed") details.open = false;
    if (saved === null && details.dataset.autoOpen === "true") details.open = true;
    details.addEventListener("toggle", () => {
      try {
        window.sessionStorage.setItem(storageKey, details.open ? "open" : "closed");
      } catch (_error) {
        // Disclosure state remains usable when session storage is unavailable.
      }
      if (!details.open || !window.matchMedia("(max-width: 767px)").matches) return;
      const group = details.closest("[data-disclosure-group], .vh-stage-list, .vh-trial-list");
      group?.querySelectorAll("details[open]").forEach((other) => {
        if (other !== details) other.open = false;
      });
    });
  });

  function formatElapsed(totalSeconds) {
    const bounded = Math.max(0, Number(totalSeconds) || 0);
    const hours = Math.floor(bounded / 3600);
    const minutes = Math.floor((bounded % 3600) / 60);
    const seconds = Math.floor(bounded % 60);
    return [hours, minutes, seconds].map((value) => String(value).padStart(2, "0")).join(":");
  }

  document.querySelectorAll("[data-operational-stream]").forEach((root) => {
    const url = root.dataset.operationalStream;
    if (!url || !("EventSource" in window)) return;
    const copy = root.querySelector("[data-operational-copy]");
    const state = document.querySelector("[data-operational-state]");
    const trial = document.querySelector("[data-operational-trial]");
    const confirmed = document.querySelector("[data-operational-confirmed]");
    const elapsed = root.querySelector("[data-operational-elapsed]");
    const log = document.querySelector("[data-live-events]");
    let lastSequence = Number(root.dataset.lastSequence || 0);
    let elapsedSeconds = 0;
    const startedAt = Date.parse(root.dataset.startedAt || "");
    if (Number.isFinite(startedAt)) {
      elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    }
    if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
    const timer = window.setInterval(() => {
      if (!root.classList.contains("is-active")) return;
      elapsedSeconds += 1;
      if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
    }, 1000);

    function appendEvent(event) {
      if (!log || log.querySelector(`[data-event-sequence="${event.sequence}"]`)) return;
      log.querySelector("[data-empty-events]")?.remove();
      const line = document.createElement("div");
      line.className = "vh-log-line is-new";
      line.dataset.eventSequence = String(event.sequence);
      const prefix = document.createElement("span");
      prefix.className = "vh-log-prefix";
      prefix.textContent = `[${event.event_type}]`;
      const time = document.createElement("time");
      time.textContent = event.timestamp || "";
      const summary = document.createElement("span");
      summary.textContent = event.summary || "Recorded activity";
      const reference = document.createElement("code");
      reference.textContent = event.event_sha256 ? `${event.event_sha256.slice(0, 16)}…` : "";
      line.append(prefix, time, summary, reference);
      log.append(line);
      window.setTimeout(() => line.classList.remove("is-new"), 1200);
    }

    const source = new EventSource(`${url}?after_sequence=${lastSequence}`);
    source.addEventListener("activity", (message) => {
      let payload;
      try {
        payload = JSON.parse(message.data);
      } catch (_error) {
        return;
      }
      const events = Array.isArray(payload.events) ? payload.events : [];
      events.forEach(appendEvent);
      const latest = events.at(-1);
      if (latest?.summary && copy) copy.textContent = latest.summary;
      if (!latest?.summary && payload.active_summary && copy) copy.textContent = payload.active_summary;
      lastSequence = Math.max(lastSequence, Number(payload.last_sequence || 0));
      root.dataset.lastSequence = String(lastSequence);
      if (state && payload.run_state) state.textContent = payload.run_state;
      if (trial && payload.maximum_trials !== undefined) {
        trial.textContent = `Trial ${payload.current_trial || 0}/${payload.maximum_trials}`;
      }
      if (confirmed && payload.confirmed_trials !== undefined) {
        confirmed.textContent = String(payload.confirmed_trials);
      }
      if (payload.elapsed_seconds !== undefined) {
        elapsedSeconds = Number(payload.elapsed_seconds) || elapsedSeconds;
        if (elapsed) elapsed.textContent = formatElapsed(elapsedSeconds);
      }
      const terminal = Boolean(payload.terminal);
      root.classList.toggle("is-active", !terminal);
      root.classList.toggle("is-terminal", terminal);
      if (terminal) {
        window.clearInterval(timer);
        source.close();
      }
    });
    source.addEventListener("error", () => {
      root.classList.add("is-reconnecting");
      window.setTimeout(() => root.classList.remove("is-reconnecting"), 1200);
    });
  });
"""
path.write_text(text[:-5] + addition + "})();\n", encoding="utf-8")
