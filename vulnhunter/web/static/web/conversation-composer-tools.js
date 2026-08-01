(() => {
  "use strict";

  if (typeof document === "undefined" || typeof window === "undefined") return;

  const current = document.currentScript?.src;
  if (current && !document.querySelector("link[data-composer-tools-styles]")) {
    const styleUrl = new URL(current, window.location.href);
    styleUrl.pathname = styleUrl.pathname.replace(
      /conversation-composer-tools\.js$/,
      "conversation-composer-tools.css",
    );
    styleUrl.search = "?v=20260801-composer-tools1";
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl.toString();
    link.dataset.composerToolsStyles = "true";
    document.head.append(link);
  }

  const workspace = document.querySelector("[data-conversation-workspace]");
  const form = document.querySelector("[data-conversation-form]");
  const input = document.querySelector("[data-conversation-input]");
  const inputShell = document.querySelector(".vh-chat-input-shell");
  const composerMeta = document.querySelector(".vh-chat-composer-meta");
  if (!workspace || !form || !input || !inputShell || !composerMeta) return;

  const maximumLength = input.maxLength > 0 ? input.maxLength : 4000;
  const prompts = [
    {
      label: "Website assessment",
      description: "Describe an authorised website target and request a safe assessment plan.",
      value:
        "Help me assess this authorised website target: [target]. Start by confirming the exact scope and proposing the safest suitable assessment plan.",
    },
    {
      label: "APK analysis",
      description: "Prepare an uploaded Android APK for static and governed dynamic analysis.",
      value:
        "Analyse the attached Android APK. Start with static analysis, explain the permissions and risky components, then propose any governed dynamic checks that still require confirmation.",
    },
    {
      label: "Source review",
      description: "Review source code or a repository without leaving the current workspace.",
      value:
        "Review this authorised source repository for security issues. Explain the highest-risk code paths, evidence, and the next safe verification step.",
    },
    {
      label: "Explain findings",
      description: "Summarise current findings in straightforward language.",
      value:
        "Explain the current findings in plain language. Separate confirmed evidence, unverified observations, likely impact, and recommended remediation.",
    },
    {
      label: "Status and next step",
      description: "Ask what is complete, blocked, or awaiting confirmation.",
      value:
        "Summarise the current workspace status. Tell me what is complete, what is blocked, what needs my confirmation, and the safest next action.",
    },
  ];

  const tools = document.createElement("div");
  tools.className = "vh-composer-tools";
  tools.dataset.composerTools = "true";

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "vh-composer-tools-trigger";
  trigger.dataset.composerToolsTrigger = "true";
  trigger.textContent = "Prompts";
  trigger.title = "Insert a safe starter prompt";
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("aria-controls", "vh-composer-prompt-menu");

  const clear = document.createElement("button");
  clear.type = "button";
  clear.className = "vh-composer-clear";
  clear.dataset.composerClear = "true";
  clear.textContent = "Clear";
  clear.title = "Clear the current prompt";
  clear.hidden = true;

  const counter = document.createElement("output");
  counter.className = "vh-composer-counter";
  counter.dataset.composerCounter = "true";
  counter.setAttribute("aria-live", "polite");

  tools.append(trigger, clear, counter);
  composerMeta.append(tools);

  const menu = document.createElement("section");
  menu.id = "vh-composer-prompt-menu";
  menu.className = "vh-composer-prompt-menu";
  menu.dataset.composerPromptMenu = "true";
  menu.hidden = true;
  menu.setAttribute("aria-label", "Safe starter prompts");

  const menuHeader = document.createElement("header");
  const heading = document.createElement("div");
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "Starter prompts";
  const title = document.createElement("strong");
  title.textContent = "Choose what you want to do";
  heading.append(eyebrow, title);
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "×";
  close.setAttribute("aria-label", "Close starter prompts");
  menuHeader.append(heading, close);
  menu.append(menuHeader);

  const list = document.createElement("div");
  list.className = "vh-composer-prompt-list";
  prompts.forEach((prompt) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "vh-composer-prompt-option";
    button.dataset.promptValue = prompt.value;
    const label = document.createElement("strong");
    label.textContent = prompt.label;
    const description = document.createElement("small");
    description.textContent = prompt.description;
    button.append(label, description);
    list.append(button);
  });
  menu.append(list);
  form.insertBefore(menu, inputShell);

  const setInputValue = (value) => {
    input.value = String(value || "").slice(0, maximumLength);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  };

  const closeMenu = ({ focusTrigger = false } = {}) => {
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (focusTrigger) trigger.focus();
  };

  const openMenu = () => {
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    window.requestAnimationFrame(() => list.querySelector("button")?.focus());
  };

  const update = () => {
    const length = input.value.length;
    const remaining = Math.max(0, maximumLength - length);
    counter.textContent = `${length.toLocaleString()} / ${maximumLength.toLocaleString()}`;
    counter.dataset.state = remaining <= 200 ? "warning" : "normal";
    counter.title = `${remaining.toLocaleString()} characters remaining`;
    clear.hidden = length === 0;
    clear.disabled = input.disabled || length === 0;
  };

  trigger.addEventListener("click", () => {
    if (menu.hidden) openMenu();
    else closeMenu({ focusTrigger: true });
  });
  close.addEventListener("click", () => closeMenu({ focusTrigger: true }));
  clear.addEventListener("click", () => {
    setInputValue("");
    closeMenu();
  });
  list.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-prompt-value]");
    if (!(button instanceof HTMLButtonElement)) return;
    const prompt = button.dataset.promptValue || "";
    setInputValue(input.value.trim() ? `${input.value.trim()}\n\n${prompt}` : prompt);
    closeMenu();
  });
  menu.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      closeMenu({ focusTrigger: true });
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (menu.hidden || menu.contains(event.target) || trigger.contains(event.target)) return;
    closeMenu();
  });
  input.addEventListener("input", update);
  new MutationObserver(update).observe(input, { attributes: true, attributeFilter: ["disabled"] });

  update();
  window.VulnHunterComposerTools = Object.freeze({
    open: openMenu,
    close: closeMenu,
    clear: () => setInputValue(""),
    insert: setInputValue,
  });
})();