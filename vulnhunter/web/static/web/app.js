(() => {
  "use strict";

  const sidebar = document.querySelector("[data-sidebar]");
  const navToggle = document.querySelector("[data-nav-toggle]");
  const navClose = document.querySelector("[data-nav-close]");

  function setNavigation(open) {
    if (!sidebar || !navToggle || !navClose) {
      return;
    }
    sidebar.classList.toggle("is-open", open);
    navToggle.setAttribute("aria-expanded", String(open));
    navToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    navClose.hidden = !open;
    document.body.classList.toggle("vh-nav-open", open);
    if (!open) {
      navToggle.focus({ preventScroll: true });
    }
  }

  navToggle?.addEventListener("click", () => {
    setNavigation(navToggle.getAttribute("aria-expanded") !== "true");
  });
  navClose?.addEventListener("click", () => setNavigation(false));

  const contextMenus = [...document.querySelectorAll(".vh-context-menu")];
  contextMenus.forEach((menu) => {
    menu.addEventListener("toggle", () => {
      if (!menu.open) return;
      contextMenus.forEach((otherMenu) => {
        if (otherMenu !== menu) otherMenu.open = false;
      });
    });
  });
  document.addEventListener("click", (event) => {
    contextMenus.forEach((menu) => {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
  });

  sidebar?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.matchMedia("(max-width: 1023px)").matches) {
        setNavigation(false);
      }
    });
  });

  const commandDialog = document.querySelector("#vh-command-dialog");
  const searchToggle = document.querySelector("[data-search-toggle]");
  const commandInput = document.querySelector("[data-command-input]");
  const commandItems = [...document.querySelectorAll("[data-command-results] li")];

  function openSearch() {
    if (!(commandDialog instanceof HTMLDialogElement)) {
      return;
    }
    commandDialog.showModal();
    searchToggle?.setAttribute("aria-expanded", "true");
    window.requestAnimationFrame(() => commandInput?.focus());
  }

  searchToggle?.addEventListener("click", openSearch);
  commandDialog?.addEventListener("close", () => {
    searchToggle?.setAttribute("aria-expanded", "false");
    commandInput.value = "";
    commandItems.forEach((item) => { item.hidden = false; });
    searchToggle?.focus({ preventScroll: true });
  });
  commandInput?.addEventListener("input", () => {
    const query = commandInput.value.trim().toLocaleLowerCase();
    commandItems.forEach((item) => {
      item.hidden = Boolean(query) && !item.textContent.toLocaleLowerCase().includes(query);
    });
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    }
    if (event.key === "Escape" && sidebar?.classList.contains("is-open")) {
      setNavigation(false);
    }
    if (event.key === "Escape") {
      contextMenus.forEach((menu) => { menu.open = false; });
    }
  });

  document.querySelectorAll("[data-ui-tabs]").forEach((root) => {
    const tabList = root.querySelector(":scope > [role='tablist']");
    const tabs = tabList ? [...tabList.querySelectorAll(":scope > [role='tab']")] : [];
    const panels = [...root.querySelectorAll(":scope > [role='tabpanel']")];

    function selectTab(tab, moveFocus = false) {
      tabs.forEach((item) => {
        const selected = item === tab;
        item.classList.toggle("is-active", selected);
        item.setAttribute("aria-selected", String(selected));
        item.tabIndex = selected ? 0 : -1;
      });
      panels.forEach((panel) => {
        panel.hidden = panel.id !== tab.dataset.tabTarget;
      });
      if (moveFocus) {
        tab.focus();
      }
    }

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => selectTab(tab));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
          return;
        }
        event.preventDefault();
        let nextIndex = index;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        if (event.key === "Home") nextIndex = 0;
        if (event.key === "End") nextIndex = tabs.length - 1;
        selectTab(tabs[nextIndex], true);
      });
    });
    if (tabs[0]) {
      selectTab(tabs.find((tab) => tab.getAttribute("aria-selected") === "true") || tabs[0]);
    }
  });

  document.querySelectorAll("[data-tab-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      const tab = document.getElementById(button.dataset.tabJump || "");
      if (!(tab instanceof HTMLElement)) return;
      tab.click();
      tab.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  });

  const approvalDialog = document.querySelector("[data-approval-dialog]");
  const approvalOpeners = [...document.querySelectorAll("[data-approval-open]")];
  const approvalCloser = document.querySelector("[data-approval-close]");

  function openApprovalDialog() {
    if (!(approvalDialog instanceof HTMLDialogElement) || approvalDialog.open) return;
    approvalDialog.showModal();
    window.requestAnimationFrame(() => {
      approvalDialog.querySelector("textarea, button, a")?.focus();
    });
  }

  approvalOpeners.forEach((button) => button.addEventListener("click", openApprovalDialog));
  approvalCloser?.addEventListener("click", () => approvalDialog?.close());
  approvalDialog?.addEventListener("click", (event) => {
    if (event.target === approvalDialog) approvalDialog.close();
  });
  approvalDialog?.addEventListener("cancel", () => {
    approvalOpeners[0]?.focus({ preventScroll: true });
  });
  if (approvalDialog?.dataset.autoOpen === "true") {
    window.requestAnimationFrame(openApprovalDialog);
  }
})();
