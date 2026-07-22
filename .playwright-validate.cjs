const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
const outputRoot = process.env.VULNHUNTER_UI_OUTPUT || "/tmp/vulnhunter-ui-audit";
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const viewports = [
  { name: "reference-1672", width: 1672, height: 941 },
  { name: "desktop-1440", width: 1440, height: 900 },
  { name: "tablet-1024", width: 1024, height: 768 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "mobile-390", width: 390, height: 844 },
  { name: "mobile-360", width: 360, height: 800 },
];
function safeName(value) {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-");
}

(async () => {
  fs.mkdirSync(outputRoot, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const report = {
    pages: [],
    consoleErrors: [],
    pageErrors: [],
    assetFailures: [],
    linkFailures: [],
    interactionFailures: [],
    failures: [],
  };
  const contextCache = new Map();
  const checkedLinks = new Map();
  const testedGlobalInteractions = new Set();

  async function contextFor(viewport, personaName) {
    const key = `${viewport.name}:${personaName}`;
    if (contextCache.has(key)) return contextCache.get(key);
    const context = await browser.newContext({
      viewport,
      colorScheme: "dark",
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    const persona = manifest.personas[personaName];
    const login = await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    if (!login || login.status() >= 400) throw new Error(`Login page failed for ${personaName}`);
    await page.getByLabel("Username").fill(persona.username);
    await page.getByLabel("Password").fill(persona.password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);
    await page.close();
    contextCache.set(key, context);
    return context;
  }

  async function auditGlobalInteractions(page, viewport, personaName, routeKey) {
    const interactionKey = `${viewport.name}:${personaName}`;
    if (testedGlobalInteractions.has(interactionKey)) return;
    testedGlobalInteractions.add(interactionKey);

    try {
      const searchButton = page.locator("[data-search-toggle]");
      if (await searchButton.isVisible()) {
        await searchButton.click();
        const dialog = page.locator("#vh-command-dialog");
        if (!(await dialog.evaluate((element) => element.open))) {
          report.interactionFailures.push({ routeKey, interaction: "search-open" });
        } else {
          const input = page.locator("[data-command-input]");
          await input.fill("Settings");
          const settingsResult = page.getByRole("link", { name: "Settings", exact: true });
          if (!(await settingsResult.isVisible())) {
            report.interactionFailures.push({ routeKey, interaction: "search-filter" });
          }
          await page.keyboard.press("Escape");
          if (await dialog.evaluate((element) => element.open)) {
            report.interactionFailures.push({ routeKey, interaction: "search-close" });
          }
        }
      }
    } catch (error) {
      report.interactionFailures.push({
        routeKey,
        interaction: "search-dialog",
        text: error.message,
      });
    }

    if (viewport.width <= 768) {
      try {
        const toggle = page.locator("[data-nav-toggle]");
        const sidebar = page.locator("[data-sidebar]");
        const close = page.locator("[data-nav-close]");
        await toggle.click();
        if (!(await sidebar.isVisible()) || (await toggle.getAttribute("aria-expanded")) !== "true") {
          report.interactionFailures.push({ routeKey, interaction: "mobile-nav-open" });
        }
        await close.click({ position: { x: viewport.width - 8, y: 8 } });
        if ((await toggle.getAttribute("aria-expanded")) !== "false") {
          report.interactionFailures.push({ routeKey, interaction: "mobile-nav-close" });
        }
      } catch (error) {
        report.interactionFailures.push({
          routeKey,
          interaction: "mobile-navigation",
          text: error.message,
        });
      }
    }
  }

  for (const pageDefinition of manifest.pages) {
    const targets = pageDefinition.responsive ? viewports : [viewports[1]];
    for (const viewport of targets) {
      const context = await contextFor(viewport, pageDefinition.persona);
      const page = await context.newPage();
      const routeKey = `${pageDefinition.name}:${viewport.name}`;
      page.on("console", (message) => {
        if (message.type() === "error") {
          report.consoleErrors.push({ routeKey, text: message.text() });
        }
      });
      page.on("pageerror", (error) => report.pageErrors.push({ routeKey, text: error.message }));
      page.on("response", (response) => {
        if (response.url().includes("/static/") && response.status() >= 400) {
          report.assetFailures.push({
            routeKey,
            url: response.url(),
            status: response.status(),
          });
        }
      });
      const response = await page.goto(`${baseUrl}${pageDefinition.path}`, {
        waitUntil: "networkidle",
      });
      await page.waitForTimeout(150);
      await auditGlobalInteractions(page, viewport, pageDefinition.persona, routeKey);

      const audit = await page.evaluate(async () => {
        const visible = (element) => {
          const style = getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return (
            style.display !== "none" &&
            style.visibility !== "hidden" &&
            rect.width > 0 &&
            rect.height > 0
          );
        };
        const nextFrame = () => new Promise((resolve) => requestAnimationFrame(() => resolve()));
        const controls = [
          ...document.querySelectorAll("button, a, input, select, textarea, summary"),
        ].filter(visible);
        const unnamedControls = controls
          .filter((element) => {
            const id = element.getAttribute("id");
            const label = id
              ? document.querySelector(`label[for="${CSS.escape(id)}"]`)
              : null;
            return !(
              element.getAttribute("aria-label") ||
              element.getAttribute("aria-labelledby") ||
              element.textContent.trim() ||
              element.getAttribute("title") ||
              element.getAttribute("placeholder") ||
              label?.textContent.trim()
            );
          })
          .map((element) => element.outerHTML.slice(0, 220));
        const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
        const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
        const sidebar = document.querySelector(".vh-sidebar");
        const navToggle = document.querySelector("[data-nav-toggle]");
        const activeNavigation = [
          ...document.querySelectorAll('.vh-nav-list a[aria-current="page"]'),
        ];
        const bodyText = document.body.innerText;
        const root = document.scrollingElement || document.documentElement;
        const main = document.querySelector(".vh-main");

        async function verifyScroll(element) {
          if (!element || element.scrollHeight <= element.clientHeight + 2) {
            return {
              needed: false,
              reachedBottom: true,
              scrollHeight: element?.scrollHeight || 0,
              clientHeight: element?.clientHeight || 0,
            };
          }
          const original = element.scrollTop;
          const maximum = element.scrollHeight - element.clientHeight;
          element.scrollTop = maximum;
          await nextFrame();
          await nextFrame();
          const reachedBottom = element.scrollTop >= maximum - 2;
          element.scrollTop = original;
          return {
            needed: true,
            reachedBottom,
            scrollHeight: element.scrollHeight,
            clientHeight: element.clientHeight,
          };
        }

        const documentScroll = await verifyScroll(root);
        const mainStyle = main ? getComputedStyle(main) : null;
        const mainCanOwnScroll = Boolean(
          mainStyle && ["auto", "scroll"].includes(mainStyle.overflowY),
        );
        const mainScroll = mainCanOwnScroll
          ? await verifyScroll(main)
          : {
              needed: false,
              reachedBottom: true,
              scrollHeight: main?.scrollHeight || 0,
              clientHeight: main?.clientHeight || 0,
            };

        const clippingContainers = [
          ...document.querySelectorAll(
            ".vh-main-shell, .vh-main, .vh-page-shell, .vh-product-page, .vh-settings-page",
          ),
        ]
          .filter((element) => {
            const style = getComputedStyle(element);
            return (
              ["hidden", "clip"].includes(style.overflowY) &&
              element.scrollHeight > element.clientHeight + 2
            );
          })
          .map((element) => ({
            selector:
              element.id ||
              [...element.classList].map((name) => `.${name}`).join("") ||
              element.tagName.toLowerCase(),
            scrollHeight: element.scrollHeight,
            clientHeight: element.clientHeight,
            overflowY: getComputedStyle(element).overflowY,
          }));

        const lastContent = main
          ? [...main.children].filter(visible).at(-1) || null
          : null;
        const owner = documentScroll.needed ? root : mainScroll.needed ? main : null;
        let lastContentReachable = true;
        if (lastContent && owner) {
          const original = owner.scrollTop;
          owner.scrollTop = owner.scrollHeight - owner.clientHeight;
          await nextFrame();
          await nextFrame();
          const rect = lastContent.getBoundingClientRect();
          lastContentReachable = rect.top < window.innerHeight && rect.bottom <= window.innerHeight + 4;
          owner.scrollTop = original;
        } else if (lastContent) {
          const rect = lastContent.getBoundingClientRect();
          lastContentReachable = rect.bottom <= window.innerHeight + 4;
        }

        const deadButtons = [...document.querySelectorAll('button[type="button"]')]
          .filter(visible)
          .filter((element) => !element.disabled)
          .filter((element) => {
            const hasDataHook = [...element.attributes].some((attribute) =>
              attribute.name.startsWith("data-"),
            );
            return !(
              hasDataHook ||
              element.getAttribute("aria-controls") ||
              element.getAttribute("onclick") ||
              element.closest("form")
            );
          })
          .map((element) => element.outerHTML.slice(0, 220));

        const placeholderLinks = [...document.querySelectorAll("a[href]")]
          .filter(visible)
          .filter((element) => {
            const href = element.getAttribute("href").trim();
            return href === "#" || href.startsWith("javascript:");
          })
          .map((element) => element.outerHTML.slice(0, 220));

        const postFormsWithoutCsrf = [...document.querySelectorAll("form")]
          .filter((form) => (form.getAttribute("method") || "get").toLowerCase() === "post")
          .filter((form) => !form.querySelector('input[name="csrfmiddlewaretoken"]'))
          .map((form) => form.outerHTML.slice(0, 220));

        const internalLinks = [
          ...new Set(
            [...document.querySelectorAll("a[href]")]
              .filter(visible)
              .map((element) => new URL(element.href, window.location.href))
              .filter((url) => url.origin === window.location.origin)
              .filter((url) => !url.pathname.includes("/activity/stream/"))
              .map((url) => `${url.pathname}${url.search}`),
          ),
        ];

        return {
          title: document.title,
          h1Count: [...document.querySelectorAll("h1")].filter(visible).length,
          overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
          bodyScrollWidth: document.documentElement.scrollWidth,
          bodyClientWidth: document.documentElement.clientWidth,
          documentScroll,
          mainScroll,
          rootOverflowY: getComputedStyle(document.documentElement).overflowY,
          stableScrollbar: getComputedStyle(document.documentElement).overflowY === "scroll",
          clippingContainers,
          lastContentReachable,
          unnamedControls,
          deadButtons,
          placeholderLinks,
          postFormsWithoutCsrf,
          duplicateIds: [...new Set(duplicateIds)],
          internalLinks,
          activeNavigation: activeNavigation.map((item) => item.textContent.trim()),
          djangoError:
            Boolean(document.querySelector("#traceback, .technical-500")) ||
            /TemplateSyntaxError at\/|Server Error \(500\)/i.test(bodyText),
          sidebarVisible: sidebar ? visible(sidebar) : false,
          navToggleVisible: navToggle ? visible(navToggle) : false,
        };
      });

      for (const href of audit.internalLinks) {
        const absoluteUrl = new URL(href, baseUrl).toString();
        const linkKey = `${pageDefinition.persona}:${absoluteUrl}`;
        if (!checkedLinks.has(linkKey)) {
          try {
            const linkResponse = await context.request.get(absoluteUrl, {
              failOnStatusCode: false,
              maxRedirects: 3,
              timeout: 10_000,
            });
            checkedLinks.set(linkKey, linkResponse.status());
          } catch (error) {
            checkedLinks.set(linkKey, 0);
            report.linkFailures.push({ routeKey, href, status: 0, text: error.message });
          }
        }
        const linkStatus = checkedLinks.get(linkKey);
        if (linkStatus === 0 || linkStatus >= 400) {
          report.linkFailures.push({ routeKey, href, status: linkStatus });
        }
      }

      const status = response ? response.status() : 0;
      report.pages.push({ ...pageDefinition, viewport: viewport.name, status, ...audit });
      if (status >= 400) report.failures.push(`${routeKey} returned ${status}`);
      if (audit.djangoError) report.failures.push(`${routeKey} displayed a Django error`);
      if (audit.overflowX) report.failures.push(`${routeKey} has body-level horizontal overflow`);
      if (audit.unnamedControls.length) report.failures.push(`${routeKey} has unnamed controls`);
      if (audit.deadButtons.length) report.failures.push(`${routeKey} has unwired buttons`);
      if (audit.placeholderLinks.length) report.failures.push(`${routeKey} has placeholder links`);
      if (audit.postFormsWithoutCsrf.length) {
        report.failures.push(`${routeKey} has POST forms without CSRF protection`);
      }
      if (audit.duplicateIds.length) report.failures.push(`${routeKey} has duplicate ids`);
      if (audit.clippingContainers.length) {
        report.failures.push(`${routeKey} clips vertically overflowing content`);
      }
      if (!audit.documentScroll.reachedBottom || !audit.mainScroll.reachedBottom) {
        report.failures.push(`${routeKey} has content that cannot be scrolled to the bottom`);
      }
      if (!audit.lastContentReachable) {
        report.failures.push(`${routeKey} has unreachable final page content`);
      }
      if (viewport.width >= 1024 && !audit.stableScrollbar) {
        report.failures.push(`${routeKey} does not reserve a stable vertical scrollbar`);
      }
      if (audit.h1Count !== 1) {
        report.failures.push(`${routeKey} has ${audit.h1Count} visible h1 elements`);
      }
      if (audit.activeNavigation.length !== 1) {
        report.failures.push(
          `${routeKey} has ${audit.activeNavigation.length} active navigation items`,
        );
      }
      if (viewport.width <= 768 && (!audit.navToggleVisible || audit.sidebarVisible)) {
        report.failures.push(
          `${routeKey} mobile navigation is not closed with a visible toggle`,
        );
      }
      await page.screenshot({
        path: path.join(outputRoot, `${safeName(pageDefinition.name)}-${viewport.name}.png`),
        fullPage: true,
      });
      await page.close();
    }
  }

  for (const context of contextCache.values()) await context.close();
  await browser.close();
  if (report.consoleErrors.length) {
    report.failures.push(`${report.consoleErrors.length} console error(s)`);
  }
  if (report.pageErrors.length) report.failures.push(`${report.pageErrors.length} page error(s)`);
  if (report.assetFailures.length) {
    report.failures.push(`${report.assetFailures.length} failed static asset response(s)`);
  }
  if (report.linkFailures.length) {
    report.failures.push(`${report.linkFailures.length} broken internal link(s)`);
  }
  if (report.interactionFailures.length) {
    report.failures.push(`${report.interactionFailures.length} broken UI interaction(s)`);
  }
  fs.writeFileSync(
    path.join(outputRoot, "validation-report.json"),
    JSON.stringify(report, null, 2),
  );
  console.log(JSON.stringify({ pages: report.pages.length, failures: report.failures }, null, 2));
  if (report.failures.length) process.exitCode = 1;
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
