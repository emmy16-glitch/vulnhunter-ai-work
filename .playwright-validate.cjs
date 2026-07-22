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
    failures: [],
  };
  const contextCache = new Map();

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
    if (!login || login.status() >= 400) {
      throw new Error(`Login page failed for ${personaName}`);
    }
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
      page.on("pageerror", (error) => {
        report.pageErrors.push({ routeKey, text: error.message });
      });
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
        const sidebarNavigation = document.querySelector(".vh-nav");
        const navToggle = document.querySelector("[data-nav-toggle]");
        const activeNavigation = [
          ...document.querySelectorAll('.vh-nav-list a[aria-current="page"]'),
        ];
        const primaryLinks = [
          ...document.querySelectorAll(".vh-nav-list a[href]"),
        ];
        const linkSignatures = primaryLinks.map(
          (link) => `${link.getAttribute("href")}::${link.textContent.trim()}`,
        );
        const duplicateNavigation = linkSignatures.filter(
          (signature, index) => linkSignatures.indexOf(signature) !== index,
        );
        const emptyLinks = [...document.querySelectorAll('a[href=""], a:not([href])')]
          .filter(visible)
          .map((element) => element.outerHTML.slice(0, 220));
        const brokenAnchors = [...document.querySelectorAll('a[href^="#"]')]
          .filter(visible)
          .filter((element) => {
            const target = element.getAttribute("href").slice(1);
            return target && !document.getElementById(target);
          })
          .map((element) => element.getAttribute("href"));
        const bodyText = document.body.innerText;
        const root = document.documentElement;
        const pageIsLong = root.scrollHeight > root.clientHeight + 1;
        const initialScrollY = window.scrollY;
        let pageCanScrollVertically = true;
        if (pageIsLong) {
          window.scrollTo(0, root.scrollHeight);
          await new Promise((resolve) => requestAnimationFrame(resolve));
          pageCanScrollVertically = window.scrollY > initialScrollY;
          window.scrollTo(0, initialScrollY);
        }
        const rootOverflowY = getComputedStyle(root).overflowY;
        const sidebarNeedsScroll = Boolean(
          sidebarNavigation &&
            sidebarNavigation.scrollHeight > sidebarNavigation.clientHeight + 1,
        );
        let sidebarCanScroll = true;
        if (sidebarNeedsScroll) {
          const original = sidebarNavigation.scrollTop;
          sidebarNavigation.scrollTop = sidebarNavigation.scrollHeight;
          sidebarCanScroll = sidebarNavigation.scrollTop > original;
          sidebarNavigation.scrollTop = original;
        }
        return {
          title: document.title,
          h1Count: [...document.querySelectorAll("h1")].filter(visible).length,
          overflowX: root.scrollWidth > root.clientWidth + 1,
          bodyScrollWidth: root.scrollWidth,
          bodyClientWidth: root.clientWidth,
          pageIsLong,
          pageCanScrollVertically,
          rootOverflowY,
          sidebarNeedsScroll,
          sidebarCanScroll,
          unnamedControls,
          duplicateIds: [...new Set(duplicateIds)],
          duplicateNavigation: [...new Set(duplicateNavigation)],
          emptyLinks,
          brokenAnchors: [...new Set(brokenAnchors)],
          activeNavigation: activeNavigation.map((item) => item.textContent.trim()),
          djangoError:
            Boolean(document.querySelector("#traceback, .technical-500")) ||
            /TemplateSyntaxError at\/|Server Error \(500\)/i.test(bodyText),
          sidebarVisible: sidebar ? visible(sidebar) : false,
          navToggleVisible: navToggle ? visible(navToggle) : false,
        };
      });
      const status = response ? response.status() : 0;
      report.pages.push({ ...pageDefinition, viewport: viewport.name, status, ...audit });
      if (status >= 400) report.failures.push(`${routeKey} returned ${status}`);
      if (audit.djangoError) report.failures.push(`${routeKey} displayed a Django error`);
      if (audit.overflowX) {
        report.failures.push(`${routeKey} has body-level horizontal overflow`);
      }
      if (audit.pageIsLong && !audit.pageCanScrollVertically) {
        report.failures.push(`${routeKey} is long but cannot scroll vertically`);
      }
      if (audit.pageIsLong && audit.rootOverflowY === "hidden") {
        report.failures.push(`${routeKey} hides the page-level vertical scrollbar`);
      }
      if (audit.sidebarNeedsScroll && !audit.sidebarCanScroll) {
        report.failures.push(`${routeKey} has clipped sidebar navigation`);
      }
      if (audit.unnamedControls.length) {
        report.failures.push(`${routeKey} has unnamed controls`);
      }
      if (audit.duplicateIds.length) {
        report.failures.push(`${routeKey} has duplicate ids`);
      }
      if (audit.duplicateNavigation.length) {
        report.failures.push(`${routeKey} has duplicate primary navigation destinations`);
      }
      if (audit.emptyLinks.length) {
        report.failures.push(`${routeKey} has visible links without destinations`);
      }
      if (audit.brokenAnchors.length) {
        report.failures.push(`${routeKey} has broken in-page anchor links`);
      }
      if (audit.h1Count !== 1) {
        report.failures.push(`${routeKey} has ${audit.h1Count} visible h1 elements`);
      }
      if (audit.activeNavigation.length !== 1) {
        report.failures.push(
          `${routeKey} has ${audit.activeNavigation.length} active navigation items`,
        );
      }
      if (
        viewport.width <= 768 &&
        (!audit.navToggleVisible || audit.sidebarVisible)
      ) {
        report.failures.push(
          `${routeKey} mobile navigation is not closed with a visible toggle`,
        );
      }
      await page.screenshot({
        path: path.join(
          outputRoot,
          `${safeName(pageDefinition.name)}-${viewport.name}.png`,
        ),
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
  if (report.pageErrors.length) {
    report.failures.push(`${report.pageErrors.length} page error(s)`);
  }
  if (report.assetFailures.length) {
    report.failures.push(`${report.assetFailures.length} failed static asset response(s)`);
  }
  fs.writeFileSync(
    path.join(outputRoot, "validation-report.json"),
    JSON.stringify(report, null, 2),
  );
  console.log(
    JSON.stringify({ pages: report.pages.length, failures: report.failures }, null, 2),
  );
  if (report.failures.length) process.exitCode = 1;
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
