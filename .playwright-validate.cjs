const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
const outputRoot = process.env.VULNHUNTER_UI_OUTPUT || "/tmp/vulnhunter-ui-audit";
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const navigationTimeoutMs = Number(process.env.VULNHUNTER_UI_NAVIGATION_TIMEOUT_MS || 15000);
const actionTimeoutMs = Number(process.env.VULNHUNTER_UI_ACTION_TIMEOUT_MS || 10000);
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

function persistReport(report) {
  fs.writeFileSync(
    path.join(outputRoot, "validation-report.json"),
    JSON.stringify(report, null, 2),
  );
}

const report = {
  pages: [],
  modals: [],
  consoleErrors: [],
  pageErrors: [],
  assetFailures: [],
  failures: [],
};

(async () => {
  fs.mkdirSync(outputRoot, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const contextCache = new Map();

  async function contextFor(viewport, personaName) {
    const key = `${viewport.name}:${personaName}`;
    if (contextCache.has(key)) return contextCache.get(key);

    const context = await browser.newContext({
      viewport,
      colorScheme: "light",
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    page.setDefaultTimeout(actionTimeoutMs);
    page.setDefaultNavigationTimeout(navigationTimeoutMs);
    const persona = manifest.personas[personaName];
    const login = await page.goto(`${baseUrl}/login/`, {
      waitUntil: "domcontentloaded",
      timeout: navigationTimeoutMs,
    });
    if (!login || login.status() >= 400) {
      throw new Error(`Login page failed for ${personaName}`);
    }
    await page.getByLabel("Username").fill(persona.username);
    await page.getByLabel("Password").fill(persona.password);
    await Promise.all([
      page.waitForURL((url) => new URL(url).pathname !== "/login/", {
        waitUntil: "domcontentloaded",
        timeout: navigationTimeoutMs,
      }),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);
    await page.close();
    contextCache.set(key, context);
    return context;
  }

  for (const pageDefinition of manifest.pages) {
    const targets = pageDefinition.responsive ? viewports : [viewports[1]];
    for (const viewport of targets) {
      let context;
      try {
        context = await contextFor(viewport, pageDefinition.persona);
      } catch (error) {
        const routeKey = `${pageDefinition.name}:${viewport.name}`;
        report.failures.push(`${routeKey} login failed: ${error.message}`);
        report.pages.push({
          ...pageDefinition,
          viewport: viewport.name,
          status: 0,
          loginError: error.message,
        });
        persistReport(report);
        continue;
      }

      const page = await context.newPage();
      page.setDefaultTimeout(actionTimeoutMs);
      page.setDefaultNavigationTimeout(navigationTimeoutMs);
      const routeKey = `${pageDefinition.name}:${viewport.name}`;
      console.log(`Auditing ${routeKey}`);

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

      let response;
      try {
        response = await page.goto(`${baseUrl}${pageDefinition.path}`, {
          waitUntil: "domcontentloaded",
          timeout: navigationTimeoutMs,
        });
        await page.locator("body").waitFor({ state: "visible", timeout: actionTimeoutMs });
        await page.waitForTimeout(150);
      } catch (error) {
        report.failures.push(`${routeKey} navigation failed: ${error.message}`);
        report.pages.push({
          ...pageDefinition,
          viewport: viewport.name,
          status: 0,
          navigationError: error.message,
        });
        persistReport(report);
        await page.close();
        continue;
      }

      try {
        const openDialog = page.locator("dialog[open]").first();
        if ((await openDialog.count()) > 0) {
          const modalAudit = await openDialog.evaluate((dialog) => {
            const style = getComputedStyle(dialog);
            const rect = dialog.getBoundingClientRect();
            const controls = [
              ...dialog.querySelectorAll("button, a, input, select, textarea, summary"),
            ].filter((element) => {
              const elementStyle = getComputedStyle(element);
              const elementRect = element.getBoundingClientRect();
              return (
                elementStyle.display !== "none" &&
                elementStyle.visibility !== "hidden" &&
                elementRect.width > 0 &&
                elementRect.height > 0
              );
            });
            return {
              id: dialog.id || null,
              heading: dialog.querySelector("h1, h2, h3")?.textContent.trim() || "",
              visible:
                style.display !== "none" &&
                style.visibility !== "hidden" &&
                rect.width > 0 &&
                rect.height > 0,
              fitsViewport:
                rect.left >= -1 &&
                rect.top >= -1 &&
                rect.right <= window.innerWidth + 1 &&
                rect.bottom <= window.innerHeight + 1,
              width: Math.round(rect.width),
              height: Math.round(rect.height),
              viewportWidth: window.innerWidth,
              viewportHeight: window.innerHeight,
              controlCount: controls.length,
              closeControlVisible: Boolean(
                controls.find(
                  (element) =>
                    element.matches("[data-approval-close]") ||
                    /close|cancel|esc/i.test(
                      element.getAttribute("aria-label") || element.textContent || "",
                    ),
                ),
              ),
              overflowY: style.overflowY,
              contentScrollable:
                dialog.scrollHeight <= dialog.clientHeight + 1 ||
                ["auto", "scroll"].includes(style.overflowY),
            };
          });
          report.modals.push({ routeKey, ...modalAudit });
          if (!modalAudit.visible) {
            report.failures.push(`${routeKey} has an open modal that is not visible`);
          }
          if (!modalAudit.fitsViewport) {
            report.failures.push(`${routeKey} has an open modal outside the viewport`);
          }
          if (!modalAudit.heading) {
            report.failures.push(`${routeKey} has an open modal without a visible heading`);
          }
          if (modalAudit.controlCount < 1 || !modalAudit.closeControlVisible) {
            report.failures.push(`${routeKey} has an open modal without usable controls`);
          }
          if (!modalAudit.contentScrollable) {
            report.failures.push(`${routeKey} has clipped modal content`);
          }
          await openDialog.evaluate((dialog) => dialog.close());
          await page.waitForTimeout(75);
          if (await page.evaluate(() => Boolean(document.querySelector("dialog[open]")))) {
            report.failures.push(`${routeKey} modal could not be closed`);
          }
        }

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
          const intersectsViewport = (element) => {
            if (!element || !visible(element)) return false;
            const rect = element.getBoundingClientRect();
            return (
              rect.right > 1 &&
              rect.bottom > 1 &&
              rect.left < window.innerWidth - 1 &&
              rect.top < window.innerHeight - 1
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
          const sidebar = document.querySelector("[data-sidebar]");
          const sidebarNavigation = document.querySelector(".vh-chat-shell-scroll");
          const navToggle = document.querySelector("[data-nav-toggle]");
          const activeNavigation = [
            ...document.querySelectorAll('.vh-sidebar a[aria-current="page"]'),
          ];
          const primaryLinks = [...document.querySelectorAll(".vh-sidebar a[href]")];
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

          const conversationWorkspace = document.querySelector("[data-conversation-workspace]");
          const conversationScrollRegion = conversationWorkspace?.querySelector(
            "[data-conversation-feed]",
          );
          let conversationScrollContractValid = false;
          let conversationNeedsScroll = false;
          let conversationCanScroll = false;
          let conversationOverflowY = null;
          if (conversationScrollRegion) {
            const conversationStyle = getComputedStyle(conversationScrollRegion);
            conversationOverflowY = conversationStyle.overflowY;
            const ownsVerticalScroll = ["auto", "scroll"].includes(conversationOverflowY);
            const hasViewport = conversationScrollRegion.clientHeight > 0;
            conversationNeedsScroll =
              conversationScrollRegion.scrollHeight > conversationScrollRegion.clientHeight + 1;
            conversationCanScroll = ownsVerticalScroll && hasViewport;
            if (conversationNeedsScroll && conversationCanScroll) {
              const original = conversationScrollRegion.scrollTop;
              conversationScrollRegion.scrollTop = conversationScrollRegion.scrollHeight;
              await new Promise((resolve) => requestAnimationFrame(resolve));
              conversationCanScroll = conversationScrollRegion.scrollTop > original;
              conversationScrollRegion.scrollTop = original;
            }
            conversationScrollContractValid = ownsVerticalScroll && hasViewport && conversationCanScroll;
          }

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
            conversationWorkspace: Boolean(conversationWorkspace),
            conversationScrollContractValid,
            conversationNeedsScroll,
            conversationCanScroll,
            conversationOverflowY,
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
            sidebarVisibleInViewport: intersectsViewport(sidebar),
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
        if (audit.conversationWorkspace && !audit.conversationScrollContractValid) {
          report.failures.push(`${routeKey} has no usable conversation scroll region`);
        }
        const pageScrollRequired =
          audit.pageIsLong && !(audit.conversationWorkspace && audit.conversationScrollContractValid);
        if (pageScrollRequired && !audit.pageCanScrollVertically) {
          report.failures.push(`${routeKey} is long but cannot scroll vertically`);
        }
        if (pageScrollRequired && audit.rootOverflowY === "hidden") {
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
        if (audit.conversationWorkspace) {
          if (audit.activeNavigation.length > 1) {
            report.failures.push(
              `${routeKey} has ${audit.activeNavigation.length} active navigation items`,
            );
          }
        } else if (audit.activeNavigation.length !== 1) {
          report.failures.push(
            `${routeKey} has ${audit.activeNavigation.length} active navigation items`,
          );
        }
        if (
          viewport.width <= 768 &&
          (!audit.navToggleVisible || audit.sidebarVisibleInViewport)
        ) {
          report.failures.push(
            `${routeKey} mobile navigation is not closed off-canvas with a visible toggle`,
          );
        }

        await page.screenshot({
          path: path.join(
            outputRoot,
            `${safeName(pageDefinition.name)}-${viewport.name}.png`,
          ),
          fullPage: true,
          timeout: actionTimeoutMs,
        });
      } catch (error) {
        report.failures.push(`${routeKey} audit failed: ${error.message}`);
      } finally {
        persistReport(report);
        await page.close();
      }
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
  persistReport(report);
  console.log(
    JSON.stringify(
      {
        pages: report.pages.length,
        modals: report.modals.length,
        failures: report.failures,
      },
      null,
      2,
    ),
  );
  if (report.failures.length) process.exitCode = 1;
})().catch((error) => {
  report.failures.push(`Fatal browser audit failure: ${error.message}`);
  persistReport(report);
  console.error(error);
  process.exitCode = 1;
});
