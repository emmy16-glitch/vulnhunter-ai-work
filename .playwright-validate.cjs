const fs = require("fs");
const { chromium } = require("/tmp/vh-playwright/node_modules/playwright");

const baseUrl = "http://127.0.0.1:8767";
const executablePath = "/tmp/vh-playwright-browsers/chromium_headless_shell-1232/chrome-headless-shell-linux64/chrome-headless-shell";
const storageState = "/tmp/vh-ui-playwright-state.json";
const outputRoot = "/tmp/vh-playwright-output";
const viewports = [
  { name: "reference-1672", width: 1672, height: 941 },
  { name: "desktop-1440", width: 1440, height: 900 },
  { name: "desktop-1280", width: 1280, height: 800 },
  { name: "tablet-1024", width: 1024, height: 768 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "mobile-390", width: 390, height: 844 },
  { name: "mobile-360", width: 360, height: 800 },
];
const pages = [
  "/",
  "/agent/runs/",
  "/findings/",
  "/oracle/",
  "/approvals/",
  "/mobile-analysis/",
  "/reports/",
  "/governance/",
  "/settings/",
];

(async () => {
  fs.mkdirSync(outputRoot, { recursive: true });
  const browser = await chromium.launch({ executablePath, headless: true, chromiumSandbox: false });
  const report = { viewports: [], majorPages: [], assetResponses: {}, console: [], pageErrors: [] };

  for (const viewport of viewports) {
    const context = await browser.newContext({ viewport, storageState, colorScheme: "dark", reducedMotion: "reduce" });
    const page = await context.newPage();
    page.on("console", (message) => {
      if (["warning", "error"].includes(message.type())) report.console.push({ viewport: viewport.name, type: message.type(), text: message.text() });
    });
    page.on("pageerror", (error) => report.pageErrors.push({ viewport: viewport.name, text: error.message }));
    page.on("response", (response) => {
      const url = response.url();
      if (url.includes("/static/")) report.assetResponses[url.replace(baseUrl, "")] = response.status();
    });
    const response = await page.goto(`${baseUrl}/agent/runs/ui-reference-run/`, { waitUntil: "load" });
    await page.waitForTimeout(300);
    const audit = await page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
      };
      const controls = [...document.querySelectorAll("button, a, input, select, textarea, summary")].filter(visible);
      const unnamed = controls.filter((element) => {
        const id = element.getAttribute("id");
        const label = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null;
        return !(element.getAttribute("aria-label") || element.getAttribute("aria-labelledby") || element.textContent.trim() || element.getAttribute("title") || element.getAttribute("placeholder") || label?.textContent.trim());
      }).map((element) => element.outerHTML.slice(0, 180));
      const sidebar = document.querySelector(".vh-sidebar");
      const active = document.querySelector('.vh-nav-list a[aria-current="page"]');
      return {
        title: document.title,
        bodyScrollWidth: document.documentElement.scrollWidth,
        bodyClientWidth: document.documentElement.clientWidth,
        overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        sidebarHeight: sidebar ? Math.round(sidebar.getBoundingClientRect().height) : null,
        sidebarVisible: sidebar ? visible(sidebar) : false,
        activeNavigation: active?.textContent.trim() || null,
        unnamedControls: unnamed,
        headings: [...document.querySelectorAll("h1,h2,h3")].filter(visible).map((heading) => heading.textContent.trim()),
        requiredRegions: {
          workstream: Boolean(document.querySelector(".vh-workstream-panel")),
          approval: Boolean(document.querySelector(".vh-approval-inline")),
          inspector: Boolean(document.querySelector(".vh-inspector")),
          evidence: Boolean(document.querySelector(".vh-result-evidence")),
          attackPath: Boolean(document.querySelector(".vh-attack-path")),
        },
      };
    });
    report.viewports.push({ ...viewport, status: response?.status(), ...audit });
    await page.screenshot({ path: `${outputRoot}/${viewport.name}.png`, fullPage: false, timeout: 60000 });
    await context.close();
  }

  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, storageState, colorScheme: "dark" });
  const page = await context.newPage();
  for (const path of pages) {
    const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "load" });
    report.majorPages.push({ path, status: response?.status(), title: await page.title(), djangoError: await page.locator("body").getByText("Traceback", { exact: false }).count() > 0 });
  }
  await context.close();
  await browser.close();
  fs.writeFileSync(`${outputRoot}/validation-report.json`, JSON.stringify(report, null, 2));
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
