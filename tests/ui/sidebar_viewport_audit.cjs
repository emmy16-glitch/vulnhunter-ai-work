const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
const outputRoot = process.env.VULNHUNTER_UI_OUTPUT || "/tmp/vulnhunter-ui-audit";
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const persona = manifest.personas.admin;
const viewports = [
  { name: "reference-1672", width: 1672, height: 941 },
  { name: "desktop-1440", width: 1440, height: 900 },
  { name: "tablet-1024", width: 1024, height: 768 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "mobile-390", width: 390, height: 844 },
  { name: "mobile-360", width: 360, height: 800 },
];

(async () => {
  fs.mkdirSync(outputRoot, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const failures = [];
  const results = [];

  for (const viewport of viewports) {
    const context = await browser.newContext({
      viewport,
      colorScheme: "dark",
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    await page.goto(`${baseUrl}/login/`, { waitUntil: "load" });
    await page.getByLabel("Username").fill(persona.username);
    await page.getByLabel("Password").fill(persona.password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);
    await page.waitForTimeout(150);

    const state = await page.evaluate(() => {
      const sidebar = document.querySelector("[data-sidebar]");
      const toggle = document.querySelector("[data-nav-toggle]");
      const navLinks = [...document.querySelectorAll(".vh-nav-list a")];
      const current = document.querySelector('.vh-nav-list a[aria-current="page"]');
      const brand = document.querySelector(".vh-brand strong");
      const organisation = document.querySelector(".vh-organisation strong");
      const visibleInViewport = (element) => {
        if (!element) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          Number(style.opacity || "1") > 0 &&
          rect.width > 0 &&
          rect.height > 0 &&
          rect.right > 0 &&
          rect.bottom > 0 &&
          rect.left < innerWidth &&
          rect.top < innerHeight
        );
      };
      const hitTarget = current
        ? document.elementFromPoint(
            current.getBoundingClientRect().left + 12,
            current.getBoundingClientRect().top + current.getBoundingClientRect().height / 2,
          )
        : null;
      return {
        sidebarVisible: visibleInViewport(sidebar),
        toggleVisible: visibleInViewport(toggle),
        visibleNavigationCount: navLinks.filter(visibleInViewport).length,
        currentNavigation: current?.textContent.trim() || "",
        currentNavigationVisible: visibleInViewport(current),
        currentNavigationReceivesPointer:
          Boolean(current && hitTarget && (hitTarget === current || current.contains(hitTarget))),
        brandVisible: visibleInViewport(brand),
        organisationVisible: visibleInViewport(organisation),
      };
    });

    if (viewport.width >= 1024) {
      if (!state.sidebarVisible) failures.push(`${viewport.name}: sidebar is not visible`);
      if (state.toggleVisible) failures.push(`${viewport.name}: desktop toggle should be hidden`);
      if (state.visibleNavigationCount < 10) {
        failures.push(`${viewport.name}: only ${state.visibleNavigationCount} navigation links are visible`);
      }
      if (state.currentNavigation !== "Dashboard" || !state.currentNavigationVisible) {
        failures.push(`${viewport.name}: Dashboard navigation is not visibly active`);
      }
      if (!state.currentNavigationReceivesPointer) {
        failures.push(`${viewport.name}: active navigation does not receive pointer input`);
      }
      if (!state.brandVisible || !state.organisationVisible) {
        failures.push(`${viewport.name}: sidebar identity text is not visible`);
      }
    } else {
      if (!state.toggleVisible || state.sidebarVisible) {
        failures.push(`${viewport.name}: mobile drawer does not start closed`);
      }
      const toggle = page.locator("[data-nav-toggle]");
      const sidebar = page.locator("[data-sidebar]");
      const scrim = page.locator("[data-nav-close]");
      await toggle.click();
      if (!(await sidebar.isVisible()) || (await toggle.getAttribute("aria-expanded")) !== "true") {
        failures.push(`${viewport.name}: mobile drawer did not open`);
      }
      const visibleLinks = await sidebar.locator(".vh-nav-list a").evaluateAll((links) =>
        links.filter((element) => {
          const rect = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
        }).length,
      );
      if (visibleLinks < 3) failures.push(`${viewport.name}: mobile navigation links are not visible`);
      const scrimBox = await scrim.boundingBox();
      if (!scrimBox) {
        failures.push(`${viewport.name}: mobile backdrop is not visible`);
      } else {
        await scrim.click({
          position: {
            x: Math.max(2, scrimBox.width - 8),
            y: Math.min(100, Math.max(2, scrimBox.height - 8)),
          },
        });
      }
      if ((await toggle.getAttribute("aria-expanded")) !== "false" || (await sidebar.isVisible())) {
        failures.push(`${viewport.name}: mobile backdrop did not close the drawer`);
      }
    }

    await page.screenshot({
      path: path.join(outputRoot, `sidebar-viewport-${viewport.name}.png`),
      fullPage: false,
    });
    results.push({ viewport: viewport.name, ...state });
    await context.close();
  }

  await browser.close();
  fs.writeFileSync(
    path.join(outputRoot, "sidebar-viewport-report.json"),
    JSON.stringify({ results, failures }, null, 2),
  );
  console.log(JSON.stringify({ checks: results.length, failures }, null, 2));
  if (failures.length) process.exitCode = 1;
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
