const fs = require("fs");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const persona = manifest.personas.admin;
const viewports = [
  { width: 390, height: 844 },
  { width: 360, height: 800 },
];

async function login(page) {
  await page.goto(`${baseUrl}/login/`, { waitUntil: "domcontentloaded" });
  await page.getByLabel("Username").fill(persona.username);
  await page.getByLabel("Password").fill(persona.password);
  await Promise.all([
    page.waitForURL((url) => new URL(url).pathname !== "/login/"),
    page.getByRole("button", { name: /sign in securely/i }).click(),
  ]);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const viewport of viewports) {
      const context = await browser.newContext({ viewport, colorScheme: "dark" });
      const page = await context.newPage();
      await login(page);
      await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });

      const form = page.locator("[data-conversation-form]");
      const input = page.locator("[data-conversation-input]");
      const trigger = page.locator("[data-composer-tools-trigger]");
      const clear = page.locator("[data-composer-clear]");
      const counter = page.locator("[data-composer-counter]");
      const menu = page.locator("[data-composer-prompt-menu]");
      const empty = page.locator("[data-composer-prompt-empty]");
      await form.waitFor({ state: "visible" });
      await trigger.waitFor({ state: "visible" });
      await counter.waitFor({ state: "visible" });

      const initialCounter = await counter.textContent();
      if (!/^0\s*\/\s*4,?000$/.test((initialCounter || "").trim())) {
        throw new Error(`Unexpected empty composer counter: ${initialCounter}`);
      }
      if (!(await clear.isHidden())) {
        throw new Error("Clear prompt should remain hidden while the composer is empty");
      }

      const userMessageCount = await page.locator(".vh-chat-message.is-user").count();
      const runCardCount = await page.locator("[data-run-card]").count();
      let messagePosts = 0;
      page.on("request", (request) => {
        const action = new URL(request.url(), baseUrl);
        const formAction = new URL(page.url());
        if (
          request.method() === "POST" &&
          action.pathname.includes("conversation") &&
          action.pathname !== formAction.pathname
        ) {
          messagePosts += 1;
        }
      });

      await trigger.click();
      await menu.waitFor({ state: "visible" });
      if ((await trigger.getAttribute("aria-expanded")) !== "true") {
        throw new Error("Prompt menu trigger did not expose its expanded state");
      }

      const menuGeometry = await menu.evaluate((element) => {
        const rect = element.getBoundingClientRect();
        return {
          left: rect.left,
          right: rect.right,
          top: rect.top,
          bottom: rect.bottom,
          width: rect.width,
          height: rect.height,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          stylesLoaded: Boolean(document.querySelector("link[data-composer-tools-styles]")),
        };
      });
      if (
        !menuGeometry.stylesLoaded ||
        menuGeometry.width <= 0 ||
        menuGeometry.height <= 0 ||
        menuGeometry.left < -1 ||
        menuGeometry.right > menuGeometry.innerWidth + 1 ||
        menuGeometry.top < -1 ||
        menuGeometry.bottom > menuGeometry.innerHeight + 1
      ) {
        throw new Error(`Prompt menu leaves the phone viewport: ${JSON.stringify(menuGeometry)}`);
      }

      const options = await menu.locator("[data-prompt-value]").allTextContents();
      const expectedLabels = [
        "Website assessment",
        "APK analysis",
        "Source review",
        "Explain findings",
        "Status and next step",
      ];
      for (const label of expectedLabels) {
        if (!options.some((copy) => copy.includes(label))) {
          throw new Error(`Starter prompt is missing: ${label}`);
        }
      }

      await menu.getByRole("button", { name: /status and next step/i }).click();
      await menu.waitFor({ state: "hidden" });
      const inserted = await input.inputValue();
      if (!inserted.includes("Summarise the current workspace status")) {
        throw new Error(`Starter prompt was not inserted: ${inserted}`);
      }
      if (!(await clear.isVisible())) {
        throw new Error("Clear prompt did not appear after inserting a starter prompt");
      }
      const populatedCounter = (await counter.textContent()) || "";
      const expectedLength = inserted.length.toLocaleString();
      if (!populatedCounter.startsWith(`${expectedLength} /`)) {
        throw new Error(`Composer count does not match inserted prompt: ${populatedCounter}`);
      }
      if ((await page.locator(".vh-chat-message.is-user").count()) !== userMessageCount) {
        throw new Error("Choosing a starter prompt submitted a user message automatically");
      }
      if ((await page.locator("[data-run-card]").count()) !== runCardCount) {
        throw new Error("Choosing a starter prompt started an assessment automatically");
      }
      if (messagePosts !== 0) {
        throw new Error(`Choosing a starter prompt made ${messagePosts} unexpected POST request(s)`);
      }

      await clear.click();
      if ((await input.inputValue()) !== "") {
        throw new Error("Clear prompt did not empty the composer");
      }
      await clear.waitFor({ state: "hidden" });
      const clearedCounter = await counter.textContent();
      if (!/^0\s*\/\s*4,?000$/.test((clearedCounter || "").trim())) {
        throw new Error(`Composer counter did not reset: ${clearedCounter}`);
      }

      await input.fill("/status");
      await menu.waitFor({ state: "visible" });
      if ((await menu.getAttribute("data-opened-by-slash")) !== "true") {
        throw new Error("Typing a slash command did not mark the filtered prompt menu");
      }
      const visibleSlashOptions = menu.locator("[data-prompt-value]:visible");
      if ((await visibleSlashOptions.count()) !== 1) {
        throw new Error(`Expected one /status match, found ${await visibleSlashOptions.count()}`);
      }
      if (!((await visibleSlashOptions.first().textContent()) || "").includes("Status and next step")) {
        throw new Error("The /status filter did not select the status starter prompt");
      }
      if (!(await empty.isHidden())) {
        throw new Error("The no-results state appeared while /status had a match");
      }
      await page.keyboard.press("Enter");
      await menu.waitFor({ state: "hidden" });
      const slashInserted = await input.inputValue();
      if (!slashInserted.includes("Summarise the current workspace status")) {
        throw new Error(`Enter did not insert the /status prompt: ${slashInserted}`);
      }
      if (slashInserted.startsWith("/status")) {
        throw new Error("The slash command text was not replaced by the starter prompt");
      }
      if (messagePosts !== 0 || (await page.locator(".vh-chat-message.is-user").count()) !== userMessageCount) {
        throw new Error("Selecting /status submitted the prompt instead of inserting it");
      }
      await clear.click();
      await clear.waitFor({ state: "hidden" });

      await input.fill("/does-not-exist");
      await menu.waitFor({ state: "visible" });
      if ((await menu.locator("[data-prompt-value]:visible").count()) !== 0) {
        throw new Error("An unmatched slash command left prompt options visible");
      }
      await empty.waitFor({ state: "visible" });
      await page.keyboard.press("Escape");
      await menu.waitFor({ state: "hidden" });
      if ((await trigger.getAttribute("aria-expanded")) !== "false") {
        throw new Error("Escape did not close the slash-filtered prompt menu accessibly");
      }
      if ((await input.inputValue()) !== "/does-not-exist") {
        throw new Error("Closing an unmatched slash command unexpectedly rewrote the composer");
      }
      await clear.click();

      await trigger.click();
      await menu.waitFor({ state: "visible" });
      await page.keyboard.press("Escape");
      await menu.waitFor({ state: "hidden" });
      if ((await trigger.getAttribute("aria-expanded")) !== "false") {
        throw new Error("Escape did not close the prompt menu accessibly");
      }

      if (messagePosts !== 0) {
        throw new Error(`Composer tools made ${messagePosts} unexpected POST request(s)`);
      }
      await context.close();
    }
    console.log(
      "Phone prompt menu, slash filtering, safe insertion, character counter and clear prompt acceptance passed.",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});