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
      await page.locator("[data-conversation-form]").waitFor({ state: "visible" });

      const layout = await page.evaluate(() => {
        const composer = document.querySelector("[data-conversation-form]");
        const reasoning = document.querySelector("[data-reasoning-effort]");
        const provider = document.querySelector("[data-provider-runtime]");
        if (!composer || !reasoning || !provider) return { missing: true };

        const dock = document.createElement("div");
        dock.className = "vh-background-upload-dock";
        dock.innerHTML = `
          <article class="vh-background-upload is-failed">
            <div><strong>Phone acceptance.apk</strong><small>Upload needs attention</small><progress max="1" value="0"></progress></div>
            <div><button type="button">Retry</button><button type="button">Cancel</button></div>
          </article>`;
        document.body.append(dock);

        const composerRect = composer.getBoundingClientRect();
        const dockRect = dock.getBoundingClientRect();
        const reasoningRect = reasoning.getBoundingClientRect();
        const providerRect = provider.getBoundingClientRect();
        const options = [...reasoning.options].map((option) => option.textContent.trim());
        const overlapsComposer = !(
          dockRect.bottom <= composerRect.top + 1 ||
          dockRect.top >= composerRect.bottom - 1
        );
        const result = {
          missing: false,
          innerWidth: window.innerWidth,
          composerVisible: composerRect.width > 0 && composerRect.height > 0,
          composerInsideViewport:
            composerRect.left >= -1 &&
            composerRect.right <= window.innerWidth + 1 &&
            composerRect.bottom <= window.innerHeight + 1,
          reasoningVisible: reasoningRect.width >= 80 && reasoningRect.height >= 38,
          reasoningOptions: options,
          providerVisible: providerRect.width > 0 && providerRect.height > 0,
          dockVisible: dockRect.width > 0 && dockRect.height > 0,
          dockInsideViewport:
            dockRect.left >= -1 &&
            dockRect.right <= window.innerWidth + 1 &&
            dockRect.top >= -1 &&
            dockRect.bottom <= window.innerHeight + 1,
          overlapsComposer,
        };
        dock.remove();
        return result;
      });

      if (layout.missing) throw new Error(`Phone controls are missing at ${viewport.width}px`);
      if (layout.innerWidth !== viewport.width) {
        throw new Error(`Viewport mismatch: expected ${viewport.width}, received ${layout.innerWidth}`);
      }
      if (!layout.composerVisible || !layout.composerInsideViewport) {
        throw new Error(`Composer is clipped at ${viewport.width}px: ${JSON.stringify(layout)}`);
      }
      if (!layout.reasoningVisible) {
        throw new Error(`Reasoning selector is not usable at ${viewport.width}px`);
      }
      if (layout.reasoningOptions.join(",") !== "Low,Medium,High") {
        throw new Error(`Reasoning options are incomplete: ${layout.reasoningOptions.join(",")}`);
      }
      if (!layout.providerVisible) {
        throw new Error(`Groq runtime status is hidden at ${viewport.width}px`);
      }
      if (!layout.dockVisible || !layout.dockInsideViewport || layout.overlapsComposer) {
        throw new Error(`Upload dock overlaps or leaves the viewport: ${JSON.stringify(layout)}`);
      }

      const startUrl = await page.locator("[data-conversation-form]").getAttribute("data-upload-start-url");
      if (!startUrl) throw new Error("Upload start URL is missing");
      const absoluteStartUrl = new URL(startUrl, baseUrl).toString();
      let startAttempts = 0;
      await page.route(absoluteStartUrl, async (route) => {
        startAttempts += 1;
        if (startAttempts === 1) {
          await route.fulfill({
            status: 403,
            contentType: "application/json",
            body: JSON.stringify({ detail: "Synthetic stale CSRF response" }),
          });
          return;
        }
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({
            upload_id: "phone-acceptance-upload",
            chunk_size: 4,
            offset: 0,
            status_url: "/__phone-upload-status__",
            chunk_url: "/__phone-upload-chunk__",
            complete_url: "/__phone-upload-complete__",
            cancel_url: "/__phone-upload-cancel__",
          }),
        });
      });

      await page.locator("[data-conversation-file]").setInputFiles({
        name: "phone-acceptance.apk",
        mimeType: "application/vnd.android.package-archive",
        buffer: Buffer.from("PK\u0003\u0004phone-acceptance"),
      });
      await page.waitForFunction(() => {
        const text = document.querySelector("[data-background-upload-dock]")?.textContent || "";
        return /Retry/.test(text);
      });
      if (startAttempts !== 2) {
        throw new Error(`Expected one automatic CSRF retry, observed ${startAttempts} start attempts`);
      }
      await page.getByRole("button", { name: "Cancel" }).last().click();
      await context.close();
    }
    console.log("Phone conversation, reasoning, upload recovery and layout acceptance passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
