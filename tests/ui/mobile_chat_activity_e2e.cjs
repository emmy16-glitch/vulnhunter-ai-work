const fs = require("fs");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const persona = manifest.personas.admin;

const attachment = {
  attachment_id: "attachment-browser-0123456789",
  kind: "android_apk",
  artifact_id: "apk-browser-0123456789abcdef",
  artifact_sha256: "b".repeat(64),
  original_filename: "browser-demo.apk",
  size_bytes: 128,
  archive_entry_count: 3,
  dex_count: 1,
  native_library_count: 0,
  native_abis: [],
};
const plan = {
  run_id: "mobile-browser-demo",
  plan_id: "analysis-browser-demo",
  plan_digest: "a".repeat(64),
  profile: "static",
  requested_profile: "static",
  tool_count: 3,
  tools: [{ name: "JADX", tool_id: "jadx", gate: "policy" }],
  rounds: [{ altitude: "artifact", label: "APK identity", purpose: "Inspect the package envelope", status: "planned" }],
  dynamic_deferred: false,
  execution: { state: "gated", reason: "Static worker is not activated in this preview." },
};

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
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.VULNHUNTER_CHROME_PATH || "/usr/bin/chromium",
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  try {
    await login(page);
    await page.route("**/workspace/uploads/start/", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          upload_id: "upload-browser-demo",
          chunk_url: "/workspace/uploads/upload-browser-demo/chunk/",
          status_url: "/workspace/uploads/upload-browser-demo/status/",
          cancel_url: "/workspace/uploads/upload-browser-demo/cancel/",
          chunk_bytes: 1024,
          maximum_bytes: 10_000_000,
        }),
      });
    });
    await page.route("**/workspace/uploads/upload-browser-demo/chunk/", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          upload_id: "upload-browser-demo",
          received_bytes: 128,
          expected_bytes: 128,
          complete: false,
          attachment,
        }),
      });
    });
    await page.route("**/workspace/mobile-message/", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          attachment,
          mobile_plan: plan,
          message: {
            role: "assistant",
            kind: "mobile_plan",
            content: "I prepared the APK assessment and selected the safe static tools first.",
            metadata: { mobile_plan: plan, attachment },
          },
        }),
      });
    });
    await page.route("**/workspace/mobile-activity/**/stream/**", async (route) => {
      const event = {
        run_id: plan.run_id,
        events: [
          {
            event_id: "evt_0123456789abcdef01234567",
            sequence: 1,
            event_type: "plan_proposed",
            summary: "The governed APK assessment plan is ready.",
            timestamp: "2026-08-19T12:00:00+00:00",
            metadata: { profile: "static" },
          },
        ],
        last_sequence: 1,
        run_state: "planning",
        terminal: false,
      };
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: `retry: 1500\nid: 1\nevent: activity\ndata: ${JSON.stringify(event)}\n\n`,
      });
    });

    await page.goto(`${baseUrl}/`, { waitUntil: "domcontentloaded" });
    await page.locator("[data-conversation-form]").waitFor({ state: "visible" });
    await page.locator("[data-conversation-file]").setInputFiles({
      name: "browser-demo.apk",
      mimeType: "application/vnd.android.package-archive",
      buffer: Buffer.alloc(128, 0x41),
    });
    await page.locator("[data-attachment-tray]").getByText("browser-demo.apk").waitFor();
    await page.locator("[data-conversation-input]").fill("Scan this APK and check for vulnerabilities");
    await page.getByRole("button", { name: "Send message" }).click();

    await page.getByText("I prepared the APK assessment and selected the safe static tools first.").waitFor();
    await page.getByText("The governed APK assessment plan is ready.").waitFor();
    const feedText = await page.locator("[data-conversation-feed]").textContent();
    if (!/browser-demo\.apk/i.test(feedText || "")) throw new Error("The uploaded APK was not shown in the chat feed");
    if (!/JADX/i.test(feedText || "")) throw new Error("The selected safe tool was not shown in the chat feed");
    if (!/plan is ready/i.test(feedText || "")) throw new Error("The persisted APK activity was not shown in the chat feed");
    console.log("Unified APK chat activity acceptance passed.");
  } finally {
    await browser.close();
  }
})();

