const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const username = process.env.VULNHUNTER_UI_USERNAME || "conversation-e2e";
const password = process.env.VULNHUNTER_UI_PASSWORD || "Vh-Conversation-E2E-2026!";

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.VULNHUNTER_CHROME_PATH || "/usr/bin/chromium",
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  let submittedBody = "";
  let messageRequests = 0;

  try {
    await page.on("request", (request) => {
      if (request.url().includes("/workspace/message/")) messageRequests += 1;
    });
    await page.route("**/workspace/public-consent/verify/", async (route) => {
      submittedBody = route.request().postData() || "";
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          authorization: {
            id: "auth-browser-public",
            target_url: "https://public.test/community/",
            expires_at: "2026-08-26T12:00:00+00:00",
            passive_only: true,
            consent_url: "https://public.test/.well-known/vulnhunter-consent.json",
            consent_sha256: "a".repeat(64),
          },
          message: "Public consent verified. The target is authorized for bounded passive mapping only.",
        }),
      });
    });

    await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);

    await page.locator("[data-conversation-workspace]").waitFor({ timeout: 15000 });
    const panel = page.locator("[data-public-consent-panel]");
    await panel.locator("summary").click();
    await panel.locator('[name="target_url"]').fill("https://public.test/community/");
    await panel.locator('[name="challenge_token"]').fill("consent-token-0123456789");
    await panel.locator('[name="owner"]').fill("Public Test Owner");
    await panel.locator('[name="approved_by"]').fill("Browser Approver");
    await panel.locator('[name="purpose"]').fill("Bounded passive mapping");
    await panel.locator('[name="expires_at"]').fill("2026-08-26T12:00");
    await panel.getByRole("button", { name: "Verify consent" }).click();

    await panel
      .locator("[data-public-consent-status]")
      .filter({ hasText: /Verified for passive mapping/i })
      .waitFor({ timeout: 10000 });
    if (!/public\.test/.test(submittedBody) || !/consent-token-0123456789/.test(submittedBody)) {
      throw new Error(`Consent form did not submit the expected mock target and token: ${submittedBody}`);
    }
    if (await panel.getByRole("button", { name: "Verify consent" }).isDisabled()) {
      throw new Error("Consent submit control remained disabled after the response completed");
    }
    if (messageRequests !== 0) {
      throw new Error(`Consent verification unexpectedly started ${messageRequests} conversation request(s)`);
    }
    console.log("Public consent workspace acceptance passed.");
  } finally {
    await browser.close();
  }
})();
