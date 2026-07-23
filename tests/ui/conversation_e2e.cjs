const { execFile } = require("child_process");
const { promisify } = require("util");
const { chromium } = require("playwright");

const execFileAsync = promisify(execFile);
const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const username = "visual-admin";
const password = "Vh-Visual-Audit-2026!";

let browser;

(async () => {
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
    const consoleErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await Promise.all([
      page.waitForURL(`${baseUrl}/`),
      page.getByRole("button", { name: /sign in securely/i }).click(),
    ]);
    const input = page.locator("[data-conversation-input]");
    const send = page.locator("[data-conversation-send]");
    await input.fill("Scan http://10.0.11.34:8010/ using the passive profile");
    await send.click();
    await page.getByText(/Review and confirm the plan below/i).waitFor({ timeout: 15000 });
    await page.locator("[data-inline-approval]").waitFor({ state: "visible", timeout: 15000 });
    const runId = await page.locator("[data-run-card]").getAttribute("data-run-id");
    if (!runId) throw new Error("The conversation did not expose an authoritative run id");

    await input.fill("Confirm");
    await send.click();
    await page.getByText(/Approved\. Starting the governed assessment/i).waitFor({ timeout: 15000 });
    const worker = execFileAsync("python", [
      "tests/ui/complete_conversation_run.py",
      "--run-id",
      runId,
    ]);
    await page.getByText(/Running passive checks/i).waitFor({ timeout: 15000 });
    await page.getByText(/Verifying one possible finding/i).waitFor({ timeout: 15000 });
    await page.getByText(/Analysis complete in/i).waitFor({ timeout: 20000 });
    await worker;

    await input.fill("Show me the results");
    await send.click();
    const results = page.locator(".vh-chat-message.is-assistant .vh-message-copy").last();
    await results.waitFor({ timeout: 10000 });
    const resultsCopy = await results.textContent();
    if (!resultsCopy || !resultsCopy.includes("Missing X-Content-Type-Options")) {
      throw new Error(`Results reply was not evidence-specific: ${resultsCopy}`);
    }

    await input.fill("Next step");
    await send.click();
    const next = page.locator(".vh-chat-message.is-assistant .vh-message-copy").last();
    await next.waitFor({ timeout: 10000 });
    const nextCopy = await next.textContent();
    if (!nextCopy || nextCopy === resultsCopy || !/evidence|remediation|retest/i.test(nextCopy)) {
      throw new Error(`Next-step reply was not distinct and actionable: ${nextCopy}`);
    }

    const technicalOpen = await page.locator('details[data-section="technical"]').evaluate(
      (element) => element.open,
    );
    if (technicalOpen) throw new Error("Technical details must remain collapsed by default");
    if (consoleErrors.length) throw new Error(`Browser console errors: ${consoleErrors.join(" | ")}`);
    console.log(JSON.stringify({ runId, resultsCopy, nextCopy }));
  } finally {
    if (browser) await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
