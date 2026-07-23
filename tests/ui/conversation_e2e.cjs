const { execFile } = require("child_process");
const fs = require("fs");
const { promisify } = require("util");
const { chromium } = require("playwright");

const execFileAsync = promisify(execFile);
const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const username = "conversation-e2e";
const password = "Vh-Conversation-E2E-2026!";
const failureScreenshot = "/tmp/vh-ui/screenshots/conversation-e2e-failure.png";
const serverLog = "/tmp/vh-ui/server.log";

let browser;
let page;

(async () => {
  try {
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
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
    const assistantMessages = page.locator(".vh-chat-message.is-assistant .vh-message-copy");
    await input.fill("Scan http://10.0.11.34:8010/ using the passive profile");
    await send.click();
    await page.getByText(/Review and confirm the plan below/i).waitFor({ timeout: 15000 });
    await page.locator("[data-inline-approval]").waitFor({ state: "visible", timeout: 15000 });
    const runId = await page.locator("[data-run-card]").getAttribute("data-run-id");
    if (!runId) throw new Error("The conversation did not expose an authoritative run id");

    await input.fill("Confirm");
    await send.click();
    await assistantMessages
      .filter({ hasText: /Approved\. Starting the governed assessment/ })
      .last()
      .waitFor({ timeout: 15000 });
    const workerResult = await execFileAsync("python", [
      "tests/ui/complete_conversation_run.py",
      "--run-id",
      runId,
    ]);
    if (workerResult.stderr) {
      fs.appendFileSync(serverLog, `\n--- Browser E2E worker stderr ---\n${workerResult.stderr}\n`);
    }
    await assistantMessages
      .filter({ hasText: /^Running passive checks…$/ })
      .last()
      .waitFor({ timeout: 15000 });
    await assistantMessages
      .filter({ hasText: /^Verifying one possible finding…$/ })
      .last()
      .waitFor({ timeout: 15000 });
    await assistantMessages
      .filter({ hasText: /Analysis complete in/ })
      .last()
      .waitFor({ timeout: 20000 });

    await input.fill("Show me the results");
    await send.click();
    const results = assistantMessages.last();
    await results.waitFor({ timeout: 10000 });
    const resultsCopy = await results.textContent();
    if (!resultsCopy || !resultsCopy.includes("Missing X-Content-Type-Options")) {
      throw new Error(`Results reply was not evidence-specific: ${resultsCopy}`);
    }

    await input.fill("Next step");
    await send.click();
    const next = assistantMessages.last();
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
  } catch (error) {
    const detail = error && error.stack ? error.stack : String(error);
    console.error(detail);
    fs.appendFileSync(serverLog, `\n\n--- Conversational E2E failure ---\n${detail}\n`);
    if (page) {
      fs.mkdirSync("/tmp/vh-ui/screenshots", { recursive: true });
      await page.screenshot({ path: failureScreenshot, fullPage: true }).catch(() => undefined);
    }
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
  }
})();
