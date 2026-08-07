const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(
  "vulnhunter/web/static/web/conversation-runtime-compat.js",
  "utf8",
);
const context = vm.createContext({});
vm.runInContext(source, context);

const result = vm.runInContext(
  '" ".join("What can you do??".toLowerCase().split())',
  context,
);

if (result !== "what can you do??") {
  throw new Error(`Chat normalizer returned ${JSON.stringify(result)}`);
}
if (!source.includes("conversation-upload-recovery.js")) {
  throw new Error("Conversation runtime does not load the APK upload recovery bridge");
}

const recoverySource = fs.readFileSync(
  "vulnhunter/web/static/web/conversation-upload-recovery.js",
  "utf8",
);

const fakeResponse = (payload) => ({
  ok: true,
  clone() {
    return fakeResponse(payload);
  },
  async json() {
    return payload;
  },
});

const uploadInit = (offset = 0) => ({
  method: "POST",
  credentials: "same-origin",
  headers: { "X-VulnHunter-Thread": "thread-1" },
  body: {
    get(name) {
      return name === "offset" ? String(offset) : null;
    },
  },
});

const installRecovery = (fetchImpl) => {
  const window = {
    fetch: fetchImpl,
    location: { href: "https://testserver/workspace/" },
  };
  const recoveryContext = vm.createContext({ window, URL });
  vm.runInContext(recoverySource, recoveryContext);
  return recoveryContext.window;
};

(async () => {
  const committedCalls = [];
  const committedStatus = fakeResponse({
    upload: { complete: true, received_bytes: 128, expected_bytes: 128 },
  });
  const committedWindow = installRecovery(async (input, init = {}) => {
    committedCalls.push([String(input), String(init.method || "GET").toUpperCase()]);
    if (String(init.method || "GET").toUpperCase() === "POST") {
      throw new Error("response lost after commit");
    }
    return committedStatus;
  });
  const recovered = await committedWindow.fetch(
    "/workspace/uploads/upload-1/chunk/",
    uploadInit(64),
  );
  if (recovered !== committedStatus) {
    throw new Error("Committed final APK chunk was not recovered from the status receipt");
  }
  if (
    committedCalls.length !== 2 ||
    committedCalls[1][0] !== "https://testserver/workspace/uploads/upload-1/status/" ||
    committedCalls[1][1] !== "GET"
  ) {
    throw new Error(`Unexpected committed-chunk recovery calls: ${JSON.stringify(committedCalls)}`);
  }

  const retryCalls = [];
  const retrySuccess = fakeResponse({ received_bytes: 64, expected_bytes: 128, complete: false });
  let postAttempts = 0;
  const retryWindow = installRecovery(async (input, init = {}) => {
    const method = String(init.method || "GET").toUpperCase();
    retryCalls.push([String(input), method]);
    if (method === "GET") {
      return fakeResponse({ received_bytes: 0, expected_bytes: 128, complete: false });
    }
    postAttempts += 1;
    if (postAttempts === 1) throw new Error("request failed before commit");
    return retrySuccess;
  });
  const retried = await retryWindow.fetch(
    "/workspace/uploads/upload-2/chunk/",
    uploadInit(0),
  );
  if (retried !== retrySuccess || postAttempts !== 2) {
    throw new Error("Uncommitted APK chunk was not retried exactly once");
  }
  if (retryCalls.length !== 3 || retryCalls[1][1] !== "GET" || retryCalls[2][1] !== "POST") {
    throw new Error(`Unexpected bounded retry calls: ${JSON.stringify(retryCalls)}`);
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
