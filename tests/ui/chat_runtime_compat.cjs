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
