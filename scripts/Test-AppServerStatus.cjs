const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appPath = path.join(__dirname, "..", "app.js");
const context = {
  Date,
  Intl,
  console,
  document: undefined,
  module: { exports: {} }
};
vm.runInNewContext(fs.readFileSync(appPath, "utf8"), context, { filename: appPath });

const { formatServerStatus, getEffectiveServerStatus } = context.module.exports;
const now = new Date("2026-07-09T14:30:00Z");

assert.equal(formatServerStatus("online"), "Online");
assert.equal(getEffectiveServerStatus({ status: "online", updatedAt: "2026-07-09T13:30:00Z" }, now), "online");
assert.equal(getEffectiveServerStatus({ status: "online", updatedAt: "2026-07-09T13:19:59Z" }, now), "offline");
assert.equal(getEffectiveServerStatus({ status: "online", updatedAt: "" }, now), "offline");
assert.equal(getEffectiveServerStatus({ status: "maintenance" }, now), "maintenance");

console.log("App server status tests passed.");
