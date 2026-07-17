import assert from "node:assert/strict";

process.env.SITE_ACCESS_PASSWORD = "temporary-test-password";
process.env.SITE_ACCESS_SIGNING_KEY = "temporary-test-signing-key-32-bytes-minimum";

const { default: middleware, createSessionToken, verifySessionToken } = await import("../middleware.js");

const rootRequest = new Request("https://shinobionline.vercel.app/");
const loginResponse = await middleware(rootRequest);
assert.equal(loginResponse.status, 401);
assert.doesNotMatch(await loginResponse.text(), /temporary-test-password/);

const wrongRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: "password=wrong"
});
assert.equal((await middleware(wrongRequest)).status, 404);

const correctRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: "password=temporary-test-password"
});
const correctResponse = await middleware(correctRequest);
assert.equal(correctResponse.status, 303);
assert.match(correctResponse.headers.get("set-cookie"), /^shinobi_site_access=/);

const sessionToken = await createSessionToken(process.env.SITE_ACCESS_SIGNING_KEY, 1_800_000_000);
assert.equal(await verifySessionToken(sessionToken, process.env.SITE_ACCESS_SIGNING_KEY, 1_800_000_001), true);
assert.equal(await verifySessionToken(sessionToken, "different-signing-key-32-bytes-minimum", 1_800_000_001), false);

const protectedManifest = await middleware(new Request("https://shinobionline.vercel.app/public/latest.json"));
assert.equal(protectedManifest.status, 404);

const publicServerManifest = await middleware(new Request("https://shinobionline.vercel.app/public/server.json"));
assert.equal(publicServerManifest.headers.get("x-middleware-next"), "1");

console.log("Access gate OK: signed session, wrong-password 404, latest manifest protected, server manifest public.");
