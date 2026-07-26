import assert from "node:assert/strict";

process.env.SITE_ACCESS_KEY = "temporary-test-access-key-24-plus";
process.env.SITE_ACCESS_SIGNING_KEY = "temporary-test-signing-key-with-at-least-48-bytes";

const { default: middleware, createSessionToken, verifySessionToken } = await import("../middleware.js");

const onlineManifest = {
  schemaVersion: 1,
  serverName: "Leaf",
  status: "online",
  mode: "pinggy",
  loginHost: "127.0.0.1",
  loginPort: 7171,
  gameHost: "127.0.0.1",
  gamePort: 7172,
  protocol: 854,
  updatedAt: "2026-07-26T12:00:00.1234567Z",
  endpointRevision: 1,
  message: "Leaf is online."
};
globalThis.fetch = async () => new Response(JSON.stringify(onlineManifest), {
  status: 200,
  headers: { "content-type": "application/json" }
});

const rootRequest = new Request("https://shinobionline.vercel.app/");
const loginResponse = await middleware(rootRequest);
assert.equal(loginResponse.status, 401);
assert.doesNotMatch(await loginResponse.text(), /temporary-test-access-key-24-plus/);

const wrongRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "x-vercel-forwarded-for": "192.0.2.10"
  },
  body: "key=wrong"
});
assert.equal((await middleware(wrongRequest)).status, 404);

const correctRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "x-vercel-forwarded-for": "192.0.2.11"
  },
  body: "key=temporary-test-access-key-24-plus"
});
const correctResponse = await middleware(correctRequest);
assert.equal(correctResponse.status, 303);
assert.match(correctResponse.headers.get("set-cookie"), /^__Host-shinobi_site_access=/);

const sessionToken = await createSessionToken(process.env.SITE_ACCESS_SIGNING_KEY, 1_800_000_000);
assert.equal(await verifySessionToken(sessionToken, process.env.SITE_ACCESS_SIGNING_KEY, 1_800_000_001), true);
assert.equal(await verifySessionToken(sessionToken, "different-signing-key-with-at-least-48-bytes", 1_800_000_001), false);

const oversizedRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "content-length": "513"
  },
  body: "key=wrong"
});
assert.equal((await middleware(oversizedRequest)).status, 404);

const jsonRequest = new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ key: process.env.SITE_ACCESS_KEY })
});
assert.equal((await middleware(jsonRequest)).status, 404);

for (let attempt = 0; attempt < 8; attempt += 1) {
  const response = await middleware(new Request("https://shinobionline.vercel.app/", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "x-vercel-forwarded-for": "192.0.2.12"
    },
    body: "key=wrong"
  }));
  assert.equal(response.status, 404);
}
const throttledCorrectResponse = await middleware(new Request("https://shinobionline.vercel.app/", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "x-vercel-forwarded-for": "192.0.2.12"
  },
  body: "key=temporary-test-access-key-24-plus"
}));
assert.equal(throttledCorrectResponse.status, 404);

const protectedManifest = await middleware(new Request("https://shinobionline.vercel.app/public/v0.2/latest.json"));
assert.equal(protectedManifest.status, 404);
const protectedSignature = await middleware(new Request("https://shinobionline.vercel.app/public/v0.2/latest.sig"));
assert.equal(protectedSignature.status, 404);

const publicServerManifest = await middleware(new Request("https://shinobionline.vercel.app/public/server.json"));
assert.equal(publicServerManifest.status, 200);
assert.deepEqual(await publicServerManifest.json(), onlineManifest);

globalThis.fetch = async () => {
  throw new Error("upstream unavailable");
};
const unavailableServerManifest = await middleware(new Request("https://shinobionline.vercel.app/public/server.json"));
assert.equal(unavailableServerManifest.status, 503);

console.log("Access gate OK: signed session, generic failures, bounded throttle, v0.2 manifest protected, server status proxied.");
