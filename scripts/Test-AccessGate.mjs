import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

process.env.SITE_ACCESS_SIGNING_KEY = "temporary-test-signing-key-with-at-least-48-bytes";
process.env.SITE_ACCESS_KEY = "legacy-shared-key-is-ignored";

const { default: middleware, verifySessionToken } = await import("../middleware.js");

const onlineManifest = {
  schemaVersion: 2,
  acceptanceSchemaVersion: 1,
  serverName: "Leaf",
  status: "online",
  mode: "pinggy",
  loginHost: "127.0.0.1",
  loginPort: 7171,
  gameHost: "127.0.0.1",
  gamePort: 7172,
  protocol: 854,
  onlineAcceptanceToken: "d".repeat(64),
  clientBuildToken: "e".repeat(64),
  releaseVersion: "v0.4.69",
  updatedAt: "2026-07-26T12:00:00.1234567Z",
  endpointRevision: 1,
  message: "Leaf is online."
};
const onlineManifestBytes = `${JSON.stringify(onlineManifest, null, 2)}\n`;
const serverSignatureEnvelope = {
  schemaVersion: 1,
  algorithm: "RSASSA-PKCS1-v1_5-SHA256",
  keyId: `sha256:${"a".repeat(64)}`,
  manifestSha256: "b".repeat(64),
  signature: "c".repeat(512)
};
const serverSignatureBytes = `${JSON.stringify(serverSignatureEnvelope, null, 2)}\n`;

globalThis.fetch = async (url) => new Response(
  String(url).includes("server.sig") ? serverSignatureBytes : onlineManifestBytes,
  { status: 200, headers: { "content-type": "application/json" } }
);

const root = await middleware(new Request("https://shinobionline.vercel.app/"));
assert.equal(root.headers.get("x-middleware-next"), "1", "the static landing page stays public");
const landingHtml = await readFile(new URL("../index.html", import.meta.url), "utf8");
assert.match(landingHtml, /href="\/download"/);
assert.doesNotMatch(landingHtml, /github\.com\/frizas\/shinobi-online\/releases|latest\.json|server\.json|app\.js/);

const guestDownload = await middleware(new Request("https://shinobionline.vercel.app/download"));
assert.equal(guestDownload.status, 303);
assert.equal(guestDownload.headers.get("location"), "https://shinobionline.vercel.app/login?next=%2Fdownload");
const guestDownloadFile = await middleware(new Request("https://shinobionline.vercel.app/download.html"));
assert.equal(guestDownloadFile.status, 303, "the backing download page is gated too");
const guestAppScript = await middleware(new Request("https://shinobionline.vercel.app/app.js"));
assert.equal(guestAppScript.status, 303, "download details are not served to a guest");

const loginPage = await middleware(new Request("https://shinobionline.vercel.app/login?next=%2Fdownload"));
assert.equal(loginPage.status, 200);
const loginHtml = await loginPage.text();
assert.match(loginHtml, /Game username/);
assert.match(loginHtml, /current-password/);
assert.match(loginHtml, /same username and password you use to log in to the game/i);
assert.doesNotMatch(loginHtml, /Access key|legacy-shared-key-is-ignored/);

let lastLoginForward;
globalThis.fetch = async (url, options) => {
  lastLoginForward = { url: String(url), options };
  return new Response('{"authenticated":false}', { status: 401 });
};
const rejectedLogin = await middleware(new Request("https://shinobionline.vercel.app/login", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    origin: "https://shinobionline.vercel.app",
    "x-vercel-forwarded-for": "192.0.2.10"
  },
  body: "username=shinobiuser&password=incorrect"
}));
assert.equal(rejectedLogin.status, 200);
assert.match(await rejectedLogin.text(), /Login failed/);
assert.equal(lastLoginForward.url, "https://shinobionline.vercel.app/api/website-login");
assert.equal(lastLoginForward.options.method, "POST");
assert.equal(JSON.parse(lastLoginForward.options.body).username, "shinobiuser");
assert.ok(lastLoginForward.options.headers["x-shinobi-login-proof"]);

globalThis.fetch = async () => new Response('{"authenticated":true}', { status: 200 });
const acceptedLogin = await middleware(new Request("https://shinobionline.vercel.app/login", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    origin: "https://shinobionline.vercel.app",
    "x-vercel-forwarded-for": "192.0.2.11"
  },
  body: "username=shinobiuser&password=correct-horse&returnTo=https%3A%2F%2Fevil.example"
}));
assert.equal(acceptedLogin.status, 303);
assert.equal(acceptedLogin.headers.get("location"), "/download", "return path is fixed to the gated download page");
const cookie = acceptedLogin.headers.get("set-cookie");
assert.match(cookie, /^__Host-shinobi_site_access=.*; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200$/);
const sessionToken = cookie.split(";")[0].split("=")[1];
assert.equal(await verifySessionToken(sessionToken, process.env.SITE_ACCESS_SIGNING_KEY), true);

const acceptedLoginWithoutOrigin = await middleware(new Request("https://shinobionline.vercel.app/login", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "sec-fetch-site": "same-origin",
    "x-vercel-forwarded-for": "192.0.2.13"
  },
  body: "username=shinobiuser&password=correct-horse"
}));
assert.equal(acceptedLoginWithoutOrigin.status, 303,
  "a browser same-origin POST may use Sec-Fetch-Site when Origin is omitted");

const rejectedCrossOriginLogin = await middleware(new Request("https://shinobionline.vercel.app/login", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    origin: "https://attacker.example",
    "sec-fetch-site": "cross-site",
    "x-vercel-forwarded-for": "192.0.2.14"
  },
  body: "username=shinobiuser&password=correct-horse"
}));
assert.equal(rejectedCrossOriginLogin.status, 404,
  "cross-origin login submissions remain rejected");

const permittedDownload = await middleware(new Request("https://shinobionline.vercel.app/download", {
  headers: { cookie: `__Host-shinobi_site_access=${sessionToken}` }
}));
assert.equal(permittedDownload.headers.get("x-middleware-next"), "1");
assert.equal(permittedDownload.headers.get("cache-control"), "private, no-store");

const logout = await middleware(new Request("https://shinobionline.vercel.app/logout"));
assert.equal(logout.status, 303);
assert.equal(logout.headers.get("location"), "/");
assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);

const publicLatestManifest = await middleware(new Request("https://shinobionline.vercel.app/public/v0.2/latest.json"));
assert.equal(publicLatestManifest.headers.get("x-middleware-next"), "1");
globalThis.fetch = async (url) => new Response(
  String(url).includes("server.sig") ? serverSignatureBytes : onlineManifestBytes,
  { status: 200, headers: { "content-type": "application/json" } }
);
const publicServerManifest = await middleware(new Request("https://shinobionline.vercel.app/public/server.json"));
assert.equal(publicServerManifest.status, 200);
assert.match(publicServerManifest.headers.get("cache-control"), /no-store/i,
  "signed server metadata must not cache server.json and server.sig independently");
assert.equal(await publicServerManifest.text(), onlineManifestBytes);

globalThis.fetch = async () => new Response('{"authenticated":false}', { status: 401 });
for (let attempt = 0; attempt < 8; attempt += 1) {
  await middleware(new Request("https://shinobionline.vercel.app/login", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      origin: "https://shinobionline.vercel.app",
      "x-vercel-forwarded-for": "192.0.2.12"
    },
    body: "username=shinobiuser&password=incorrect"
  }));
}
const throttledLogin = await middleware(new Request("https://shinobionline.vercel.app/login", {
  method: "POST",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    origin: "https://shinobionline.vercel.app",
    "x-vercel-forwarded-for": "192.0.2.12"
  },
  body: "username=shinobiuser&password=correct-horse"
}));
assert.match(await throttledLogin.text(), /Login failed/);

console.log("Website access gate OK: public landing, protected download view, game-account session, logout, public launcher manifests, and bounded login attempts.");
