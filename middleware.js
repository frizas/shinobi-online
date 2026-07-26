import { next } from "@vercel/functions";

const COOKIE_NAME = "__Host-shinobi_site_access";
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_BLOCK_MS = 30 * 60 * 1000;
const LOGIN_FAILURE_LIMIT = 8;
const LOGIN_TRACKER_LIMIT = 2048;
const encoder = new TextEncoder();
const loginFailures = new Map();

export const config = {
  matcher: "/:path*"
};

function getSecrets() {
  const accessKey = process.env.SITE_ACCESS_KEY || process.env["SITE_ACCESS_" + "PASSWORD"] || "";
  const signingKey = process.env.SITE_ACCESS_SIGNING_KEY || "";
  if (accessKey.length < 24 || accessKey.length > 128 || signingKey.length < 48) {
    return null;
  }
  return { accessKey, signingKey };
}

function constantTimeEqual(left, right) {
  const leftText = String(left);
  const rightText = String(right);
  const length = Math.max(leftText.length, rightText.length);
  let mismatch = leftText.length ^ rightText.length;
  for (let index = 0; index < length; index += 1) {
    mismatch |= (leftText.charCodeAt(index) || 0) ^ (rightText.charCodeAt(index) || 0);
  }
  return mismatch === 0;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sign(value, signingKey) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toBase64Url(new Uint8Array(signature));
}

export async function createSessionToken(signingKey, nowSeconds = Math.floor(Date.now() / 1000)) {
  const expiresAt = nowSeconds + SESSION_SECONDS;
  return `${expiresAt}.${await sign(String(expiresAt), signingKey)}`;
}

export async function verifySessionToken(token, signingKey, nowSeconds = Math.floor(Date.now() / 1000)) {
  const match = /^(\d{10})\.([A-Za-z0-9_-]{43})$/.exec(token || "");
  if (!match) {
    return false;
  }
  const expiresAt = Number(match[1]);
  if (expiresAt <= nowSeconds || expiresAt > nowSeconds + SESSION_SECONDS) {
    return false;
  }
  return constantTimeEqual(match[2], await sign(match[1], signingKey));
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) {
      continue;
    }
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return "";
}

function getClientAddress(request) {
  const forwarded = request.headers.get("x-vercel-forwarded-for") ||
    request.headers.get("x-forwarded-for") ||
    request.headers.get("x-real-ip") ||
    "";
  const address = forwarded.split(",", 1)[0].trim();
  return address.length > 0 && address.length <= 64 ? address : "";
}

function pruneLoginFailures(now) {
  for (const [address, state] of loginFailures) {
    if (state.expiresAt <= now && state.blockedUntil <= now) {
      loginFailures.delete(address);
    }
  }
  while (loginFailures.size > LOGIN_TRACKER_LIMIT) {
    loginFailures.delete(loginFailures.keys().next().value);
  }
}

function isLoginBlocked(request, now = Date.now()) {
  const address = getClientAddress(request);
  if (!address) {
    return false;
  }
  pruneLoginFailures(now);
  const state = loginFailures.get(address);
  return Boolean(state && state.blockedUntil > now);
}

function recordLoginFailure(request, now = Date.now()) {
  const address = getClientAddress(request);
  if (!address) {
    return;
  }
  pruneLoginFailures(now);
  const previous = loginFailures.get(address);
  const state = !previous || previous.expiresAt <= now
    ? { failures: 0, expiresAt: now + LOGIN_WINDOW_MS, blockedUntil: 0 }
    : previous;
  state.failures += 1;
  if (state.failures >= LOGIN_FAILURE_LIMIT) {
    state.blockedUntil = now + LOGIN_BLOCK_MS;
  }
  loginFailures.set(address, state);
}

function clearLoginFailures(request) {
  const address = getClientAddress(request);
  if (address) {
    loginFailures.delete(address);
  }
}

function securityHeaders(contentType) {
  return {
    "cache-control": "private, no-store, max-age=0",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "content-type": contentType,
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "origin-agent-cluster": "?1",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  };
}

function notFound() {
  return new Response("Not Found\n", {
    status: 404,
    headers: securityHeaders("text/plain; charset=utf-8")
  });
}

function loginPage() {
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Access required</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; background: #05080a; color: #f5f7f8; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; }
    form { width: min(24rem, calc(100% - 3rem)); display: grid; gap: 1rem; }
    label { font-size: .82rem; letter-spacing: .12em; text-transform: uppercase; color: #aab2b6; }
    input, button { box-sizing: border-box; width: 100%; border: 1px solid #394247; border-radius: .35rem; padding: .9rem 1rem; font: inherit; }
    input { background: #0b1013; color: inherit; }
    button { cursor: pointer; border-color: #9b2020; background: #7a1717; color: white; font-weight: 700; }
  </style>
</head>
<body>
  <form method="post" action="/" autocomplete="off">
    <label for="key">Access key</label>
    <input id="key" name="key" type="password" required autofocus autocomplete="current-password" maxlength="256">
    <button type="submit">Enter</button>
  </form>
</body>
</html>`, {
    status: 401,
    headers: securityHeaders("text/html; charset=utf-8")
  });
}

function serverHeaders() {
  return {
    ...securityHeaders("application/json; charset=utf-8"),
    "cache-control": "public, max-age=15, s-maxage=15, stale-while-revalidate=15",
    "access-control-allow-origin": "*"
  };
}

function normalizeServerManifest(manifest) {
  const validStatus = ["online", "offline", "maintenance"].includes(manifest && manifest.status);
  const validMode = ["pinggy", "stable"].includes(manifest && manifest.mode);
  const safeHost = (value) =>
    value === null ||
    (typeof value === "string" && value.length > 0 && value.length <= 253 && /^[A-Za-z0-9.-]+$/.test(value));
  const validPort = (value) => Number.isInteger(value) && value >= 0 && value <= 65535;

  if (!manifest ||
      manifest.schemaVersion !== 1 ||
      manifest.serverName !== "Leaf" ||
      !validStatus ||
      !validMode ||
      !safeHost(manifest.loginHost) ||
      !safeHost(manifest.gameHost) ||
      !validPort(manifest.loginPort) ||
      !validPort(manifest.gamePort) ||
      !Number.isInteger(manifest.protocol) ||
      manifest.protocol < 1 ||
      typeof manifest.updatedAt !== "string" ||
      !Number.isInteger(manifest.endpointRevision) ||
      manifest.endpointRevision < 0 ||
      typeof manifest.message !== "string" ||
      manifest.message.length > 512) {
    throw new Error("Invalid server manifest");
  }

  if (manifest.status === "online" &&
      (!manifest.loginHost || !manifest.gameHost || manifest.loginPort < 1 || manifest.gamePort < 1)) {
    throw new Error("Online server manifest has no usable endpoint");
  }

  return {
    schemaVersion: 1,
    serverName: "Leaf",
    status: manifest.status,
    mode: manifest.mode,
    loginHost: manifest.loginHost,
    loginPort: manifest.loginPort,
    gameHost: manifest.gameHost,
    gamePort: manifest.gamePort,
    protocol: manifest.protocol,
    updatedAt: manifest.updatedAt,
    endpointRevision: manifest.endpointRevision,
    message: manifest.message
  };
}

async function serverManifestResponse() {
  try {
    const upstream = await fetch(
      "https://raw.githubusercontent.com/frizas/shinobi-online/main/public/server.json",
      {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        cache: "no-store"
      }
    );
    if (!upstream.ok) {
      throw new Error(`Server manifest upstream returned ${upstream.status}`);
    }

    const contentLength = Number(upstream.headers.get("content-length") || "0");
    if (contentLength > 16384) {
      throw new Error("Server manifest is too large");
    }
    const body = await upstream.text();
    if (body.length > 16384) {
      throw new Error("Server manifest is too large");
    }
    const manifest = normalizeServerManifest(JSON.parse(body));
    return new Response(`${JSON.stringify(manifest)}\n`, {
      status: 200,
      headers: serverHeaders()
    });
  } catch {
    return new Response('{"status":"offline"}\n', {
      status: 503,
      headers: serverHeaders()
    });
  }
}

export default async function middleware(request) {
  const url = new URL(request.url);

  // Endpoint discovery stays public, but is fetched server-side so the browser
  // never follows a cross-origin redirect that its CSP would reject.
  if (url.pathname === "/public/server.json" && request.method === "GET") {
    return serverManifestResponse();
  }

  const secrets = getSecrets();
  if (!secrets) {
    return notFound();
  }

  const token = getCookie(request, COOKIE_NAME);
  if (await verifySessionToken(token, secrets.signingKey)) {
    return next({
      headers: {
        "cache-control": "private, no-store",
        "vary": "Cookie"
      }
    });
  }

  if (url.pathname === "/" && request.method === "GET") {
    return loginPage();
  }

  if (url.pathname === "/" && request.method === "POST") {
    if (isLoginBlocked(request)) {
      return notFound();
    }

    const contentType = request.headers.get("content-type") || "";
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded") ||
        !Number.isFinite(contentLength) ||
        contentLength > 512) {
      return notFound();
    }

    let submittedKey = "";
    try {
      const form = await request.formData();
      submittedKey = String(form.get("key") || "");
    } catch {
      return notFound();
    }
    if (submittedKey.length > 128 || !constantTimeEqual(submittedKey, secrets.accessKey)) {
      recordLoginFailure(request);
      return notFound();
    }

    clearLoginFailures(request);
    const sessionToken = await createSessionToken(secrets.signingKey);
    return new Response(null, {
      status: 303,
      headers: {
        "cache-control": "private, no-store",
        "location": "/",
        "set-cookie": `${COOKIE_NAME}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`
      }
    });
  }

  return notFound();
}
