import { next } from "@vercel/functions";

const COOKIE_NAME = "shinobi_site_access";
const SESSION_SECONDS = 12 * 60 * 60;
const encoder = new TextEncoder();

export const config = {
  matcher: "/:path*"
};

function getSecrets() {
  const password = process.env.SITE_ACCESS_PASSWORD || "";
  const signingKey = process.env.SITE_ACCESS_SIGNING_KEY || "";
  if (password.length < 8 || signingKey.length < 32) {
    return null;
  }
  return { password, signingKey };
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

function securityHeaders(contentType) {
  return {
    "cache-control": "private, no-store, max-age=0",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "content-type": contentType,
    "referrer-policy": "no-referrer",
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
    <label for="password">Access password</label>
    <input id="password" name="password" type="password" required autofocus autocomplete="current-password" maxlength="256">
    <button type="submit">Enter</button>
  </form>
</body>
</html>`, {
    status: 401,
    headers: securityHeaders("text/html; charset=utf-8")
  });
}

export default async function middleware(request) {
  const url = new URL(request.url);

  // The running client needs endpoint discovery, but no release/download data is exposed here.
  if (url.pathname === "/public/server.json") {
    return next();
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
    let submittedPassword = "";
    try {
      const form = await request.formData();
      submittedPassword = String(form.get("password") || "");
    } catch {
      return notFound();
    }
    if (!constantTimeEqual(submittedPassword, secrets.password)) {
      return notFound();
    }

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
