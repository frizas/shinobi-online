import { next } from "@vercel/functions";
import { createSessionToken, verifySessionToken, createLoginRequestProof, SESSION_TTL_SECONDS } from "./session.js";
export { createSessionToken, verifySessionToken } from "./session.js";

const COOKIE_NAME = "__Host-shinobi_site_access";
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_BLOCK_MS = 30 * 60 * 1000;
const LOGIN_FAILURE_LIMIT = 8;
const LOGIN_TRACKER_LIMIT = 2048;
const loginFailures = new Map();

export const config = {
  matcher: "/:path*"
};

function getSecrets() {
  const signingKey = process.env.SITE_ACCESS_SIGNING_KEY || "";
  if (signingKey.length < 48) {
    return null;
  }
  return { signingKey };
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

function safeReturnPath(value) {
  return value === "/download" ? value : "/download";
}

function loginPage(returnPath = "/download", errorKind = "") {
  const errorMessage = errorKind === "unavailable"
    ? "Game-account login is temporarily unavailable. Please try again while Shinobi Online is online."
    : errorKind
      ? "Login failed. Check your username and password, then try again."
      : "";
  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Log in · Shinobi Online</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; background: #05080a; color: #f7f1df; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; background: radial-gradient(ellipse at 50% 35%, #17211e, #05080a 68%); }
    main { width: min(28rem, 100%); border: 1px solid rgba(247,241,223,.17); border-left: 3px solid #e09f49; border-radius: 8px; background: rgba(8,16,18,.92); padding: clamp(24px, 6vw, 42px); box-shadow: 0 24px 80px rgba(0,0,0,.45); }
    .eyebrow { margin: 0 0 10px; color: #e09f49; font-size: .75rem; font-weight: 800; letter-spacing: .13em; text-transform: uppercase; }
    h1 { margin: 0 0 10px; font-size: clamp(1.7rem, 5vw, 2.1rem); line-height: 1.1; }
    .hint { margin: 0 0 24px; color: #b7c0ba; line-height: 1.5; }
    form { display: grid; gap: 15px; }
    label { display: grid; gap: 7px; color: #c8cec4; font-size: .82rem; font-weight: 700; }
    input, button { box-sizing: border-box; width: 100%; min-height: 48px; border: 1px solid #394247; border-radius: .35rem; padding: .75rem .9rem; font: inherit; }
    input { background: #0b1013; color: inherit; }
    input:focus { outline: 2px solid #e09f49; outline-offset: 2px; }
    button { margin-top: 4px; cursor: pointer; border-color: transparent; background: linear-gradient(180deg, #f0bd62, #e09f49); color: #15100a; font-weight: 800; }
    button:hover { background: #f0bd62; }
    .error { margin: 0 0 16px; border-left: 2px solid #d77a67; padding: 8px 10px; color: #f1aa98; }
    .back { display: inline-block; margin-top: 20px; color: #b7c0ba; font-size: .9rem; text-underline-offset: 4px; }
  </style>
</head>
<body>
  <main>
    <p class="eyebrow">Shinobi Online</p>
    <h1>Log in to continue</h1>
    <p class="hint">Use the same username and password you use to log in to the game.</p>
    ${errorMessage ? `<p class="error" role="alert">${errorMessage}</p>` : ''}
    <form method="post" action="/login" autocomplete="on">
      <input type="hidden" name="returnTo" value="${safeReturnPath(returnPath)}">
      <label for="username">Game username
        <input id="username" name="username" type="text" required autofocus autocomplete="username" minlength="3" maxlength="25" autocapitalize="none" spellcheck="false">
      </label>
      <label for="password">Password
        <input id="password" name="password" type="password" required autocomplete="current-password" minlength="4" maxlength="64">
      </label>
      <button type="submit">Log in</button>
    </form>
    <a class="back" href="/">Back to Shinobi Online</a>
  </main>
</body>
</html>`, {
    status: 200,
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
    typeof value === "string" &&
    (value === "" || (value.length <= 253 && /^[A-Za-z0-9.-]+$/.test(value)));
  const validPort = (value) => Number.isInteger(value) && value >= 0 && value <= 65535;
  const safeAcceptanceToken = (value) =>
    typeof value === "string" && (value === "" || /^[a-f0-9]{64}$/.test(value));
  const safeReleaseVersion = (value) =>
    typeof value === "string" &&
    (value === "" || /^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(value));

  if (!manifest ||
      manifest.schemaVersion !== 2 ||
      manifest.acceptanceSchemaVersion !== 1 ||
      manifest.serverName !== "Leaf" ||
      !validStatus ||
      !validMode ||
      !safeHost(manifest.loginHost) ||
      !safeHost(manifest.gameHost) ||
      !validPort(manifest.loginPort) ||
      !validPort(manifest.gamePort) ||
      !Number.isInteger(manifest.protocol) ||
      manifest.protocol < 1 ||
      !safeAcceptanceToken(manifest.onlineAcceptanceToken) ||
      !safeAcceptanceToken(manifest.clientBuildToken) ||
      !safeReleaseVersion(manifest.releaseVersion) ||
      typeof manifest.updatedAt !== "string" ||
      !Number.isInteger(manifest.endpointRevision) ||
      manifest.endpointRevision < 0 ||
      typeof manifest.message !== "string" ||
      manifest.message.length > 512) {
    throw new Error("Invalid server manifest");
  }

  if (manifest.status === "online" &&
      (!manifest.loginHost || !manifest.gameHost || manifest.loginPort < 1 || manifest.gamePort < 1 ||
       !manifest.onlineAcceptanceToken || !manifest.clientBuildToken || !manifest.releaseVersion)) {
    throw new Error("Online server manifest has no usable accepted endpoint");
  }
  if (manifest.status !== "online" &&
      (manifest.loginHost || manifest.gameHost || manifest.loginPort !== 0 || manifest.gamePort !== 0 ||
       manifest.onlineAcceptanceToken || manifest.clientBuildToken || manifest.releaseVersion)) {
    throw new Error("Non-online server manifest retains stale acceptance identity");
  }

  return {
    schemaVersion: 2,
    acceptanceSchemaVersion: 1,
    serverName: "Leaf",
    status: manifest.status,
    mode: manifest.mode,
    loginHost: manifest.loginHost,
    loginPort: manifest.loginPort,
    gameHost: manifest.gameHost,
    gamePort: manifest.gamePort,
    protocol: manifest.protocol,
    onlineAcceptanceToken: manifest.onlineAcceptanceToken,
    clientBuildToken: manifest.clientBuildToken,
    releaseVersion: manifest.releaseVersion,
    updatedAt: manifest.updatedAt,
    endpointRevision: manifest.endpointRevision,
    message: manifest.message
  };
}

function normalizeServerSignature(signature) {
  if (!signature ||
      signature.schemaVersion !== 1 ||
      signature.algorithm !== "RSASSA-PKCS1-v1_5-SHA256" ||
      typeof signature.keyId !== "string" ||
      !/^sha256:[a-f0-9]{64}$/.test(signature.keyId) ||
      typeof signature.manifestSha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(signature.manifestSha256) ||
      typeof signature.signature !== "string" ||
      signature.signature.length < 128 ||
      signature.signature.length > 2048) {
    throw new Error("Invalid server manifest signature envelope");
  }
  return signature;
}

async function serverMetadataResponse(fileName) {
  if (fileName !== "server.json" && fileName !== "server.sig") {
    return new Response('{"status":"offline"}\n', {
      status: 503,
      headers: serverHeaders()
    });
  }

  const upstreams = [
    {
      url: `https://raw.githubusercontent.com/frizas/shinobi-online/main/public/${fileName}`,
      accept: "application/json"
    },
    {
      url: `https://api.github.com/repos/frizas/shinobi-online/contents/public/${fileName}?ref=main`,
      accept: "application/vnd.github.raw"
    }
  ];

  for (const candidate of upstreams) {
    try {
      const upstream = await fetch(candidate.url, {
        method: "GET",
        headers: {
          accept: candidate.accept,
          "user-agent": "ShinobiOnlineStatusProxy/0.2"
        },
        redirect: "error",
        cache: "no-store"
      });
      if (!upstream.ok) {
        continue;
      }

      const contentLength = Number(upstream.headers.get("content-length") || "0");
      if (contentLength > 16384) {
        continue;
      }
      const body = await upstream.text();
      if (body.length > 16384) {
        continue;
      }
      const parsed = JSON.parse(body);
      if (fileName === "server.json") {
        normalizeServerManifest(parsed);
      } else {
        normalizeServerSignature(parsed);
      }
      return new Response(body, {
        status: 200,
        headers: serverHeaders()
      });
    } catch {
      // Try the independent GitHub API route before failing closed.
    }
  }

  return new Response('{"status":"offline"}\n', {
    status: 503,
    headers: serverHeaders()
  });
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Player launchers require these signed manifests before a browser session
  // exists. Their signatures remain the authority for clients that consume them.
  if (request.method === "GET" &&
      (pathname === "/public/v0.2/latest.json" || pathname === "/public/v0.2/latest.sig")) {
    return next();
  }

  if (request.method === "GET" &&
      (pathname === "/public/server.json" || pathname === "/public/server.sig")) {
    return serverMetadataResponse(pathname.endsWith(".sig") ? "server.sig" : "server.json");
  }

  // Public static landing assets do not include live release/download details.
  if (request.method === "GET" &&
      (pathname === "/" || pathname === "/styles.css" || pathname === "/favicon.ico" ||
       pathname === "/site.webmanifest" || pathname.startsWith("/assets/"))) {
    return next();
  }

  // The Node function validates credentials against the running game's login
  // service. The middleware owns throttling and session issuance.
  if (pathname === "/api/website-login" && request.method === "POST") {
    return next();
  }

  if (pathname === "/logout" && request.method === "GET") {
    return new Response(null, {
      status: 303,
      headers: {
        ...securityHeaders("text/plain; charset=utf-8"),
        "location": "/",
        "set-cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      }
    });
  }

  const secrets = getSecrets();
  if (!secrets) {
    return notFound();
  }

  const token = getCookie(request, COOKIE_NAME);
  const authenticated = await verifySessionToken(token, secrets.signingKey);

  if (pathname === "/login" && request.method === "GET") {
    if (authenticated) {
      return Response.redirect(new URL("/download", request.url), 303);
    }
    return loginPage(safeReturnPath(url.searchParams.get("next")));
  }

  if (pathname === "/login" && request.method === "POST") {
    const origin = request.headers.get("origin") || "";
    try {
      if (new URL(origin).origin !== url.origin) return notFound();
    } catch {
      return notFound();
    }
    if (isLoginBlocked(request)) {
      return loginPage("/download", true);
    }
    const clientAddress = getClientAddress(request);
    if (!clientAddress) {
      return new Response(loginPage("/download", "unavailable").body, {
        status: 503,
        headers: securityHeaders("text/html; charset=utf-8")
      });
    }

    const contentType = request.headers.get("content-type") || "";
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded") ||
        !Number.isFinite(contentLength) || contentLength > 1024) {
      return notFound();
    }

    let username = "";
    let password = "";
    let returnTo = "/download";
    try {
      const form = await request.formData();
      username = String(form.get("username") || "").trim();
      password = String(form.get("password") || "");
      returnTo = safeReturnPath(String(form.get("returnTo") || ""));
    } catch {
      return notFound();
    }

    if (!/^[A-Za-z0-9]{3,25}$/.test(username) || password.length < 4 || password.length > 64) {
      recordLoginFailure(request);
      return loginPage(returnTo, true);
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const proof = await createLoginRequestProof(secrets.signingKey, timestamp, clientAddress, username, password);
    let verification;
    try {
      verification = await fetch(new URL("/api/website-login", request.url), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-shinobi-login-time": timestamp,
          "x-shinobi-login-ip": clientAddress,
          "x-shinobi-login-proof": proof
        },
        body: JSON.stringify({ username, password })
      });
    } catch {
      return new Response(loginPage(returnTo, "unavailable").body, {
        status: 503,
        headers: securityHeaders("text/html; charset=utf-8")
      });
    }

    if (verification.status === 401) {
      recordLoginFailure(request);
      return loginPage(returnTo, true);
    }
    if (!verification.ok) {
      return new Response(loginPage(returnTo, "unavailable").body, {
        status: 503,
        headers: securityHeaders("text/html; charset=utf-8")
      });
    }

    clearLoginFailures(request);
    const sessionToken = await createSessionToken(secrets.signingKey);
    return new Response(null, {
      status: 303,
      headers: {
        ...securityHeaders("text/plain; charset=utf-8"),
        "location": returnTo,
        "set-cookie": `${COOKIE_NAME}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
      }
    });
  }

  if ((pathname === "/download" || pathname === "/download.html" || pathname === "/app.js") &&
      request.method === "GET") {
    if (!authenticated) {
      return Response.redirect(new URL("/login?next=%2Fdownload", request.url), 303);
    }
    return next({
      headers: {
        "cache-control": "private, no-store",
        "vary": "Cookie"
      }
    });
  }

  return notFound();
}
