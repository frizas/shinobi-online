const SESSION_SECONDS = 12 * 60 * 60;
const encoder = new TextEncoder();

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

export async function createLoginRequestProof(signingKey, timestamp, clientAddress, username, password) {
  const payload = ["shinobi-web-login-v1", timestamp, clientAddress, username, password].join("\n");
  return sign(payload, signingKey);
}

export async function verifyLoginRequestProof(signingKey, timestamp, clientAddress, username, password, proof) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(proof || "")) {
    return false;
  }
  return constantTimeEqual(
    proof,
    await createLoginRequestProof(signingKey, timestamp, clientAddress, username, password)
  );
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

export const SESSION_TTL_SECONDS = SESSION_SECONDS;
