import net from "node:net";
import { createHash, randomBytes, timingSafeEqual, verify as verifySignature } from "node:crypto";
import signingKey from "../public/manifest-signing-key.json" with { type: "json" };
import { verifyLoginRequestProof } from "../session.js";

const LOGIN_TIMEOUT_MS = 6000;
const MAX_MANIFEST_BYTES = 16384;
const CLIENT_GENERATION = "v0.2";
const CLIENT_GENERATION_PROOF = "Eekxym0vIlAq54Shy4yn-3YKbVzbZ-5zqkLU1VgtCg4";
const OTSERV_RSA = BigInt(
  "1091201329673994292788609605089955415282375029027981291234687579" +
  "3726629149257644633073969600111060390723088861007265581882535850" +
  "3429057592827629436413108566029093628212635953836686562675849720" +
  "6207862794310902180176810615217550567108238764764442605581471797" +
  "07119674283982419152118103759076030616683978566631413"
);
const RSA_EXPONENT = 65537n;

function textResponse(status, message) {
  return new Response(message, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff"
    }
  });
}

function isPublicIpv4(address) {
  if (net.isIP(address) !== 4) return false;
  const octets = address.split(".").map(Number);
  const [first, second, third] = octets;
  if (first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || second === 168)) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0 && third === 113)) {
    return false;
  }
  return true;
}

function writeU16(value) {
  const buffer = Buffer.allocUnsafe(2);
  buffer.writeUInt16LE(value);
  return buffer;
}

function writeString(value) {
  const body = Buffer.from(value, "utf8");
  if (body.length > 256) throw new Error("protocol-string-too-long");
  return Buffer.concat([writeU16(body.length), body]);
}

function adler32(buffer) {
  let a = 1;
  let b = 0;
  for (const value of buffer) {
    a = (a + value) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function bufferToBigInt(buffer) {
  return BigInt(`0x${buffer.toString("hex") || "0"}`);
}

function bigIntToBuffer(value, size) {
  const hex = value.toString(16).padStart(size * 2, "0");
  if (hex.length > size * 2) throw new Error("rsa-block-overflow");
  return Buffer.from(hex, "hex");
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

function encryptRsaPlaintext(plaintext) {
  return bigIntToBuffer(modPow(bufferToBigInt(plaintext), RSA_EXPONENT, OTSERV_RSA), 128);
}

function createLoginPacket(username, password, buildToken, xteaKey = randomBytes(16), action = "website-login") {
  if (!/^[A-Za-z0-9]{3,25}$/.test(username) || password.length < 4 || password.length > 64 || !/^[a-f0-9]{64}$/i.test(buildToken)) {
    throw new Error("invalid-login-input");
  }
  if (!new Set(["website-login", "create-account"]).has(action)) throw new Error("unsupported-account-action");
  const keyWords = Array.from({ length: 4 }, (_, index) => xteaKey.readUInt32LE(index * 4));
  const accountBlock = Buffer.alloc(128);
  let position = 0;
  accountBlock.writeUInt8(0, position++);
  for (const keyPart of keyWords) {
    accountBlock.writeUInt32LE(keyPart, position);
    position += 4;
  }
  for (const value of [username, password]) {
    const encoded = writeString(value);
    encoded.copy(accountBlock, position);
    position += encoded.length;
  }
  randomBytes(128 - position).copy(accountBlock, position);

  const extensionBlock = Buffer.alloc(128);
  extensionBlock.writeUInt8(0, 0);
  const extension = writeString(`SOC2|${CLIENT_GENERATION}|${CLIENT_GENERATION_PROOF}|${action}|${buildToken.toLowerCase().slice(0, 16)}`);
  extension.copy(extensionBlock, 1);
  randomBytes(127 - extension.length).copy(extensionBlock, 1 + extension.length);

  const protocolHeader = Buffer.alloc(17);
  protocolHeader.writeUInt8(0x01, 0); // Login protocol
  protocolHeader.writeUInt16LE(2, 1); // OTClient Windows
  protocolHeader.writeUInt16LE(854, 3);
  const payload = Buffer.concat([
    protocolHeader,
    encryptRsaPlaintext(accountBlock),
    encryptRsaPlaintext(extensionBlock)
  ]);
  const frameBody = Buffer.allocUnsafe(4 + payload.length);
  frameBody.writeUInt32LE(adler32(payload), 0);
  payload.copy(frameBody, 4);
  return { packet: Buffer.concat([writeU16(frameBody.length), frameBody]), keyWords };
}

function decryptXtea(encrypted, key) {
  if (encrypted.length < 8 || encrypted.length % 8 !== 0) throw new Error("invalid-encrypted-response");
  const output = Buffer.from(encrypted);
  const delta = 0x9e3779b9;
  for (let offset = 0; offset < output.length; offset += 8) {
    let left = output.readUInt32LE(offset);
    let right = output.readUInt32LE(offset + 4);
    let sum = 0xc6ef3720;
    for (let round = 0; round < 32; round += 1) {
      right = (right - ((((left << 4) ^ (left >>> 5)) + left) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
      sum = (sum - delta) >>> 0;
      left = (left - ((((right << 4) ^ (right >>> 5)) + right) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
    }
    output.writeUInt32LE(left, offset);
    output.writeUInt32LE(right, offset + 4);
  }
  return output;
}

function readString(buffer, offset) {
  if (offset + 2 > buffer.length) throw new Error("invalid-login-response");
  const length = buffer.readUInt16LE(offset);
  const start = offset + 2;
  const end = start + length;
  if (end > buffer.length) throw new Error("invalid-login-response");
  return { value: buffer.toString("utf8", start, end), offset: end };
}

export function parseAccountActionResponse(payload, expectedAction) {
  if (payload.length < 4 || payload.readUInt8(0) !== 0x67 || payload.readUInt8(1) !== 1) {
    throw new Error("unexpected-login-response");
  }
  const action = readString(payload, 2);
  if (action.value !== expectedAction || action.offset + 1 > payload.length) {
    throw new Error("unexpected-login-response");
  }
  const accepted = payload.readUInt8(action.offset) === 1;
  const message = readString(payload, action.offset + 1);
  if (message.offset + 8 !== payload.length) throw new Error("unexpected-login-response");
  return { accepted, message: message.value };
}

export function parseWebsiteLoginResponse(payload) {
  return parseAccountActionResponse(payload, "website-login");
}

export function exchangeGameAccountAction(host, port, username, password, buildToken, action, xteaKey = randomBytes(16)) {
  const { packet, keyWords } = createLoginPacket(username, password, buildToken, xteaKey, action);
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let received = Buffer.alloc(0);
    let settled = false;
    const finish = (error, result = { accepted: false }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error("game-login-timeout")), LOGIN_TIMEOUT_MS);
    socket.setNoDelay(true);
    socket.on("error", () => finish(new Error("game-login-unavailable")));
    socket.on("close", () => {
      if (!settled) finish(new Error("game-login-closed"));
    });
    socket.on("data", (chunk) => {
      if (received.length + chunk.length > 8192) return finish(new Error("invalid-login-response"));
      received = Buffer.concat([received, chunk]);
      if (received.length < 2) return;
      const frameLength = received.readUInt16LE(0);
      if (frameLength < 12 || frameLength > 4096) return finish(new Error("invalid-login-response"));
      if (received.length < frameLength + 2) return;
      const frame = received.subarray(2, frameLength + 2);
      const checksum = frame.readUInt32LE(0);
      const encrypted = frame.subarray(4);
      const actualChecksum = Buffer.alloc(4);
      actualChecksum.writeUInt32LE(adler32(encrypted));
      const expectedChecksum = Buffer.alloc(4);
      expectedChecksum.writeUInt32LE(checksum);
      if (!timingSafeEqual(actualChecksum, expectedChecksum)) return finish(new Error("invalid-login-response"));
      try {
        const decrypted = decryptXtea(encrypted, keyWords);
        const innerLength = decrypted.readUInt16LE(0);
        if (innerLength < 1 || innerLength + 2 > decrypted.length) throw new Error("invalid-login-response");
        const result = parseAccountActionResponse(decrypted.subarray(2, innerLength + 2), action);
        finish(null, result);
      } catch {
        finish(new Error("invalid-login-response"));
      }
    });
    socket.setTimeout(LOGIN_TIMEOUT_MS, () => finish(new Error("game-login-timeout")));
    socket.connect({ host, port }, () => socket.write(packet));
  });
}

function verifyGameCredentials(host, port, username, password, buildToken, xteaKey = randomBytes(16)) {
  return exchangeGameAccountAction(host, port, username, password, buildToken, "website-login", xteaKey);
}

async function getSignedOnlineServerManifest(origin) {
  const signal = AbortSignal.timeout(4000);
  const [manifestResponse, signatureResponse] = await Promise.all([
    fetch(new URL("/public/server.json", origin), { cache: "no-store", redirect: "error", signal }),
    fetch(new URL("/public/server.sig", origin), { cache: "no-store", redirect: "error", signal })
  ]);
  if (!manifestResponse.ok || !signatureResponse.ok) throw new Error("server-unavailable");
  const [manifestText, signatureText] = await Promise.all([manifestResponse.text(), signatureResponse.text()]);
  const manifest = verifySignedManifest(manifestText, signatureText);

  if (manifest.schemaVersion !== 2 ||
      manifest.status !== "online" ||
      manifest.protocol !== 854 ||
      !isPublicIpv4(manifest.loginHost) ||
      !Number.isInteger(manifest.loginPort) || manifest.loginPort < 1 || manifest.loginPort > 65535 ||
      !/^[a-f0-9]{64}$/i.test(manifest.clientBuildToken || "")) {
    throw new Error("server-unavailable");
  }
  return manifest;
}

export function verifySignedManifest(manifestText, signatureText) {
  if (manifestText.length > MAX_MANIFEST_BYTES || signatureText.length > MAX_MANIFEST_BYTES) throw new Error("server-unavailable");

  const manifestBytes = Buffer.from(manifestText, "utf8");
  const manifest = JSON.parse(manifestText);
  const signature = JSON.parse(signatureText);
  const digest = createHash("sha256").update(manifestBytes).digest("hex");
  if (signature.schemaVersion !== 1 ||
      signature.algorithm !== "RSASSA-PKCS1-v1_5-SHA256" ||
      signature.keyId !== signingKey.keyId ||
      signature.manifestSha256 !== digest ||
      typeof signature.signature !== "string") {
    throw new Error("server-unavailable");
  }
  const publicKey = {
    key: {
      kty: "RSA",
      n: signingKey.modulus.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      e: signingKey.exponent.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      alg: "RS256",
      ext: true
    },
    format: "jwk"
  };
  if (!verifySignature("RSA-SHA256", manifestBytes, publicKey, Buffer.from(signature.signature, "base64"))) {
    throw new Error("server-unavailable");
  }
  return manifest;
}

async function handle(request) {
  if (request.method !== "POST") return textResponse(405, '{"error":"method-not-allowed"}');
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(contentLength) || contentLength > 1024) return textResponse(400, '{"error":"invalid-request"}');

  const signingSecret = process.env.SITE_ACCESS_SIGNING_KEY || "";
  if (signingSecret.length < 48) return textResponse(503, '{"error":"login-unavailable"}');

  let body;
  try {
    const rawBody = await request.text();
    if (Buffer.byteLength(rawBody, "utf8") > 1024) return textResponse(400, '{"error":"invalid-request"}');
    body = JSON.parse(rawBody);
  } catch {
    return textResponse(400, '{"error":"invalid-request"}');
  }
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const timestamp = request.headers.get("x-shinobi-login-time") || "";
  const clientAddress = request.headers.get("x-shinobi-login-ip") || "";
  const proof = request.headers.get("x-shinobi-login-proof") || "";
  const now = Math.floor(Date.now() / 1000);
  if (!/^\d{10}$/.test(timestamp) || Math.abs(now - Number(timestamp)) > 30 ||
      clientAddress.length < 1 || clientAddress.length > 64 || /[\r\n,\s]/.test(clientAddress) ||
      !/^[A-Za-z0-9]{3,25}$/.test(username) || password.length < 4 || password.length > 64 ||
      !await verifyLoginRequestProof(signingSecret, timestamp, clientAddress, username, password, proof)) {
    return textResponse(404, '{"error":"not-found"}');
  }

  let manifest;
  try {
    manifest = await getSignedOnlineServerManifest(new URL(request.url).origin);
  } catch {
    return textResponse(503, '{"error":"login-unavailable"}');
  }

  try {
    const result = await verifyGameCredentials(manifest.loginHost, manifest.loginPort, username, password, manifest.clientBuildToken);
    return result.accepted
      ? textResponse(200, '{"authenticated":true}')
      : textResponse(401, '{"authenticated":false}');
  } catch {
    return textResponse(503, '{"error":"login-unavailable"}');
  }
}

export default { fetch: handle };

export { createLoginPacket, adler32, decryptXtea, verifyGameCredentials, getSignedOnlineServerManifest };
