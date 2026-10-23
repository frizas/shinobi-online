import assert from "node:assert/strict";
import {
  createCipheriv,
  createHash,
  generateKeyPairSync,
  pbkdf2Sync,
  privateDecrypt,
  publicEncrypt,
  sign
} from "node:crypto";
import { createWebsiteLoginHandler } from "../api/website-login.js";
import { decryptAccountVerifierSnapshot, getAccountVerifierSnapshot } from "../api/account-verifier.js";
import { createLoginRequestProof } from "../session.js";

const siteSigningSecret = "temporary-test-signing-key-with-at-least-48-bytes";
process.env.SITE_ACCESS_SIGNING_KEY = siteSigningSecret;

function keyDescriptor(keyObject) {
  const jwk = keyObject.export({ format: "jwk" });
  const modulus = Buffer.from(jwk.n, "base64url").toString("base64");
  const exponent = Buffer.from(jwk.e, "base64url").toString("base64");
  const keySize = Buffer.from(jwk.n, "base64url").length * 8;
  const keyId = `sha256:${createHash("sha256").update(`RSA-${keySize}|${modulus}|${exponent}`).digest("hex")}`;
  return { modulus, exponent, keyId };
}

function toPem(label, bytes) {
  const encoded = bytes.toString("base64");
  const lines = encoded.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function encryptSnapshot(payload, encryptionPublicKey, signingPrivateKey, signingPublicKey) {
  const dataKey = Buffer.from("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "hex");
  const nonce = Buffer.from("aabbccddeeff001122334455", "hex");
  const cipher = createCipheriv("aes-256-gcm", dataKey, nonce);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const publicIdentity = keyDescriptor(encryptionPublicKey);
  const envelope = JSON.stringify({
    schemaVersion: 1,
    algorithm: "RSA-OAEP-SHA256+A256GCM",
    encryptionKeyId: publicIdentity.keyId.slice("sha256:".length),
    encryptedKey: publicEncrypt({ key: encryptionPublicKey, oaepHash: "sha256" }, dataKey).toString("base64"),
    nonce: nonce.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64")
  });
  const signatureIdentity = keyDescriptor(signingPublicKey);
  const signatureEnvelope = JSON.stringify({
    schemaVersion: 1,
    algorithm: "RSASSA-PKCS1-v1_5-SHA256",
    keyId: signatureIdentity.keyId,
    manifestSha256: createHash("sha256").update(envelope, "utf8").digest("hex"),
    signature: sign("RSA-SHA256", Buffer.from(envelope), signingPrivateKey).toString("base64")
  });
  dataKey.fill(0);
  return { envelope, signatureEnvelope, publicIdentity, signatureIdentity };
}

const encryption = generateKeyPairSync("rsa", { modulusLength: 3072 });
const signer = generateKeyPairSync("rsa", { modulusLength: 3072 });
const encryptionPrivatePem = toPem("PRIVATE KEY", encryption.privateKey.export({ type: "pkcs8", format: "der" }));
const trustedSigningKey = {
  ...keyDescriptor(signer.publicKey),
  ...(() => {
    const jwk = signer.publicKey.export({ format: "jwk" });
    return {
      modulus: Buffer.from(jwk.n, "base64url").toString("base64"),
      exponent: Buffer.from(jwk.e, "base64url").toString("base64")
    };
  })()
};

const modernSalt = Buffer.from("0123456789abcdef", "ascii");
const modernHash = pbkdf2Sync("909090", modernSalt, 600000, 32, "sha256").toString("hex");
const payload = {
  schemaVersion: 1,
  source: "production-account-database",
  refreshedAt: new Date().toISOString(),
  accounts: [
    { username: "rizzou", passwordVerifier: `$shinobi$pbkdf2-sha256$600000$${modernSalt.toString("hex")}$${modernHash}` },
    { username: "LegacySha1", passwordVerifier: createHash("sha1").update("legacy-password").digest("hex") },
    { username: "LegacyMd5", passwordVerifier: createHash("md5").update("md5-password").digest("hex") }
  ]
};
const files = encryptSnapshot(payload, encryption.publicKey, signer.privateKey, signer.publicKey);
const decrypted = decryptAccountVerifierSnapshot(files.envelope, files.signatureEnvelope, encryptionPrivatePem, trustedSigningKey);
assert.equal(decrypted.accounts.size, 3);
assert.throws(() => decryptAccountVerifierSnapshot(files.envelope, files.signatureEnvelope, encryptionPrivatePem, { ...trustedSigningKey, keyId: "sha256:" + "0".repeat(64) }));
assert.throws(() => decryptAccountVerifierSnapshot(files.envelope, files.signatureEnvelope.replace("signature", "forged"), encryptionPrivatePem, trustedSigningKey));

const calls = [];
globalThis.fetch = async (url) => {
  const path = new URL(url).pathname;
  calls.push(path);
  if (path === "/public/account-verifiers.enc.json") return new Response(files.envelope, { status: 200 });
  if (path === "/public/account-verifiers.sig.json") return new Response(files.signatureEnvelope, { status: 200 });
  throw new Error(`Unexpected server dependency: ${path}`);
};
const handler = {
  fetch: createWebsiteLoginHandler({
    loadAccountSnapshot: (origin) => getAccountVerifierSnapshot(origin, encryptionPrivatePem, trustedSigningKey)
  })
};

async function submitLogin(username, password) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const clientIp = "192.0.2.9";
  const proof = await createLoginRequestProof(siteSigningSecret, timestamp, clientIp, username, password);
  return handler.fetch(new Request("https://shinobionline.vercel.app/api/website-login", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-shinobi-login-time": timestamp,
      "x-shinobi-login-ip": clientIp,
      "x-shinobi-login-proof": proof
    },
    body: JSON.stringify({ username, password })
  }));
}

assert.equal((await submitLogin("rizzou", "909090")).status, 200, "a correct modern game credential is accepted");
assert.equal((await submitLogin("RIZZOU", "wrong-password")).status, 401, "wrong passwords are rejected case-insensitively by account name");
assert.equal((await submitLogin("LegacySha1", "legacy-password")).status, 200, "legacy SHA-1 game credentials remain compatible");
assert.equal((await submitLogin("LegacyMd5", "md5-password")).status, 200, "legacy MD5 game credentials remain compatible");
assert.deepEqual(calls, [
  "/public/account-verifiers.enc.json", "/public/account-verifiers.sig.json",
  "/public/account-verifiers.enc.json", "/public/account-verifiers.sig.json",
  "/public/account-verifiers.enc.json", "/public/account-verifiers.sig.json",
  "/public/account-verifiers.enc.json", "/public/account-verifiers.sig.json"
], "offline account checks fetch only the encrypted verifier snapshot, never the game manifest or game login endpoint");

console.log("Website offline account auth passed: signed encrypted snapshot, PBKDF2 and legacy hashes, exact credential behavior, and zero game-server dependency.");
