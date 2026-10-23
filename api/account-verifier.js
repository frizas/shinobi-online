import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  pbkdf2,
  privateDecrypt,
  timingSafeEqual,
  verify as verifySignature,
  constants
} from "node:crypto";
import signingKey from "../public/manifest-signing-key.json" with { type: "json" };

const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;
const PRIVATE_SNAPSHOT_PATH = "/public/account-verifiers.enc.json";
const SIGNATURE_PATH = "/public/account-verifiers.sig.json";

function trustedPublicKey(key = signingKey) {
  return {
    key: {
      kty: "RSA",
      n: key.modulus.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      e: key.exponent.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      alg: "RS256",
      ext: true
    },
    format: "jwk"
  };
}

export function verifySignedAccountEnvelope(envelopeText, signatureText, key = signingKey) {
  if (typeof envelopeText !== "string" || typeof signatureText !== "string" ||
      Buffer.byteLength(envelopeText, "utf8") > MAX_ENVELOPE_BYTES ||
      Buffer.byteLength(signatureText, "utf8") > 4096) {
    throw new Error("invalid-account-snapshot");
  }

  const envelopeBytes = Buffer.from(envelopeText, "utf8");
  let signature;
  try {
    signature = JSON.parse(signatureText);
  } catch {
    throw new Error("invalid-account-snapshot");
  }
  const digest = createHash("sha256").update(envelopeBytes).digest("hex");
  if (signature.schemaVersion !== 1 ||
      signature.algorithm !== "RSASSA-PKCS1-v1_5-SHA256" ||
      signature.keyId !== key.keyId ||
      signature.manifestSha256 !== digest ||
      typeof signature.signature !== "string" ||
      !verifySignature("RSA-SHA256", envelopeBytes, trustedPublicKey(key), Buffer.from(signature.signature, "base64"))) {
    throw new Error("invalid-account-snapshot");
  }
  return true;
}

function validateSnapshot(value) {
  if (!value || value.schemaVersion !== 1 || value.source !== "production-account-database" ||
      typeof value.refreshedAt !== "string" || !Number.isFinite(Date.parse(value.refreshedAt)) ||
      !Array.isArray(value.accounts) || value.accounts.length > 100000) {
    throw new Error("invalid-account-snapshot");
  }

  const accounts = new Map();
  for (const account of value.accounts) {
    if (!account || typeof account.username !== "string" ||
        !/^[A-Za-z0-9]{3,25}$/.test(account.username) ||
        typeof account.passwordVerifier !== "string" ||
        !(/^(?:\$shinobi\$pbkdf2-sha256\$\d+\$[a-f0-9]{32}\$[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})$/i.test(account.passwordVerifier))) {
      throw new Error("invalid-account-snapshot");
    }
    const key = account.username.toLowerCase();
    if (accounts.has(key)) throw new Error("invalid-account-snapshot");
    accounts.set(key, account.passwordVerifier);
  }
  return { refreshedAt: value.refreshedAt, accounts };
}

export function decryptAccountVerifierSnapshot(envelopeText, signatureText, privateKeyPem, trustedKey = signingKey) {
  if (typeof privateKeyPem !== "string" || privateKeyPem.length < 100) {
    throw new Error("account-snapshot-key-unavailable");
  }
  verifySignedAccountEnvelope(envelopeText, signatureText, trustedKey);

  let envelope;
  try {
    envelope = JSON.parse(envelopeText);
  } catch {
    throw new Error("invalid-account-snapshot");
  }
  if (envelope.schemaVersion !== 1 || envelope.algorithm !== "RSA-OAEP-SHA256+A256GCM" ||
      !/^[a-f0-9]{64}$/i.test(envelope.encryptionKeyId || "")) {
    throw new Error("invalid-account-snapshot");
  }

  let dataKey;
  try {
    const encryptionPrivateKey = createPrivateKey(privateKeyPem);
    const publicJwk = createPublicKey(encryptionPrivateKey).export({ format: "jwk" });
    const modulus = Buffer.from(publicJwk.n, "base64url").toString("base64");
    const exponent = Buffer.from(publicJwk.e, "base64url").toString("base64");
    const keySize = Buffer.from(publicJwk.n, "base64url").length * 8;
    const keyDescriptor = `RSA-${keySize}|${modulus}|${exponent}`;
    const keyId = createHash("sha256").update(keyDescriptor, "utf8").digest("hex");
    if (envelope.encryptionKeyId.toLowerCase() !== keyId) throw new Error("invalid-account-snapshot");
    dataKey = privateDecrypt({
      key: encryptionPrivateKey,
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(envelope.encryptedKey, "base64"));
    if (dataKey.length !== 32) throw new Error("invalid-account-snapshot");

    const nonce = Buffer.from(envelope.nonce, "base64");
    const tag = Buffer.from(envelope.tag, "base64");
    const ciphertext = Buffer.from(envelope.ciphertext, "base64");
    if (nonce.length !== 12 || tag.length !== 16 || ciphertext.length > MAX_ENVELOPE_BYTES) {
      throw new Error("invalid-account-snapshot");
    }

    const decipher = createDecipheriv("aes-256-gcm", dataKey, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return validateSnapshot(JSON.parse(plaintext.toString("utf8")));
  } catch {
    throw new Error("invalid-account-snapshot");
  } finally {
    if (dataKey) dataKey.fill(0);
  }
}

export async function getAccountVerifierSnapshot(
  origin,
  privateKeyPem = process.env.SITE_ACCOUNT_SNAPSHOT_PRIVATE_KEY_PEM || "",
  trustedKey = signingKey
) {
  if (typeof privateKeyPem !== "string" || privateKeyPem.length < 100) {
    throw new Error("account-snapshot-key-unavailable");
  }
  const signal = AbortSignal.timeout(5000);
  const [snapshotResponse, signatureResponse] = await Promise.all([
    fetch(new URL(PRIVATE_SNAPSHOT_PATH, origin), { cache: "no-store", redirect: "error", signal }),
    fetch(new URL(SIGNATURE_PATH, origin), { cache: "no-store", redirect: "error", signal })
  ]);
  if (!snapshotResponse.ok || !signatureResponse.ok) throw new Error("account-snapshot-unavailable");
  const [envelopeText, signatureText] = await Promise.all([snapshotResponse.text(), signatureResponse.text()]);
  return decryptAccountVerifierSnapshot(envelopeText, signatureText, privateKeyPem, trustedKey);
}

function derivePbkdf2(password, salt, iterations) {
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, 32, "sha256", (error, derived) => error ? reject(error) : resolve(derived));
  });
}

export async function verifySnapshotPassword(snapshot, username, password) {
  if (!snapshot?.accounts || typeof username !== "string" || typeof password !== "string" ||
      !/^[A-Za-z0-9]{3,25}$/.test(username) || password.length < 4 || password.length > 64) {
    return false;
  }
  const stored = snapshot.accounts.get(username.toLowerCase());
  if (!stored) return false;

  let actual;
  let expected;
  const pbkdf2Match = /^\$shinobi\$pbkdf2-sha256\$(\d+)\$([a-f0-9]{32})\$([a-f0-9]{64})$/i.exec(stored);
  if (pbkdf2Match) {
    const iterations = Number(pbkdf2Match[1]);
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) return false;
    actual = await derivePbkdf2(password, Buffer.from(pbkdf2Match[2], "hex"), iterations);
    expected = Buffer.from(pbkdf2Match[3], "hex");
  } else if (/^[a-f0-9]{40}$/i.test(stored)) {
    actual = createHash("sha1").update(password, "utf8").digest();
    expected = Buffer.from(stored, "hex");
  } else if (/^[a-f0-9]{32}$/i.test(stored)) {
    actual = createHash("md5").update(password, "utf8").digest();
    expected = Buffer.from(stored, "hex");
  } else {
    return false;
  }
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export { validateSnapshot };
