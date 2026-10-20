import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import net from "node:net";
import { adler32, createLoginPacket, exchangeGameAccountAction, parseWebsiteLoginResponse, verifyGameCredentials, verifySignedManifest } from "../api/website-login.js";
import handler from "../api/website-login.js";
import { createLoginRequestProof, verifyLoginRequestProof } from "../session.js";

const signingSecret = "temporary-test-signing-key-with-at-least-48-bytes";
process.env.SITE_ACCESS_SIGNING_KEY = signingSecret;

function writeU16(value) {
  const result = Buffer.allocUnsafe(2);
  result.writeUInt16LE(value);
  return result;
}

function writeString(value) {
  const body = Buffer.from(value, "utf8");
  return Buffer.concat([writeU16(body.length), body]);
}

function encryptXtea(payload, key) {
  const inner = Buffer.concat([writeU16(payload.length), payload]);
  const padded = Buffer.concat([inner, Buffer.alloc((8 - (inner.length % 8)) % 8)]);
  const delta = 0x9e3779b9;
  for (let offset = 0; offset < padded.length; offset += 8) {
    let left = padded.readUInt32LE(offset);
    let right = padded.readUInt32LE(offset + 4);
    let sum = 0;
    for (let round = 0; round < 32; round += 1) {
      left = (left + ((((right << 4) ^ (right >>> 5)) + right) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
      sum = (sum + delta) >>> 0;
      right = (right + ((((left << 4) ^ (left >>> 5)) + left) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    }
    padded.writeUInt32LE(left, offset);
    padded.writeUInt32LE(right, offset + 4);
  }
  return padded;
}

function responseFrame(accepted, key) {
  const payload = Buffer.concat([
    Buffer.from([0x67, 1]),
    writeString("website-login"),
    Buffer.from([accepted ? 1 : 0]),
    writeString(accepted ? "Login accepted." : "Invalid username or password."),
    Buffer.alloc(8)
  ]);
  const encrypted = encryptXtea(payload, key);
  const body = Buffer.allocUnsafe(4 + encrypted.length);
  body.writeUInt32LE(adler32(encrypted), 0);
  encrypted.copy(body, 4);
  return Buffer.concat([writeU16(body.length), body]);
}

function createTestGameServer() {
  return net.createServer((socket) => {
    let received = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length < 2) return;
      const length = received.readUInt16LE(0);
      if (received.length < length + 2) return;
      const frame = received.subarray(2, length + 2);
      assert.equal(frame.readUInt32LE(0), adler32(frame.subarray(4)));
      assert.equal(received.includes(Buffer.from("shinobiuser")), false);
      assert.equal(received.includes(Buffer.from("correct-horse")), false);
      socket.end(responseFrame(true, packet.keyWords));
    });
  });
}

const fixedXtea = Buffer.from("00112233445566778899aabbccddeeff", "hex");
const packet = createLoginPacket("shinobiuser", "correct-horse", "e".repeat(64), fixedXtea);
assert.equal(packet.keyWords.length, 4);
assert.equal(packet.packet.readUInt16LE(0), packet.packet.length - 2);
const packetBody = packet.packet.subarray(2);
assert.equal(packetBody.readUInt32LE(0), adler32(packetBody.subarray(4)));
assert.equal(packetBody.length, 4 + 17 + 128 + 128);
assert.equal(packet.packet.includes(Buffer.from("shinobiuser")), false, "account name is inside the RSA block");
assert.equal(packet.packet.includes(Buffer.from("correct-horse")), false, "password is inside the RSA block");

const successPayload = Buffer.concat([
  Buffer.from([0x67, 1]), writeString("website-login"), Buffer.from([1]),
  writeString("Login accepted."), Buffer.alloc(8)
]);
assert.deepEqual(parseWebsiteLoginResponse(successPayload), { accepted: true, message: "Login accepted." });
assert.deepEqual(parseWebsiteLoginResponse(Buffer.concat([
  Buffer.from([0x67, 1]), writeString("website-login"), Buffer.from([0]),
  writeString("Invalid username or password."), Buffer.alloc(8)
])), { accepted: false, message: "Invalid username or password." });
assert.throws(() => parseWebsiteLoginResponse(Buffer.concat([Buffer.from([0x67, 1]), writeString("create-character")])), /unexpected-login-response/);

const gameServer = createTestGameServer();
gameServer.listen(0, "127.0.0.1");
await once(gameServer, "listening");
const port = gameServer.address().port;
try {
  assert.deepEqual(await verifyGameCredentials("127.0.0.1", port, "shinobiuser", "correct-horse", "e".repeat(64), fixedXtea), {
    accepted: true,
    message: "Login accepted."
  });
} finally {
  gameServer.close();
  await once(gameServer, "close");
}

const publicManifest = await readFile(new URL("../public/server.json", import.meta.url), "utf8");
const publicSignature = await readFile(new URL("../public/server.sig", import.meta.url), "utf8");
const verifiedManifest = verifySignedManifest(publicManifest, publicSignature);
assert.ok(["maintenance", "online"].includes(verifiedManifest.status));

const timestamp = String(Math.floor(Date.now() / 1000));
const proof = await createLoginRequestProof(signingSecret, timestamp, "192.0.2.5", "shinobiuser", "correct-horse");
assert.equal(await verifyLoginRequestProof(signingSecret, timestamp, "192.0.2.5", "shinobiuser", "correct-horse", proof), true);
assert.equal(await verifyLoginRequestProof(signingSecret, timestamp, "192.0.2.5", "shinobiuser", "wrong-password", proof), false);

const directApiCall = await handler.fetch(new Request("https://shinobionline.vercel.app/api/website-login", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "shinobiuser", password: "correct-horse" })
}));
assert.equal(directApiCall.status, 404, "the public verifier rejects requests not signed by site middleware");

globalThis.fetch = async (url) => new Response(
  String(url).includes("server.sig") ? publicSignature : publicManifest,
  { status: 200, headers: { "content-type": "application/json" } }
);
const apiGameServer = createTestGameServer();
apiGameServer.listen(0, "127.0.0.1");
await once(apiGameServer, "listening");
const originalSocketConnect = net.Socket.prototype.connect;
let apiConnectionCount = 0;
net.Socket.prototype.connect = function (options, ...args) {
  if (options && typeof options === "object" && options.host === verifiedManifest.loginHost && options.port === verifiedManifest.loginPort) {
    apiConnectionCount += 1;
    return originalSocketConnect.call(this, { ...options, host: "127.0.0.1", port: apiGameServer.address().port }, ...args);
  }
  return originalSocketConnect.call(this, options, ...args);
};
try {
  const signedApiCall = await handler.fetch(new Request("https://shinobionline.vercel.app/api/website-login", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-shinobi-login-time": timestamp,
      "x-shinobi-login-ip": "192.0.2.5",
      "x-shinobi-login-proof": proof
    },
    body: JSON.stringify({ username: "shinobiuser", password: "correct-horse" })
  }));
  assert.equal(signedApiCall.status, 503, "the intentionally incomplete mock transport fails closed");
  assert.equal(apiConnectionCount, verifiedManifest.status === "online" ? 1 : 0,
    "only the signed online manifest may route an account check to the game endpoint");
} finally {
  net.Socket.prototype.connect = originalSocketConnect;
  apiGameServer.close();
  await once(apiGameServer, "close");
}
gameServer.close();
await once(gameServer, "close");

console.log("Website game-auth tests passed: RSA-framed credentials, XTEA result parsing, signed online/maintenance metadata, middleware proof, and status-appropriate login behavior.");
