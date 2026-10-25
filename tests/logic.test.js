const { test } = require("node:test");
const assert = require("node:assert/strict");
const L = require("../src/logic.js");

// Fake tokens assembled from parts at runtime. Payloads are obviously fake.
function makeToken(header, payload, sig) {
  return L.base64UrlEncode(JSON.stringify(header)) + "." + L.base64UrlEncode(JSON.stringify(payload)) + "." + (sig || "fakesig");
}

test("base64url round trip handles padding and url-safe chars", () => {
  const s = JSON.stringify({ hello: "world?" });
  assert.equal(L.base64UrlDecode(L.base64UrlEncode(s)), s);
  assert.ok(!L.base64UrlEncode(s).includes("="));
});

test("decodeJwt parses header and payload and rejects malformed tokens", () => {
  const tok = makeToken({ alg: "HS256", typ: "JWT" }, { sub: "user-example", exp: 2000000000 });
  const d = L.decodeJwt(tok);
  assert.equal(d.header.alg, "HS256");
  assert.equal(d.payload.sub, "user-example");
  assert.throws(() => L.decodeJwt("onlyonepart"), /3 parts/);
  assert.throws(() => L.decodeJwt(""), /Paste a token/);
});

test("expiryStatus reports valid, expired and no-exp correctly", () => {
  const now = 1700000000;
  assert.equal(L.expiryStatus({ exp: now + 3600 }, now).status, "valid");
  assert.equal(L.expiryStatus({ exp: now - 10 }, now).status, "expired");
  assert.equal(L.expiryStatus({ sub: "x" }, now).status, "no-exp");
  assert.equal(L.expiryStatus({ exp: now + 3600 }, now).secondsRemaining, 3600);
});

test("humaniseClaims formats time claims and sorts keys", () => {
  const rows = L.humaniseClaims({ sub: "user-example", exp: 1700003600 }, 1700000000);
  assert.equal(rows[0].claim, "exp");
  const expRow = rows.find((r) => r.claim === "exp");
  assert.match(expRow.human, /GMT|UTC/);
  assert.equal(expRow.description, "Expires at");
});

test("diffClaims finds added, removed and changed claims", () => {
  const diff = L.diffClaims({ a: 1, b: 2, c: 3 }, { b: 20, c: 3, d: 4 });
  assert.deepEqual(diff.added.map((x) => x.claim), ["d"]);
  assert.deepEqual(diff.removed.map((x) => x.claim), ["a"]);
  assert.deepEqual(diff.changed.map((x) => x.claim), ["b"]);
  assert.equal(diff.changed[0].from, 2);
  assert.equal(diff.changed[0].to, 20);
});

test("redaction masks sensitive claims and the signature", () => {
  const tok = makeToken({ alg: "HS256" }, { sub: "user-example", email: "person@example.com", role: "admin" });
  const red = L.buildRedactedCopy(tok);
  assert.equal(red.payload.email, "REDACTED");
  assert.equal(red.payload.sub, "REDACTED");
  assert.equal(red.payload.role, "admin");
  assert.ok(red.token.endsWith(".REDACTED"));
  assert.ok(!red.text.includes("person@example.com"));
});

test("timeClaimStatus flags future nbf and exp before iat", () => {
  const now = 1700000000;
  assert.ok(L.timeClaimStatus({ nbf: now + 100 }, now).length >= 1);
  assert.ok(L.timeClaimStatus({ iat: now, exp: now - 5 }, now).some((s) => s.includes("exp is before iat")));
  assert.deepEqual(L.timeClaimStatus({ iat: now - 10, exp: now + 100 }, now), []);
});

test("supportedAlg accepts common algs and rejects none/unknown", () => {
  assert.equal(L.supportedAlg({ alg: "RS256" }), "RS256");
  assert.equal(L.supportedAlg({ alg: "ES256" }), "ES256");
  assert.equal(L.supportedAlg({ alg: "none" }), null);
});

test("algWarnings flags alg none, missing alg and key-type mismatches", () => {
  const pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----";
  // alg "none" (and missing alg) warns and returns early
  assert.ok(L.algWarnings("none", "secret").some((s) => s.includes("unsigned")));
  assert.ok(L.algWarnings(undefined, "secret").some((s) => s.includes("unsigned")));
  // HMAC alg with a PEM public key is a mismatch
  assert.ok(L.algWarnings("HS256", pem).some((s) => s.includes("shared secret")));
  // asymmetric alg with a non-PEM key is a mismatch
  assert.ok(L.algWarnings("RS256", "just-a-secret").some((s) => s.includes("PEM public key")));
  assert.ok(L.algWarnings("ES256", "just-a-secret").some((s) => s.includes("PEM public key")));
  // matching pairs produce no warnings
  assert.deepEqual(L.algWarnings("HS256", "correct-horse-battery-staple"), []);
  assert.deepEqual(L.algWarnings("RS256", pem), []);
  assert.deepEqual(L.algWarnings("RS256", ""), []);
});

// Fake JWKS key material: structure-only fixtures, never real keys.
const FAKE_JWKS = { keys: [
  { kty: "RSA", kid: "key-example-1", use: "sig", alg: "RS256", n: "fake-modulus", e: "AQAB" },
  { kty: "EC", kid: "key-example-2", use: "sig", alg: "ES256", crv: "P-256", x: "fake-x", y: "fake-y" },
  { kty: "oct", kid: "key-example-3", use: "sig", alg: "HS256", k: "fake-secret" }
]};

test("parseJwks accepts an object or JSON string and rejects bad shapes", () => {
  assert.equal(L.parseJwks(FAKE_JWKS).length, 3);
  assert.equal(L.parseJwks(JSON.stringify(FAKE_JWKS))[1].kid, "key-example-2");
  assert.throws(() => L.parseJwks("not json"), /not valid JSON/);
  assert.throws(() => L.parseJwks(""), /Paste a JWKS/);
  assert.throws(() => L.parseJwks({}), /keys array/);
  assert.throws(() => L.parseJwks({ keys: ["nope"] }), /not an object/);
});

test("selectJwksKey picks by kid and validates kty and curve against alg", () => {
  assert.equal(L.selectJwksKey(FAKE_JWKS, "key-example-1", "RS256").kty, "RSA");
  assert.equal(L.selectJwksKey(FAKE_JWKS, "key-example-2", "ES256").crv, "P-256");
  assert.equal(L.selectJwksKey(FAKE_JWKS, "key-example-3", "HS256").kty, "oct");
  assert.throws(() => L.selectJwksKey(FAKE_JWKS, "key-missing", "RS256"), /No key with kid/);
  assert.throws(() => L.selectJwksKey(FAKE_JWKS, "key-example-2", "RS256"), /needs 'RSA'/);
  assert.throws(() => L.selectJwksKey(FAKE_JWKS, "key-example-1", "HS256"), /needs 'oct'/);
  const wrongCurve = { keys: [{ kty: "EC", kid: "k1", crv: "P-384", x: "x", y: "y" }] };
  assert.throws(() => L.selectJwksKey(wrongCurve, "k1", "ES256"), /needs 'P-256'/);
});

test("selectJwksKey without a kid uses the only key and refuses ambiguity", () => {
  const single = { keys: [{ kty: "RSA", kid: "only-key", n: "fake", e: "AQAB" }] };
  assert.equal(L.selectJwksKey(single, undefined, "RS256").kid, "only-key");
  assert.throws(() => L.selectJwksKey(FAKE_JWKS, undefined, "RS256"), /cannot pick one/);
  assert.throws(() => L.selectJwksKey({ keys: [] }, undefined, "RS256"), /no keys/);
});
