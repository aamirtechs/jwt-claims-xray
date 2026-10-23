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
