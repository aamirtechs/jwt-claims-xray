"use strict";
// JWT Claims Xray core logic: pure functions, no DOM, no fetch, no network.

function base64UrlDecode(input) {
  if (typeof input !== "string") throw new Error("Input must be a string");
  let s = input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  while (s.length % 4) s += "=";
  // Validate characters after normalisation (allow padding)
  if (!/^[A-Za-z0-9+/=]+$/.test(s) && s.length) throw new Error("Invalid base64url characters");
  let decoded;
  if (typeof Buffer !== "undefined") {
    decoded = Buffer.from(s, "base64").toString("utf8");
  } else {
    const bin = atob(s);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    decoded = new TextDecoder("utf-8").decode(bytes);
  }
  return decoded;
}

function base64UrlEncode(text) {
  let b64;
  if (typeof Buffer !== "undefined") {
    b64 = Buffer.from(String(text), "utf8").toString("base64");
  } else {
    const bytes = new TextEncoder().encode(String(text));
    let bin = ""; bytes.forEach((b) => { bin += String.fromCharCode(b); });
    b64 = btoa(bin);
  }
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(input) {
  let s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(s, "base64"));
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function decodeJwt(token) {
  if (!token || typeof token !== "string") throw new Error("Paste a token first");
  const trimmed = token.trim();
  const parts = trimmed.split(".");
  if (parts.length !== 3) throw new Error("A JWT must have 3 parts separated by dots. Found " + parts.length + ".");
  let header, payload;
  try { header = JSON.parse(base64UrlDecode(parts[0])); } catch (e) { throw new Error("Header is not valid JSON: " + e.message); }
  try { payload = JSON.parse(base64UrlDecode(parts[1])); } catch (e) { throw new Error("Payload is not valid JSON: " + e.message); }
  return { header: header, payload: payload, signature: parts[2], signingInput: parts[0] + "." + parts[1], parts: parts };
}

function expiryStatus(payload, nowSec) {
  const now = typeof nowSec === "number" ? nowSec : Math.floor(Date.now() / 1000);
  if (!payload || typeof payload.exp !== "number") return { status: "no-exp", label: "No exp claim", secondsRemaining: null, expired: false };
  const diff = payload.exp - now;
  if (diff <= 0) return { status: "expired", label: "Expired " + Math.abs(diff) + " seconds ago", secondsRemaining: diff, expired: true };
  return { status: "valid", label: "Valid for " + diff + " more seconds", secondsRemaining: diff, expired: false };
}

function timeClaimStatus(payload, nowSec) {
  const now = typeof nowSec === "number" ? nowSec : Math.floor(Date.now() / 1000);
  const issues = [];
  if (payload && typeof payload.nbf === "number" && now < payload.nbf) issues.push("Not yet valid: nbf is in the future");
  if (payload && typeof payload.iat === "number" && payload.iat > now + 60) issues.push("iat is in the future");
  if (payload && typeof payload.exp === "number" && typeof payload.iat === "number" && payload.exp < payload.iat) issues.push("exp is before iat");
  return issues;
}

const TIME_CLAIMS = { exp: "Expires at", iat: "Issued at", nbf: "Not valid before", auth_time: "Authenticated at" };
const CLAIM_DESCRIPTIONS = {
  iss: "Issuer", sub: "Subject", aud: "Audience", exp: "Expires at", nbf: "Not valid before", iat: "Issued at",
  jti: "JWT ID", name: "Full name", email: "Email address", scope: "Scopes", scp: "Scopes", roles: "Roles", typ: "Token type"
};

function humaniseClaims(payload, nowSec) {
  const now = typeof nowSec === "number" ? nowSec : Math.floor(Date.now() / 1000);
  return Object.keys(payload || {}).sort().map((key) => {
    const value = payload[key];
    let human = null;
    if (TIME_CLAIMS[key] && typeof value === "number") {
      const d = new Date(value * 1000);
      human = d.toUTCString() + " (" + (value - now) + "s relative to now)";
    }
    return { claim: key, description: CLAIM_DESCRIPTIONS[key] || "", value: value, human: human };
  });
}

function diffClaims(a, b) {
  const added = [], removed = [], changed = [], unchanged = [];
  const keysA = new Set(Object.keys(a || {}));
  const keysB = new Set(Object.keys(b || {}));
  keysB.forEach((k) => { if (!keysA.has(k)) added.push({ claim: k, to: b[k] }); });
  keysA.forEach((k) => {
    if (!keysB.has(k)) removed.push({ claim: k, from: a[k] });
    else if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) changed.push({ claim: k, from: a[k], to: b[k] });
    else unchanged.push({ claim: k, value: a[k] });
  });
  const sortFn = (x, y) => x.claim.localeCompare(y.claim);
  return { added: added.sort(sortFn), removed: removed.sort(sortFn), changed: changed.sort(sortFn), unchanged: unchanged.sort(sortFn) };
}

const DEFAULT_SENSITIVE = ["email", "name", "phone", "address", "given_name", "family_name", "sub"];

function redactPayload(payload, extraSensitive) {
  const sensitive = new Set(DEFAULT_SENSITIVE.concat(extraSensitive || []));
  const out = {};
  Object.keys(payload || {}).forEach((k) => { out[k] = sensitive.has(k.toLowerCase()) ? "REDACTED" : payload[k]; });
  return out;
}

function buildRedactedCopy(token, extraSensitive) {
  const decoded = decodeJwt(token);
  const redactedPayload = redactPayload(decoded.payload, extraSensitive);
  const headerPart = base64UrlEncode(JSON.stringify(decoded.header));
  const payloadPart = base64UrlEncode(JSON.stringify(redactedPayload));
  return {
    token: headerPart + "." + payloadPart + ".REDACTED",
    header: decoded.header,
    payload: redactedPayload,
    text: "Header: " + JSON.stringify(decoded.header, null, 2) + "\nPayload (redacted): " + JSON.stringify(redactedPayload, null, 2) + "\nSignature: REDACTED"
  };
}

function supportedAlg(header) {
  if (!header || !header.alg) return null;
  if (["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384"].indexOf(header.alg) !== -1) return header.alg;
  return null;
}

// Warn about risky alg/key combinations. Pure: no DOM, no fetch, no network.
// Returns an array of warning strings (possibly empty).
function algWarnings(alg, keyText) {
  const warnings = [];
  const a = typeof alg === "string" ? alg.trim().toLowerCase() : "";
  if (!a || a === "none") {
    warnings.push("Warning: the header declares alg \"none\" — this token is unsigned and cannot be verified. Never accept it as proof of anything.");
    return warnings;
  }
  const key = typeof keyText === "string" ? keyText.trim() : "";
  const looksPemPublic = /-----BEGIN [^-]*PUBLIC KEY-----/.test(key);
  const isHmac = a.indexOf("hs") === 0;
  const isAsymmetric = a.indexOf("rs") === 0 || a.indexOf("es") === 0 || a.indexOf("ps") === 0;
  if (isHmac && key && looksPemPublic) {
    warnings.push("Warning: the token uses HMAC (" + alg + "), which needs the shared secret, but the provided key looks like a PEM public key. Paste the shared secret instead.");
  } else if (isAsymmetric && key && !looksPemPublic) {
    warnings.push("Warning: the token uses an asymmetric algorithm (" + alg + "), which needs the matching public key, but the provided key does not look like a PEM public key. Paste the PEM public key instead.");
  }
  return warnings;
}

// JWKS support: pick a verification key by kid from a JWKS the user pastes
// into the page. The JWKS is parsed locally and never fetched, so the
// zero-network guarantee stays intact.
function parseJwks(input) {
  let doc = input;
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) throw new Error("Paste a JWKS first");
    try { doc = JSON.parse(trimmed); } catch (e) { throw new Error("JWKS is not valid JSON: " + e.message); }
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("JWKS must be an object with a keys array");
  if (!Array.isArray(doc.keys)) throw new Error("JWKS must have a keys array");
  doc.keys.forEach((k, i) => {
    if (!k || typeof k !== "object" || Array.isArray(k)) throw new Error("JWKS key at index " + i + " is not an object");
  });
  return doc.keys;
}

function expectedKtyForAlg(alg) {
  if (!alg) return null;
  if (alg.indexOf("HS") === 0) return "oct";
  if (alg.indexOf("RS") === 0 || alg.indexOf("PS") === 0) return "RSA";
  if (alg.indexOf("ES") === 0) return "EC";
  return null;
}

function expectedCurveForAlg(alg) {
  if (alg === "ES256") return "P-256";
  if (alg === "ES384") return "P-384";
  return null;
}

// Pick the key for a token: exact kid match when the header carries one;
// when there is no kid, the single key of a one-key JWKS. The key's kty
// (and EC curve) must fit the token's alg, so a mismatched key fails here
// with a clear message instead of a cryptic WebCrypto error.
function selectJwksKey(jwksInput, kid, alg) {
  const keys = parseJwks(jwksInput);
  let key = null;
  if (kid) {
    key = keys.filter((k) => k.kid === kid)[0] || null;
    if (!key) throw new Error("No key with kid '" + kid + "' in JWKS");
  } else {
    if (keys.length === 0) throw new Error("JWKS has no keys");
    if (keys.length > 1) throw new Error("Token has no kid and JWKS has " + keys.length + " keys; cannot pick one");
    key = keys[0];
  }
  if (alg) {
    const wantKty = expectedKtyForAlg(alg);
    if (wantKty && key.kty && key.kty !== wantKty) throw new Error("JWKS key kid '" + (key.kid || "") + "' has kty '" + key.kty + "' but alg '" + alg + "' needs '" + wantKty + "'");
    const wantCurve = expectedCurveForAlg(alg);
    if (wantCurve && key.crv && key.crv !== wantCurve) throw new Error("JWKS key kid '" + (key.kid || "") + "' is on curve '" + key.crv + "' but alg '" + alg + "' needs '" + wantCurve + "'");
  }
  return key;
}

const api = { base64UrlDecode, base64UrlEncode, base64UrlToBytes, decodeJwt, expiryStatus, timeClaimStatus, humaniseClaims, diffClaims, redactPayload, buildRedactedCopy, supportedAlg, algWarnings, parseJwks, selectJwksKey, DEFAULT_SENSITIVE };
if (typeof module !== "undefined" && module.exports) { module.exports = api; }
if (typeof window !== "undefined") { window.JwtClaimsXray = api; }
