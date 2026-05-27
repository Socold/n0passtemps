#!/usr/bin/env node
//
// verify.mjs - verify an assertion against the JWKS endpoint.
//
// Usage:
//   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
//   N0PASSTEMPS_EXPECTED_AUDIENCE=00000000-0000-0000-0000-000000000000 \
//   node verify.mjs '<assertion>'
//
// Node 20 or later. No dependencies: the Ed25519 check comes from the built-in
// crypto module, which imports an OKP JWK directly.
//
// N0PASSTEMPS_EXPECTED_AUDIENCE is the id of the API key the ceremony was
// performed for, as GET /admin/v1/api-keys reports it. It is mandatory:
// verifying without pinning the audience accepts a token minted for a
// different key, which is the one thing pinning exists to prevent.
// N0PASSTEMPS_ISSUER pins iss and defaults to n0passtemps, which is the
// shipped configuration default.
//
// No API key is needed. The JWKS route carries no credential, because its
// contents are public keys and an integrating application has to be able to
// fetch them in order to verify offline.

import { createPublicKey, createHash, verify as cryptoVerify } from "node:crypto";
import process from "node:process";

const DEFAULT_ISSUER = "n0passtemps";
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;

// The alphabet of RFC 4648 section 5 with no padding. A JWS segment has exactly
// one valid spelling; accepting a second would let an attacker re-encode a
// captured header or payload into a different string that a laxer
// implementation would still read past the signature check.
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function requireEnv(name, hint) {
  const value = (process.env[name] ?? "").trim();
  if (value === "") {
    process.stderr.write(`${name} is not set. ${hint}\n`);
    process.exit(2);
  }
  return value;
}

function decodeSegment(segment) {
  if (typeof segment !== "string" || segment === "" || !BASE64URL.test(segment)) {
    return null;
  }
  const raw = Buffer.from(segment, "base64url");
  // Buffer.from is lenient about a final quantum whose unused bits are not
  // zero, so the decode is confirmed by re-encoding and comparing.
  if (raw.toString("base64url") !== segment) {
    return null;
  }
  return raw;
}

// RFC 7638 section 3 fixes the hash input as the JSON object of the required
// members only, with no whitespace and the member names in lexicographic
// order; RFC 8037 section 2 names those members for an OKP key. The
// construction has to be exact, because two implementations that disagree
// derive different identifiers for the same key.
function jwkThumbprint(publicKey) {
  const document = `{"crv":"Ed25519","kty":"OKP","x":"${publicKey.toString("base64url")}"}`;
  return createHash("sha256").update(document).digest("base64url");
}

function loadKeys(jwks) {
  const keys = new Map();

  for (const entry of jwks?.keys ?? []) {
    if (entry?.kty !== "OKP" || entry?.crv !== "Ed25519") continue;
    if (entry.use !== undefined && entry.use !== "sig") continue;
    if (entry.alg !== undefined && entry.alg !== "EdDSA") continue;
    if (typeof entry.kid !== "string" || entry.kid === "") continue;

    const raw = decodeSegment(entry.x);
    if (raw === null || raw.length !== ED25519_PUBLIC_KEY_SIZE) continue;

    // The service derives kid from the key itself, so a mismatch means the
    // document was not produced the way this verifier expects. Skipped rather
    // than trusted.
    if (jwkThumbprint(raw) !== entry.kid) continue;

    // createPublicKey takes the OKP JWK as it stands. Passing the JWK rather
    // than reassembling DER by hand keeps one fewer encoding to get wrong.
    keys.set(entry.kid, createPublicKey({ key: entry, format: "jwk" }));
  }

  return keys;
}

// Every failure returns the same thing, as the service's own verifier does.
// Reporting which check failed would tell an attacker whether a forged token
// had the right audience, whether a key identifier exists, or whether a
// captured token is merely expired rather than wrongly signed.
function verifyAssertion(token, keys, expectedIssuer, expectedAudience, skewSeconds) {
  if (!expectedIssuer || !expectedAudience) return null;

  // RFC 7515 section 7.1: the compact serialisation is exactly three segments.
  // Splitting on every full stop and requiring three rejects a fourth segment,
  // which a lenient parser ignores while a second recipient might read it, and
  // rejects a two-segment unsecured JWS outright.
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const rawHeader = decodeSegment(parts[0]);
  if (rawHeader === null) return null;

  let header;
  try {
    header = JSON.parse(rawHeader.toString("utf8"));
  } catch {
    return null;
  }
  if (header === null || typeof header !== "object") return null;

  // The algorithm is fixed here, never read from the token to decide what to
  // do. This single check stops the whole family of confusion attacks:
  // "alg":"none" with an empty signature, and "alg":"HS256" with the published
  // public key used as an HMAC secret.
  if (header.alg !== "EdDSA") return null;

  // RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a "crit"
  // extension it does not understand. This verifier understands none.
  if (Array.isArray(header.crit) ? header.crit.length > 0 : header.crit !== undefined) {
    return null;
  }

  // A JWS signed by the same key for another purpose must not pass as an
  // assertion.
  if (header.typ !== undefined && header.typ !== "" && header.typ !== "JWT") return null;

  // The key is selected by kid, and one candidate only. Trying every known key
  // in turn would mean a token signed under a revoked key still verifies as
  // long as that key remains published.
  if (typeof header.kid !== "string" || header.kid === "") return null;
  const key = keys.get(header.kid);
  if (key === undefined) return null;

  const signature = decodeSegment(parts[2]);
  if (signature === null || signature.length !== ED25519_SIGNATURE_SIZE) return null;

  // The signature covers the header and the payload exactly as received, which
  // is why the encoded form is what gets verified rather than any
  // re-serialisation of the parsed structures. Ed25519 takes no digest
  // algorithm, hence the null first argument.
  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  if (!cryptoVerify(null, signingInput, key, signature)) return null;

  // Only now is the payload worth parsing.
  const rawPayload = decodeSegment(parts[1]);
  if (rawPayload === null) return null;

  let claims;
  try {
    claims = JSON.parse(rawPayload.toString("utf8"));
  } catch {
    return null;
  }
  if (claims === null || typeof claims !== "object") return null;

  if (claims.iss !== expectedIssuer) return null;
  if (claims.aud !== expectedAudience) return null;
  if (!claims.sub || !Array.isArray(claims.amr) || claims.amr.length === 0) return null;

  // exp is required. Treating a missing exp as no expiry turns a captured
  // assertion into a permanent credential.
  if (!Number.isInteger(claims.exp) || claims.exp === 0) return null;

  const now = Math.floor(Date.now() / 1000);
  if (now > claims.exp + skewSeconds) return null;
  if (Number.isInteger(claims.nbf) && claims.nbf !== 0 && now < claims.nbf - skewSeconds) {
    return null;
  }

  return claims;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length !== 1 || argv[0].startsWith("-")) {
    process.stderr.write("Usage: node verify.mjs '<assertion>'\n");
    return 2;
  }
  const token = argv[0].trim();
  if (token === "") {
    process.stderr.write("The assertion is empty.\n");
    return 2;
  }

  const baseUrl = requireEnv(
    "N0PASSTEMPS_URL",
    "Set it to the base URL, for example http://127.0.0.1:8080",
  );
  const expectedAudience = requireEnv(
    "N0PASSTEMPS_EXPECTED_AUDIENCE",
    "Set it to the id of the API key the ceremony was performed for, from GET /admin/v1/api-keys.",
  );
  const expectedIssuer = (process.env.N0PASSTEMPS_ISSUER ?? "").trim() || DEFAULT_ISSUER;
  const skewSeconds = 30;

  const url = new URL("/v1/.well-known/jwks.json", baseUrl);
  process.stdout.write(`Fetching ${url.href}\n`);

  const response = await fetch(url);
  if (!response.ok) {
    process.stderr.write(`The JWKS endpoint answered ${response.status}.\n`);
    return 1;
  }
  const jwks = await response.json();

  const keys = loadKeys(jwks);
  if (keys.size === 0) {
    process.stderr.write("The JWK Set contains no usable Ed25519 signing key.\n");
    return 1;
  }
  process.stdout.write(`  keys published: ${[...keys.keys()].join(", ")}\n\n`);
  process.stdout.write(`Pinning iss=${expectedIssuer} aud=${expectedAudience}\n`);

  const claims = verifyAssertion(token, keys, expectedIssuer, expectedAudience, skewSeconds);
  if (claims === null) {
    process.stderr.write("\nThe assertion is not valid.\n");
    process.stderr.write(
      "No further detail is available by design. Reporting which check failed\n" +
        "would tell an attacker whether a forged token had the right audience,\n" +
        "whether a key identifier exists, or whether a captured token is merely\n" +
        "expired rather than wrongly signed.\n",
    );
    return 1;
  }

  process.stdout.write("\nThe assertion is valid.\n");
  for (const name of ["iss", "sub", "aud", "iat", "nbf", "exp", "jti"]) {
    process.stdout.write(`  ${name}: ${claims[name]}\n`);
  }
  process.stdout.write(`  amr: ${claims.amr.join(", ")}\n`);
  if (claims.cid) process.stdout.write(`  cid: ${claims.cid}\n`);
  if (claims.tid) process.stdout.write(`  tid: ${claims.tid}\n`);

  process.stdout.write(
    "\nTwo things remain for a real integration.\n\n" +
      "Record jti in a replay cache until exp passes. A valid signature does\n" +
      "not make a token single use, and an assertion captured in transit stays\n" +
      "replayable for the rest of its lifetime otherwise.\n\n" +
      "Apply your own policy to amr. A WebAuthn assertion with user\n" +
      "verification is a different assurance from a recovery code, which is why\n" +
      "the factors are listed separately rather than collapsed into a boolean.\n",
  );
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof TypeError && error.cause) {
    process.stderr.write(`Could not reach the service: ${error.cause.message ?? error.cause}\n`);
    process.exitCode = 1;
  } else {
    throw error;
  }
}
