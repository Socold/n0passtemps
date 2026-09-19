// Offline verification of the signed assertion a successful ceremony returns.
//
// The assertion is a compact JWS (RFC 7515) signed with Ed25519 under the
// "EdDSA" algorithm of RFC 8037, carrying JWT claims (RFC 7519). This module
// mirrors internal/assertion/assertion.go check for check, using node:crypto
// and nothing else.
//
// The JWS is parsed here rather than through a JWT library for the reason the
// service gives: the recurring vulnerabilities of those libraries are all on
// the parsing side. Honouring "alg":"none", letting the token choose which
// verification routine runs, and accepting a public key as an HMAC secret are
// each refused below by construction.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

import { InvalidAssertionError, TransportError } from "./errors.js";
import {
  MAX_RESPONSE_BYTES,
  describeFetchFailure,
  parseEndpointUrl,
  readCappedText,
} from "./internal.js";

export { InvalidAssertionError };

const ALG_EDDSA = "EdDSA";
const TYP_JWT = "JWT";
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;

// A genuine assertion is under one kilobyte. The bound keeps the work done on
// an unauthenticated string, before any signature is checked, proportionate.
const MAX_TOKEN_LENGTH = 8192;

// The alphabet of RFC 4648 section 5, with no padding.
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Decode one base64url segment, accepting exactly one spelling of it.
 *
 * "=", "+" and "/" are outside the alphabet and refused. Buffer.from is also
 * lenient about a final character whose unused low bits are not zero, so the
 * result is re-encoded and compared. Without both, an attacker could re-spell a
 * captured header, payload or signature into a different string that carries
 * the same bytes, which defeats any replay cache or log correlation keyed on
 * the token text and diverges from stricter verifiers.
 *
 * @param {unknown} segment
 * @returns {Buffer | null}
 */
function decodeSegment(segment) {
  if (typeof segment !== "string" || segment === "" || !BASE64URL.test(segment)) return null;
  const raw = Buffer.from(segment, "base64url");
  if (raw.toString("base64url") !== segment) return null;
  return raw;
}

function parseJsonObject(raw) {
  let value;
  try {
    // fatal: a segment that is not valid UTF-8 has no business being repaired
    // into U+FFFD and then interpreted.
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}

/**
 * RFC 7638 thumbprint of an Ed25519 public JWK, base64url without padding. The
 * service uses it as the `kid` of the key and of every assertion it signs.
 *
 * RFC 7638 section 3 fixes the hash input as the JSON object of the required
 * members only, no whitespace, member names in lexicographic order; RFC 8037
 * section 2 names those members for an OKP key: crv, kty and x. The string is
 * assembled by hand because the construction has to be exact: two
 * implementations that disagree about it derive different identifiers for the
 * same key.
 *
 * @param {{ kty: string, crv: string, x: string }} jwk
 * @returns {string}
 * @throws {TypeError} When the JWK is not an Ed25519 public key.
 */
export function jwkThumbprint(jwk) {
  if (jwk === null || typeof jwk !== "object" || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new TypeError("expected an OKP JWK on the Ed25519 curve");
  }
  const raw = decodeSegment(jwk.x);
  if (raw === null || raw.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new TypeError('the "x" member is not a 32-byte base64url value');
  }
  // x passed the strict decoder, so it needs no JSON escaping.
  const input = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return createHash("sha256").update(input, "utf8").digest("base64url");
}

/**
 * Turn a JWK Set into a map from kid to KeyObject, keeping only entries this
 * verifier could ever use.
 *
 * @param {unknown} jwks
 * @returns {Map<string, import("node:crypto").KeyObject>}
 */
function loadKeys(jwks) {
  const keys = new Map();
  const entries = jwks !== null && typeof jwks === "object" && Array.isArray(jwks.keys) ? jwks.keys : [];

  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    if (entry.kty !== "OKP" || entry.crv !== "Ed25519") continue;
    if (entry.use !== undefined && entry.use !== "sig") continue;
    if (entry.alg !== undefined && entry.alg !== ALG_EDDSA) continue;

    let thumbprint;
    try {
      thumbprint = jwkThumbprint(entry);
    } catch {
      continue;
    }
    // The service derives kid from the key itself. An entry whose kid is
    // something else was not produced the way this verifier expects, and is
    // skipped rather than trusted under a name it chose for itself.
    if (entry.kid !== undefined && entry.kid !== thumbprint) continue;

    // Only the three public members are imported, so a document that carries
    // a private "d" by mistake cannot put private key material in memory here.
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: entry.x },
      format: "jwk",
    });
    keys.set(thumbprint, key);
  }
  return keys;
}

/**
 * @typedef {object} KeySource
 * @property {(kid: string) => Promise<import("node:crypto").KeyObject | undefined>} get
 *   Resolve one key by its identifier, or undefined when there is none.
 */

/**
 * Key source over a JWK Set held in configuration. Use it when the deployment's
 * public key is pinned in the application, which removes the network from
 * verification altogether; the set then has to be updated by hand before the
 * operator rotates the signing key.
 *
 * @param {{ keys: object[] } | string} jwks The JWK Set, parsed or as JSON text.
 * @returns {KeySource}
 * @throws {TypeError} When the set holds no usable Ed25519 signing key.
 */
export function staticKeys(jwks) {
  let document = jwks;
  if (typeof jwks === "string") {
    try {
      document = JSON.parse(jwks);
    } catch {
      throw new TypeError("the JWK Set is not valid JSON");
    }
  }
  const keys = loadKeys(document);
  if (keys.size === 0) {
    throw new TypeError("the JWK Set holds no usable Ed25519 signing key");
  }
  return Object.freeze({
    async get(kid) {
      return keys.get(kid);
    },
  });
}

/**
 * Key source over the JWKS endpoint of the deployment,
 * `<base>/v1/.well-known/jwks.json`.
 *
 * The set is cached for `cacheSeconds`. A `kid` absent from a fresh cache
 * triggers one refetch, which is what lets a rotation take effect without
 * waiting out the cache. The `kid` comes from an unauthenticated token, though,
 * so that refetch is rate limited: without the limit anyone able to submit
 * tokens could make this process request the endpoint once per token, turning
 * the verifier into a request amplifier aimed at the authentication service.
 * The same limit covers retries after a failed fetch.
 *
 * When no fresh set can be obtained, `get` rejects with a TransportError and
 * stale keys are not used: a key withdrawn by the operator must stop verifying
 * once the cache lifetime has passed, even if the endpoint is unreachable.
 *
 * @param {string | URL} url https, or http to a loopback host.
 * @param {object} [options]
 * @param {number} [options.cacheSeconds] Lifetime of a fetched set. Default 300, the max-age the service sends.
 * @param {number} [options.minRefetchIntervalSeconds] Minimum spacing between two fetches. Default 10.
 * @param {number} [options.timeoutMs] Budget for one fetch. Default 10000.
 * @param {boolean} [options.allowInsecureTransport] Accept plain http to a host that is not loopback. Default false.
 * @param {typeof globalThis.fetch} [options.fetch] Replacement fetch.
 * @param {() => number} [options.now] Clock in seconds, for tests.
 * @returns {KeySource}
 */
export function remoteJwks(
  url,
  {
    cacheSeconds = 300,
    minRefetchIntervalSeconds = 10,
    timeoutMs = 10000,
    allowInsecureTransport = false,
    fetch = globalThis.fetch,
    now = () => Date.now() / 1000,
  } = {},
) {
  // The key set decides which signatures are believed. Fetched over plain http
  // it can be replaced in transit, and the point of a detached signature, not
  // having to trust the network path, is lost.
  const endpoint = parseEndpointUrl(url, { what: "the JWKS URL", allowInsecureTransport });
  for (const [name, value] of Object.entries({ cacheSeconds, minRefetchIntervalSeconds })) {
    if (!Number.isFinite(value) || value < 0) {
      throw new TypeError(`${name} must be a non-negative number`);
    }
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive number");
  }
  if (typeof fetch !== "function") throw new TypeError("fetch must be a function");

  /** @type {Map<string, import("node:crypto").KeyObject> | null} */
  let cache = null;
  let fetchedAt = Number.NEGATIVE_INFINITY;
  let lastAttemptAt = Number.NEGATIVE_INFINITY;
  /** @type {Promise<void> | null} */
  let inFlight = null;

  async function download() {
    let text;
    let status;
    try {
      const response = await fetch(endpoint, {
        headers: { Accept: "application/jwk-set+json, application/json" },
        // A redirect would let whatever answers choose where the keys come
        // from. The service serves the document directly.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      status = response.status;
      if (response.redirected || status !== 200) {
        await response.body?.cancel?.().catch(() => {});
        throw new TransportError(`the JWKS endpoint answered ${status}`);
      }
      text = await readCappedText(response, MAX_RESPONSE_BYTES);
    } catch (error) {
      if (error instanceof TransportError) throw error;
      throw new TransportError(`the JWKS fetch failed: ${describeFetchFailure(error, timeoutMs)}`, {
        cause: error,
      });
    }

    let document;
    try {
      document = JSON.parse(text);
    } catch {
      throw new TransportError("the JWKS endpoint did not return valid JSON");
    }
    const keys = loadKeys(document);
    // An empty set is treated as a failed fetch rather than cached: caching it
    // would refuse every assertion for a full cache lifetime.
    if (keys.size === 0) {
      throw new TransportError("the JWKS endpoint returned no usable Ed25519 signing key");
    }
    return keys;
  }

  function refresh(at) {
    // Concurrent verifications share one fetch. Without this, a burst of
    // logins arriving on a cold cache would each request the endpoint.
    if (inFlight === null) {
      lastAttemptAt = at;
      inFlight = download()
        .then((keys) => {
          cache = keys;
          fetchedAt = at;
        })
        .finally(() => {
          inFlight = null;
        });
    }
    return inFlight;
  }

  return Object.freeze({
    async get(kid) {
      const at = now();
      const fresh = cache !== null && at - fetchedAt < cacheSeconds;
      const mayFetch = inFlight !== null || at - lastAttemptAt >= minRefetchIntervalSeconds;

      if (!fresh) {
        if (!mayFetch) {
          throw new TransportError("the JWK Set is unavailable and a refetch is not due yet");
        }
        await refresh(at);
        return cache?.get(kid);
      }

      const known = cache.get(kid);
      if (known !== undefined || !mayFetch) return known;

      try {
        await refresh(at);
      } catch {
        // The cached set is still within its lifetime and does not know this
        // kid. A failed refetch does not change that answer.
        return undefined;
      }
      return cache.get(kid);
    },
  });
}

/**
 * @typedef {object} AssertionClaims
 * @property {string} iss Deployment that ran the ceremony.
 * @property {string} sub Internal subject identifier, not the application's own reference.
 * @property {string} aud Identifier of the API key the ceremony was performed for.
 * @property {number} [iat]
 * @property {number} [nbf]
 * @property {number} exp
 * @property {string} [jti] Unique token identifier, the key of a replay cache.
 * @property {string[]} amr Factors that completed the ceremony.
 * @property {string} [cid] base64url WebAuthn credential identifier.
 * @property {string} [tid] Tenant identifier on multi-tenant deployments.
 * @property {AssertionRisk} [risk] What the service made of the ceremony, present only when the deployment reports risk.
 */

/**
 * What the service made of the ceremony, from the `risk` claim.
 *
 * It is a report and never a refusal: the service verified the ceremony before
 * signing it, so `level === "high"` is not a failed authentication. What to do
 * about it belongs to the application, which knows what the user is about to
 * do.
 *
 * An absent claim means the deployment does not report risk, which is
 * deliberately not the same as a low assessment. An application that steps up
 * must handle the absent case explicitly, or disabling the feature would
 * silently turn every step-up off.
 *
 * @typedef {object} AssertionRisk
 * @property {"low" | "elevated" | "high"} level Reported level. Compare against these values rather than ordering the strings.
 * @property {string[]} reasons Every signal that fired, in a fixed order. The set is closed and documented in docs/RISK.md, but a newer deployment may report a member this library does not know, so do not treat it as exhaustive.
 * @property {number} score Total weight of the reasons, carried so a decision can be explained rather than so applications invent their own thresholds.
 */

/**
 * Verifies assertions for one issuer and one audience.
 *
 * Two duties remain with the caller after `verify` resolves, because neither
 * can be discharged by a stateless check:
 *
 * - Enforce single use of `jti`. A valid signature does not make a token single
 *   use: an assertion captured in transit stays replayable until `exp`. Record
 *   each `jti` until its `exp` plus the skew has passed and refuse a repeat.
 * - Check `amr` against the application's own policy. `webauthn-uv`, `webauthn`,
 *   `totp` and `recovery-code` are different assurances, and the service reports
 *   them separately so that the application decides, for instance, that a
 *   recovery-code login must re-enrol before reaching anything sensitive.
 */
export class Verifier {
  #issuer;
  #audience;
  #keys;
  #skew;
  #now;

  /**
   * @param {object} options
   * @param {string} options.issuer Expected `iss`. The shipped default of the service is `n0passtemps`.
   * @param {string} options.audience Expected `aud`: the identifier (a UUID) of the API key the ceremonies run under, as `GET /admin/v1/api-keys` reports it. Not the key itself.
   * @param {KeySource | { keys: object[] }} options.keys A key source, or a JWK Set, which is wrapped with {@link staticKeys}.
   * @param {number} [options.clockSkewSeconds] Tolerance on `exp` and `nbf`. Default 30. It extends the life of every token, so keep it well under the 60 second lifetime.
   * @param {() => number} [options.now] Clock in seconds since the epoch, for tests.
   */
  constructor({ issuer, audience, keys, clockSkewSeconds = 30, now = () => Date.now() / 1000 } = {}) {
    // Fail closed, and at construction rather than at the first login. An
    // empty expected audience would otherwise accept a token minted for any
    // other API key, which is the one thing pinning it exists to prevent.
    if (typeof issuer !== "string" || issuer === "") {
      throw new TypeError("issuer must be a non-empty string");
    }
    if (typeof audience !== "string" || audience === "") {
      throw new TypeError("audience must be a non-empty string");
    }
    if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
      throw new TypeError("clockSkewSeconds must be a non-negative number");
    }
    if (typeof now !== "function") throw new TypeError("now must be a function");

    let source = keys;
    if (source !== null && typeof source === "object" && Array.isArray(source.keys)) {
      source = staticKeys(source);
    }
    if (source === null || typeof source !== "object" || typeof source.get !== "function") {
      throw new TypeError("keys must be a key source from staticKeys() or remoteJwks()");
    }

    this.#issuer = issuer;
    this.#audience = audience;
    this.#keys = source;
    this.#skew = clockSkewSeconds;
    this.#now = now;
  }

  /**
   * Verify an assertion and resolve to its claims.
   *
   * @param {string} token The `assertion` member of a successful ceremony response.
   * @returns {Promise<AssertionClaims>}
   * @throws {InvalidAssertionError} For every verification failure, with no indication of which check failed.
   * @throws {TransportError} When a remote key source cannot supply a key set. This says nothing about the token.
   */
  async verify(token) {
    try {
      return await this.#verify(token);
    } catch (error) {
      if (error instanceof TransportError) throw error;
      // Anything unexpected, a throwing clock or key source included, is a
      // refusal. A fresh error is thrown so that no stack or cause from the
      // failing check travels with it.
      throw new InvalidAssertionError();
    }
  }

  async #verify(token) {
    const invalid = () => new InvalidAssertionError();

    if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) throw invalid();

    // RFC 7515 section 7.1: the compact serialisation is exactly three
    // segments. Splitting on every full stop and requiring three rejects a
    // fourth segment, which a lenient parser ignores while a second recipient
    // might read it, and rejects a two-segment unsecured JWS outright.
    const parts = token.split(".");
    if (parts.length !== 3) throw invalid();

    const rawHeader = decodeSegment(parts[0]);
    if (rawHeader === null) throw invalid();
    const header = parseJsonObject(rawHeader);
    if (header === null) throw invalid();

    // The algorithm is a constant of this module. It is compared, never used
    // to pick a routine. This one check stops the family of confusion attacks:
    // "alg":"none" with an empty signature, and "alg":"HS256" with the
    // published public key as the HMAC secret. Both are refused before any key
    // is looked up.
    if (header.alg !== ALG_EDDSA) throw invalid();

    // RFC 7515 section 4.1.11: a recipient must reject a JWS carrying a "crit"
    // extension it does not understand. This verifier understands none, and an
    // empty list is itself malformed, so any "crit" at all is fatal.
    if (header.crit !== undefined) throw invalid();

    // A JWS signed by the same key for another purpose must not pass as an
    // assertion.
    if (header.typ !== undefined && header.typ !== TYP_JWT) throw invalid();

    if (typeof header.kid !== "string" || header.kid === "") throw invalid();

    // Decoded before the key lookup so that only a well-formed token can reach
    // a remote key source.
    const signature = decodeSegment(parts[2]);
    if (signature === null || signature.length !== ED25519_SIGNATURE_SIZE) throw invalid();
    const rawPayload = decodeSegment(parts[1]);
    if (rawPayload === null) throw invalid();

    // The key is selected by kid, one candidate only. Trying every known key in
    // turn would let a token signed under a withdrawn key verify for as long
    // as that key remains in the set, and would make the cost of a failure grow
    // with the size of the set.
    const key = await this.#keys.get(header.kid);
    if (key === undefined || key === null) throw invalid();
    // Guards a hand-written key source: crypto.verify(null, ...) would
    // otherwise run whatever scheme the supplied key implies.
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw invalid();

    // The signature covers the header and payload exactly as received, which
    // is why the encoded text is verified rather than a re-serialisation of
    // the parsed objects. Ed25519 takes no digest, hence the null.
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
    if (!cryptoVerify(null, signingInput, key, signature)) throw invalid();

    // Only now is the payload worth parsing.
    const claims = parseJsonObject(rawPayload);
    if (claims === null) throw invalid();

    if (claims.iss !== this.#issuer) throw invalid();
    // Compared as a string. The service never issues an audience array, and
    // accepting one would mean deciding what "one of several audiences" means.
    if (claims.aud !== this.#audience) throw invalid();
    if (typeof claims.sub !== "string" || claims.sub === "") throw invalid();
    if (
      !Array.isArray(claims.amr) ||
      claims.amr.length === 0 ||
      !claims.amr.every((factor) => typeof factor === "string" && factor !== "")
    ) {
      throw invalid();
    }
    for (const name of ["jti", "cid", "tid"]) {
      if (claims[name] !== undefined && typeof claims[name] !== "string") throw invalid();
    }
    if (claims.iat !== undefined && !Number.isSafeInteger(claims.iat)) throw invalid();

    // A "risk" claim that is present but malformed invalidates the assertion.
    // Dropping it instead would present "risk was not reported" to an
    // application when risk was reported, which fails open on exactly the
    // signal the application asked for. Unknown members are ignored, so a
    // service that adds a field does not break this library.
    if (claims.risk !== undefined) {
      const risk = claims.risk;
      if (risk === null || typeof risk !== "object" || Array.isArray(risk)) throw invalid();
      if (typeof risk.level !== "string" || risk.level === "") throw invalid();
      if (risk.reasons !== undefined) {
        if (
          !Array.isArray(risk.reasons) ||
          !risk.reasons.every((reason) => typeof reason === "string")
        ) {
          throw invalid();
        }
      }
      if (risk.score !== undefined && !Number.isSafeInteger(risk.score)) throw invalid();
    }

    // "exp" is required. Treating a missing "exp" as "no expiry" turns a
    // captured assertion into a permanent credential.
    if (!Number.isSafeInteger(claims.exp) || claims.exp <= 0) throw invalid();

    const now = this.#now();
    if (!Number.isFinite(now)) throw invalid();
    if (now > claims.exp + this.#skew) throw invalid();

    if (claims.nbf !== undefined) {
      if (!Number.isSafeInteger(claims.nbf)) throw invalid();
      if (claims.nbf !== 0 && now < claims.nbf - this.#skew) throw invalid();
    }

    return claims;
  }
}
