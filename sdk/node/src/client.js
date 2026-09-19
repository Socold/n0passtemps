// HTTP client for the /v1 surface of an n0passtemps deployment.
//
// The contract is api/openapi.yaml and internal/api/public.go. Responses are
// returned as the service wrote them, snake_case included: a translation layer
// would be one more place for a field to be dropped, and the WebAuthn payloads
// in particular must reach the browser and come back byte for byte.

import { isIP } from "node:net";

import { TransportError, apiErrorFromProblem } from "./errors.js";
import {
  MAX_RESPONSE_BYTES,
  describeFetchFailure,
  parseEndpointUrl,
  readCappedText,
} from "./internal.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

// Printable ASCII with no space. Anything else cannot be a token the service
// minted, and a control character in a header value makes fetch throw an
// exception whose message quotes the whole value, key included.
const API_KEY_PATTERN = /^[\x21-\x7e]+$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

/**
 * Client for the routes an integrating application calls. One instance is safe
 * to share across requests; it holds no per-request state.
 *
 * Every method resolves to the JSON body the service returned, or rejects with
 * an {@link ApiError} subclass (the service refused) or a
 * {@link TransportError} (no usable response). Nothing is retried.
 */
export class Client {
  // A private field rather than a property, so that the key cannot reach a log
  // through JSON.stringify, util.inspect, a spread or a debugger dump of the
  // instance. It is a bearer credential: whoever reads it can run ceremonies
  // for every subject of the deployment.
  #apiKey;
  #origin;
  #basePath;
  #timeoutMs;
  #fetch;
  // Set only on the view forEndUser returns.
  #endUserIp;

  /**
   * @param {object} options
   * @param {string | URL} options.baseUrl Base URL of the deployment, for example `https://auth.example.org`. A path prefix is kept.
   * @param {string} options.apiKey An `npt_` token minted by `POST /admin/v1/api-keys`.
   * @param {number} [options.timeoutMs] Budget for one call, response body included. Default 10000.
   * @param {boolean} [options.allowInsecureTransport] Accept plain http to a host that is not loopback. Default false.
   * @param {typeof globalThis.fetch} [options.fetch] Replacement fetch, for tests or a custom agent.
   */
  constructor({
    baseUrl,
    apiKey,
    timeoutMs = 10000,
    allowInsecureTransport = false,
    fetch = globalThis.fetch,
  } = {}) {
    // The API key travels in the Authorization header of every request. Over
    // plain http anyone on the path reads it once and holds it until it is
    // revoked. Loopback is exempt because the traffic never leaves the host,
    // which is also the documented layout when a reverse proxy terminates TLS.
    const url = parseEndpointUrl(baseUrl, { what: "baseUrl", allowInsecureTransport });
    if (url.search !== "" || url.hash !== "") {
      throw new TypeError("baseUrl must not carry a query string or a fragment");
    }

    if (typeof apiKey !== "string" || apiKey === "") {
      throw new TypeError("apiKey must be a non-empty string");
    }
    if (!API_KEY_PATTERN.test(apiKey)) {
      throw new TypeError("apiKey contains characters that cannot appear in a token");
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive number");
    }
    if (typeof fetch !== "function") {
      throw new TypeError("fetch must be a function");
    }

    this.#apiKey = apiKey;
    this.#origin = url.origin;
    this.#basePath = url.pathname.replace(/\/+$/, "");
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetch;
  }

  /** Base URL the client talks to, without a trailing slash. */
  get baseUrl() {
    return this.#origin + this.#basePath;
  }

  /** Budget for one call in milliseconds. */
  get timeoutMs() {
    return this.#timeoutMs;
  }

  /**
   * A client that declares `ip` as the end user's address on every call, in
   * the `X-End-User-IP` header.
   *
   * The service sees every call arrive from the application's backend, which
   * says nothing about who is signing in, so its per-address rate limit and its
   * network risk signal work from the address declared here. Without it the
   * service applies no per-address limit to the call. Pass the address the
   * application observed for the user's browser, once per incoming request:
   *
   *     const auth = client.forEndUser(req.socket.remoteAddress);
   *     const result = await auth.verifyTotp(subjectRef, code);
   *
   * The view shares the settings of the client it came from and is as cheap to
   * create as an object. The original client is not changed.
   *
   * @param {string} ip An IPv4 or IPv6 address, with no port and no zone.
   * @returns {Client}
   */
  forEndUser(ip) {
    // Refused here because the service would refuse it with a 400 anyway, and
    // not quoted: it may be the one thing about the user the application does
    // not log.
    // isIP accepts a zone, which the service does not: a zone names an
    // interface of the host that saw the packet and means nothing elsewhere.
    if (typeof ip !== "string" || isIP(ip.trim()) === 0 || ip.includes("%")) {
      throw new TypeError("ip must be an IPv4 or IPv6 address, with no port and no zone");
    }
    const view = new Client({
      baseUrl: this.baseUrl,
      apiKey: this.#apiKey,
      timeoutMs: this.#timeoutMs,
      // The base URL passed the transport rule when this client was built.
      allowInsecureTransport: true,
      fetch: this.#fetch,
    });
    view.#endUserIp = ip.trim();
    return view;
  }

  /**
   * JSON form of the client, for logs. The API key is left out.
   *
   * @returns {{ baseUrl: string, timeoutMs: number }}
   */
  toJSON() {
    return { baseUrl: this.baseUrl, timeoutMs: this.#timeoutMs };
  }

  /**
   * What util.inspect and console.log print. The API key is left out.
   *
   * @returns {string}
   */
  [INSPECT]() {
    return `Client { baseUrl: '${this.baseUrl}', timeoutMs: ${this.#timeoutMs} }`;
  }

  /**
   * Resolve the application's user reference to a subject, creating it when it
   * does not exist. Idempotent, so it may be called on every login.
   *
   * @param {string} subjectRef Opaque identifier of the user. Prefer it to an email address: it appears in URL paths, which intervening proxies log.
   * @param {{ displayName?: string }} [options]
   * @returns {Promise<object>} SubjectSummary
   */
  async resolveSubject(subjectRef, { displayName } = {}) {
    requireNonEmptyString(subjectRef, "subjectRef");
    // The service refuses unknown members, so optional ones are added only
    // when set rather than sent as null.
    const body = { subject_ref: subjectRef };
    if (displayName !== undefined) {
      if (typeof displayName !== "string") throw new TypeError("displayName must be a string");
      body.display_name = displayName;
    }
    return this.#request("POST", "/v1/subjects", "/v1/subjects", body);
  }

  /**
   * Read which factors a subject has enrolled. Rejects with NotFoundError for
   * an unknown subject; it is the only route that makes that distinction.
   *
   * @param {string} subjectRef
   * @returns {Promise<object>} SubjectSummary
   */
  async getSubject(subjectRef) {
    return this.#subjectRequest("GET", "/v1/subjects/{subject_ref}", subjectRef);
  }

  /**
   * Begin a WebAuthn registration. Send `options` to the browser unchanged; see
   * `toCreateOptions` in browser.js.
   *
   * @param {string} subjectRef
   * @param {{ label?: string }} [options] `label` names the authenticator for the user and the operator.
   * @returns {Promise<object>} `{ challenge_id, options, expires_at }`
   */
  async beginRegistration(subjectRef, { label } = {}) {
    const body = {};
    if (label !== undefined) {
      if (typeof label !== "string") throw new TypeError("label must be a string");
      body.label = label;
    }
    return this.#subjectRequest("POST", "/v1/webauthn/{subject_ref}/register", subjectRef, body);
  }

  /**
   * Complete a WebAuthn registration.
   *
   * @param {string} subjectRef
   * @param {{ challengeId: string, credential: object }} input `credential` is the browser's PublicKeyCredential in JSON form, forwarded verbatim.
   * @returns {Promise<object>} `{ credential, recovery_codes_remaining }`
   */
  async completeRegistration(subjectRef, input) {
    return this.#subjectRequest(
      "POST",
      "/v1/webauthn/{subject_ref}/register/complete",
      subjectRef,
      Client.#ceremonyBody(input),
    );
  }

  /**
   * Begin a WebAuthn authentication. Send `options` to the browser unchanged;
   * see `toGetOptions` in browser.js.
   *
   * @param {string} subjectRef
   * @returns {Promise<object>} `{ challenge_id, options, expires_at }`
   */
  async beginAssertion(subjectRef) {
    return this.#subjectRequest("POST", "/v1/webauthn/{subject_ref}/assert", subjectRef);
  }

  /**
   * Complete a WebAuthn authentication. The resolved `assertion` must be
   * verified with a Verifier before anything is granted: the 200 only says the
   * request reached something, the signature says it reached the service.
   *
   * @param {string} subjectRef
   * @param {{ challengeId: string, credential: object }} input
   * @returns {Promise<object>} AssertionResult
   */
  async completeAssertion(subjectRef, input) {
    return this.#subjectRequest(
      "POST",
      "/v1/webauthn/{subject_ref}/assert/complete",
      subjectRef,
      Client.#ceremonyBody(input),
    );
  }

  /**
   * Begin a WebAuthn authentication without naming the subject.
   *
   * This is the passkey flow. The options carry no allow list, so the browser
   * offers whichever credentials the authenticator holds for this relying
   * party and the user picks one; send them to the browser unchanged, as with
   * {@link Client#beginAssertion}.
   *
   * The ceremony always requires user verification, whatever the deployment
   * configures for the named flow. A ceremony that names nobody is answered by
   * the authenticator alone, so possession on its own would let a found passkey
   * sign in as its owner.
   *
   * @returns {Promise<object>} `{ challenge_id, options, expires_at }`
   */
  async beginDiscoverableAssertion() {
    return this.#request(
      "POST",
      "/v1/webauthn/assert/discoverable",
      "/v1/webauthn/assert/discoverable",
    );
  }

  /**
   * Complete a ceremony begun without a subject. The result names the subject
   * the credential belonged to in `subject_id`.
   *
   * The credential must carry the `userHandle` the authenticator returned,
   * which a browser includes for a discoverable credential. Verify the
   * resolved `assertion` before anything is granted, and take the subject
   * identifier from the verified claims rather than from the body: the body is
   * unsigned.
   *
   * @param {{ challengeId: string, credential: object }} input
   * @returns {Promise<object>} AssertionResult
   */
  async completeDiscoverableAssertion(input) {
    return this.#request(
      "POST",
      "/v1/webauthn/assert/discoverable/complete",
      "/v1/webauthn/assert/discoverable/complete",
      Client.#ceremonyBody(input),
    );
  }

  /**
   * Issue a TOTP secret. It is disclosed in this response and never again, and
   * it is not usable until confirmed with {@link Client#confirmTotp}.
   *
   * @param {string} subjectRef
   * @returns {Promise<object>} TOTPEnrolResult
   */
  async enrolTotp(subjectRef) {
    return this.#subjectRequest("POST", "/v1/totp/{subject_ref}/enrol", subjectRef);
  }

  /**
   * Confirm a pending TOTP enrolment with one code.
   *
   * @param {string} subjectRef
   * @param {string} code
   * @returns {Promise<object>} `{ secret_id, confirmed: true }`
   */
  async confirmTotp(subjectRef, code) {
    return this.#subjectRequest("POST", "/v1/totp/{subject_ref}/enrol/confirm", subjectRef, {
      code: requireNonEmptyString(code, "code"),
    });
  }

  /**
   * Authenticate a subject with a TOTP code. Verify the resolved `assertion`.
   *
   * @param {string} subjectRef
   * @param {string} code
   * @returns {Promise<object>} AssertionResult with `factors: ["totp"]`
   */
  async verifyTotp(subjectRef, code) {
    return this.#subjectRequest("POST", "/v1/totp/{subject_ref}/verify", subjectRef, {
      code: requireNonEmptyString(code, "code"),
    });
  }

  /**
   * Issue a batch of single-use recovery codes and retire the previous batch.
   * The codes appear in this response and nowhere else: show them to the user
   * at once and do not store them.
   *
   * @param {string} subjectRef
   * @returns {Promise<object>} `{ batch_id, codes, count, warning }`
   */
  async issueRecoveryCodes(subjectRef) {
    return this.#subjectRequest("POST", "/v1/recovery/{subject_ref}/issue", subjectRef);
  }

  /**
   * Authenticate a subject with a recovery code, which is spent by the call.
   * Verify the resolved `assertion`, and consider its `recovery-code` factor a
   * lower assurance than WebAuthn.
   *
   * @param {string} subjectRef
   * @param {string} code
   * @returns {Promise<object>} AssertionResult plus `recovery_codes_remaining`
   */
  async consumeRecoveryCode(subjectRef, code) {
    return this.#subjectRequest("POST", "/v1/recovery/{subject_ref}/consume", subjectRef, {
      code: requireNonEmptyString(code, "code"),
    });
  }

  /**
   * Liveness probe. Resolves to `{ status: "ok" }`, or to `{ status: "error" }`
   * when the service answers 503 with a liveness body, because that answer is
   * the probe working as designed rather than a failed call.
   *
   * @returns {Promise<{ status: "ok" | "degraded" | "error" }>}
   */
  async health() {
    return this.#request("GET", "/v1/health", "/v1/health", undefined, { livenessOn503: true });
  }

  /**
   * Detailed component report. Needs the `health` scope.
   *
   * @returns {Promise<object>} HealthReport
   */
  async healthDetail() {
    return this.#request("GET", "/v1/health/detail", "/v1/health/detail");
  }

  static #ceremonyBody(input) {
    if (!isPlainObject(input)) {
      throw new TypeError("expected { challengeId, credential }");
    }
    const { challengeId, credential } = input;
    requireNonEmptyString(challengeId, "challengeId");
    if (!isPlainObject(credential)) {
      // A JSON string would be encoded a second time and refused by the
      // service with an error that hides the cause.
      throw new TypeError("credential must be the parsed PublicKeyCredential object");
    }
    return { challenge_id: challengeId, credential };
  }

  #subjectRequest(method, route, subjectRef, body) {
    requireNonEmptyString(subjectRef, "subjectRef");
    let encoded;
    try {
      // encodeURIComponent, not encodeURI: a reference may contain "/", "?" or
      // "#", each of which would otherwise change which route is reached.
      encoded = encodeURIComponent(subjectRef);
    } catch {
      throw new TypeError("subjectRef is not well-formed Unicode");
    }
    return this.#request(method, route, route.replace("{subject_ref}", encoded), body);
  }

  async #request(method, route, path, body, { livenessOn503 = false } = {}) {
    const expectedPath = this.#basePath + path;
    const url = new URL(this.#origin + expectedPath);
    // "." and ".." survive encodeURIComponent, and the URL parser resolves them
    // as path segments even when percent-encoded. A reference of ".." would
    // turn a subject route into a request for its parent. No encoding can carry
    // those two values in a path, so they are refused here.
    if (url.pathname !== expectedPath) {
      throw new TypeError('subjectRef cannot be "." or "..": it cannot be carried in a URL path');
    }

    const headers = {
      Accept: "application/json",
      // Sent on every request, bodyless POSTs included: the service answers 415
      // to a write without it, which is what stops a form-encoded request being
      // read as an empty JSON object.
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.#apiKey}`,
    };
    if (this.#endUserIp !== undefined) {
      headers["X-End-User-IP"] = this.#endUserIp;
    }

    let response;
    let text;
    try {
      response = await this.#fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        // fetch follows redirects by default and, for a same-origin hop or a
        // 307/308, replays the Authorization header to the target. The service
        // never redirects an API route, so a redirect means something else is
        // answering, and the bearer credential must not be handed to it.
        redirect: "error",
        // One signal covers the connection, the headers and the body, so a
        // response that trickles in cannot hold the caller past the budget.
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      if (response.redirected || (response.status >= 300 && response.status < 400)) {
        // Reached only with a substituted fetch that ignored redirect: "error".
        await response.body?.cancel?.().catch(() => {});
        throw new TransportError("the service answered with a redirect, which is refused");
      }
      text = await readCappedText(response, MAX_RESPONSE_BYTES);
    } catch (error) {
      const reason = this.#redact(describeFetchFailure(error, this.#timeoutMs));
      // The original error is kept as the cause for diagnosis, unless it quotes
      // the key, which only a substituted fetch could make it do.
      const cause = error instanceof TransportError || this.#mentionsKey(error) ? undefined : error;
      throw new TransportError(`${method} ${route}: ${reason}`, { cause });
    }

    let parsed = null;
    let parseFailed = false;
    if (text !== "") {
      try {
        parsed = JSON.parse(text);
      } catch {
        parseFailed = true;
      }
    }

    const contentType = response.headers.get("content-type") ?? "";
    const isProblem = /^application\/problem\+json\b/i.test(contentType);

    if (response.ok && !isProblem) {
      if (parseFailed) {
        throw new TransportError(`${method} ${route}: the response was not valid JSON`);
      }
      return parsed;
    }

    // The liveness probe reports an unreachable store as a 503 carrying its
    // ordinary body, not a problem document.
    if (
      livenessOn503 &&
      response.status === 503 &&
      !isProblem &&
      isPlainObject(parsed) &&
      typeof parsed.status === "string"
    ) {
      return parsed;
    }

    const problem = isPlainObject(parsed) ? { ...parsed } : {};
    // The service never echoes a credential, but whatever sits in front of it
    // might, for instance a proxy error page that dumps request headers.
    for (const member of ["title", "detail"]) {
      if (typeof problem[member] === "string") problem[member] = this.#redact(problem[member]);
    }
    throw apiErrorFromProblem({
      status: response.status,
      problem,
      requestIdHeader: response.headers.get("x-request-id"),
      retryAfterHeader: response.headers.get("retry-after"),
    });
  }

  #mentionsKey(error) {
    const texts = [error?.message, error?.cause?.message, error?.stack];
    return texts.some((text) => typeof text === "string" && text.includes(this.#apiKey));
  }

  #redact(text) {
    let out = String(text).split(this.#apiKey).join("[redacted]");
    // The half after the full stop is the secret part of selector.verifier, and
    // a truncating logger upstream may have cut the token there.
    const secret = this.#apiKey.slice(this.#apiKey.indexOf(".") + 1);
    if (secret.length >= 8) out = out.split(secret).join("[redacted]");
    return out;
  }
}
