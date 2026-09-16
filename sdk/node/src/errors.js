// Error types raised by the SDK.
//
// The hierarchy follows the way a caller has to react, not the HTTP status
// line. The service answers 401 for two unrelated conditions, a refused API key
// and a failed ceremony, and only the problem `type` tells them apart. Branching
// on the status would make an application treat a user who mistyped a TOTP code
// as a misconfigured deployment, or the reverse.

const TYPE_PREFIX = "urn:n0passtemps:error:";

/**
 * The stable problem type identifiers the service returns, as listed in
 * internal/api/problem.go. They are URNs because there is no documentation
 * site to dereference.
 */
export const ProblemType = Object.freeze({
  BAD_REQUEST: `${TYPE_PREFIX}bad-request`,
  UNAUTHORIZED: `${TYPE_PREFIX}unauthorized`,
  FORBIDDEN: `${TYPE_PREFIX}forbidden`,
  NOT_FOUND: `${TYPE_PREFIX}not-found`,
  CONFLICT: `${TYPE_PREFIX}conflict`,
  CEREMONY_FAILED: `${TYPE_PREFIX}ceremony-failed`,
  THROTTLED: `${TYPE_PREFIX}throttled`,
  PAYLOAD_TOO_LARGE: `${TYPE_PREFIX}payload-too-large`,
  UNSUPPORTED_MEDIA_TYPE: `${TYPE_PREFIX}unsupported-media-type`,
  APPROVAL_REQUIRED: `${TYPE_PREFIX}approval-required`,
  INTERNAL: `${TYPE_PREFIX}internal`,
  UNAVAILABLE: `${TYPE_PREFIX}unavailable`,
});

/**
 * Base class of every error this SDK throws on purpose. Argument validation
 * still throws the built-in TypeError, because that is a programming mistake
 * rather than a runtime condition to handle.
 */
export class N0PasstempsError extends Error {
  /**
   * @param {string} message
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * The service answered with a refusal. The fields mirror the RFC 9457 problem
 * document of internal/api/problem.go.
 *
 * `title` and `type` name a class of failure and never the specific reason one
 * request was refused, so `requestId` is the field that matters in a support
 * exchange: it locates the log and audit entries where the real reason was
 * written down.
 */
export class ApiError extends N0PasstempsError {
  /**
   * @param {object} fields
   * @param {number} fields.status HTTP status code of the response.
   * @param {string} fields.type Problem type, `about:blank` when the body was not a problem document.
   * @param {string} fields.title Fixed description of the class of failure.
   * @param {string} [fields.detail] Present only on validation and state conflicts.
   * @param {string} [fields.requestId] Identifier to quote to the operator.
   * @param {number} [fields.retryAfterSeconds] Present on a throttled response.
   */
  constructor({ status, type, title, detail, requestId, retryAfterSeconds }) {
    let message = `${status} ${type}: ${title}`;
    if (detail) message += ` (${detail})`;
    if (requestId) message += ` [request_id=${requestId}]`;
    super(message);

    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.type = type;
    /** @type {string} */
    this.title = title;
    /** @type {string | undefined} */
    this.detail = detail;
    /** @type {string | undefined} */
    this.requestId = requestId;
    /** @type {number | undefined} */
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * The API key was missing, malformed, unknown or revoked. The service does not
 * say which, so that a caller cannot enumerate valid selectors. This is a
 * deployment fault, never the end user's.
 */
export class UnauthorizedError extends ApiError {}

/**
 * The API key is valid but may not do this: it lacks the scope the route needs,
 * or, on a registration, the authenticator model is not permitted by the
 * deployment's policy. The `title` distinguishes the two.
 */
export class ForbiddenError extends ApiError {}

/** The subject does not exist. Only `getSubject` reports this. */
export class NotFoundError extends ApiError {}

/**
 * The request conflicts with the current state: credential limit reached,
 * authenticator already registered, or no TOTP enrolment awaiting
 * confirmation. `detail` says which.
 *
 * A subject with no registered authenticator is deliberately NOT one of these.
 * Beginning an assertion for such a subject answers like any other failed
 * ceremony, so the route cannot be used to learn which of an application's
 * users have enrolled. Read the subject's `credential_count` from
 * `getSubject()` to decide what to offer.
 */
export class ConflictError extends ApiError {}

/**
 * A WebAuthn, TOTP or recovery-code ceremony did not succeed. Carries no detail
 * by design: a wrong code, an expired challenge, an unknown subject and a locked
 * subject are indistinguishable. Treat it as "the user is not authenticated".
 */
export class AuthenticationFailedError extends ApiError {}

/**
 * A rate limit was reached. `retryAfterSeconds` is the wait the service asks
 * for. The SDK never retries on its own: a retry loop inside a library turns
 * one throttled login into a burst against a service that has asked for quiet.
 */
export class ThrottledError extends ApiError {}

/**
 * A dependency of the service is down, typically its database. The credential
 * was not examined, so the API key is not at fault and a later retry is
 * reasonable.
 */
export class UnavailableError extends ApiError {}

/**
 * The request never produced a usable response: connection failure, timeout,
 * refused redirect, oversized or malformed body. Nothing can be concluded about
 * whether the service performed the operation.
 */
export class TransportError extends N0PasstempsError {}

/**
 * An assertion did not verify. There is one error for every failure and it
 * carries nothing else: reporting which check failed would tell an attacker
 * whether a forged token had the right audience, whether a key identifier
 * exists, or whether a captured token is merely expired rather than wrongly
 * signed.
 */
export class InvalidAssertionError extends N0PasstempsError {
  constructor() {
    super("the assertion is not valid");
  }
}

const CLASS_BY_TYPE = new Map([
  [ProblemType.UNAUTHORIZED, UnauthorizedError],
  [ProblemType.FORBIDDEN, ForbiddenError],
  [ProblemType.NOT_FOUND, NotFoundError],
  [ProblemType.CONFLICT, ConflictError],
  [ProblemType.CEREMONY_FAILED, AuthenticationFailedError],
  [ProblemType.THROTTLED, ThrottledError],
  [ProblemType.UNAVAILABLE, UnavailableError],
]);

// Used only when the body carried no recognised type, which means the response
// came from something in front of the service, such as a reverse proxy. 401 is
// left out on purpose: without the type there is no telling a refused key from a
// failed ceremony, and guessing either way misleads the caller.
const CLASS_BY_STATUS = new Map([
  [403, ForbiddenError],
  [404, NotFoundError],
  [409, ConflictError],
  [429, ThrottledError],
  [503, UnavailableError],
]);

function optionalString(value) {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * Parse a Retry-After header value, which RFC 9110 section 10.2.3 allows as
 * either a number of seconds or an HTTP date.
 *
 * @param {string | null | undefined} value
 * @param {number} nowMs
 * @returns {number | undefined}
 */
function parseRetryAfter(value, nowMs) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (/^\d{1,9}$/.test(trimmed)) return Number(trimmed);
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, Math.ceil((at - nowMs) / 1000));
}

/**
 * Build the ApiError subclass that matches a refusal.
 *
 * The class is chosen from the problem `type`. The status code is consulted
 * only when no recognised type is present.
 *
 * @param {object} input
 * @param {number} input.status HTTP status code.
 * @param {unknown} input.problem Parsed response body, of any shape.
 * @param {string | null} [input.requestIdHeader] Value of X-Request-Id.
 * @param {string | null} [input.retryAfterHeader] Value of Retry-After.
 * @param {number} [input.nowMs] Clock used to resolve a Retry-After date.
 * @returns {ApiError}
 */
export function apiErrorFromProblem({
  status,
  problem,
  requestIdHeader,
  retryAfterHeader,
  nowMs = Date.now(),
}) {
  const body =
    problem !== null && typeof problem === "object" && !Array.isArray(problem) ? problem : {};

  const type = optionalString(body.type) ?? "about:blank";
  const title = optionalString(body.title) ?? `HTTP ${status}`;
  const detail = optionalString(body.detail);
  const requestId = optionalString(body.request_id) ?? optionalString(requestIdHeader);

  let retryAfterSeconds = parseRetryAfter(retryAfterHeader, nowMs);
  if (
    retryAfterSeconds === undefined &&
    Number.isSafeInteger(body.retry_after_seconds) &&
    body.retry_after_seconds >= 0
  ) {
    retryAfterSeconds = body.retry_after_seconds;
  }

  const ErrorClass = CLASS_BY_TYPE.get(type) ?? (type === "about:blank" ? CLASS_BY_STATUS.get(status) : undefined) ?? ApiError;
  return new ErrorClass({ status, type, title, detail, requestId, retryAfterSeconds });
}
