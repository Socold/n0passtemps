// Types for "n0passtemps". Hand-written; keep in step with the sources and with
// api/openapi.yaml, which is authoritative for the response shapes.

import type { KeyObject } from "node:crypto";

import type {
  PublicKeyCredentialJSON,
  ServerCreationOptions,
  ServerRequestOptions,
} from "./browser.js";

export * from "./browser.js";

// Responses, as the service writes them.

export type SubjectStatus = "active" | "locked" | "pending_deletion";

export interface SubjectSummary {
  subject_id: string;
  status: SubjectStatus;
  created_at: string;
  /** Active WebAuthn credentials. Revoked ones are not counted. */
  credential_count: number;
  /** True only once an enrolment has been confirmed. */
  totp_enrolled: boolean;
  recovery_codes_remaining: number;
}

export interface BeginRegistrationResult {
  challenge_id: string;
  /** Pass to the browser unchanged, then through `toCreateOptions`. */
  options: ServerCreationOptions;
  expires_at: string;
}

export interface BeginAssertionResult {
  challenge_id: string;
  /** Pass to the browser unchanged, then through `toGetOptions`. */
  options: ServerRequestOptions;
  expires_at: string;
}

export type AttestationType = "none" | "self" | "basic" | "attca" | "anonca" | "indirect";

export interface Credential {
  /** Internal identifier, the one the administrative revoke route takes. */
  id: string;
  tenant_id: string;
  subject_id: string;
  /**
   * WebAuthn credential identifier in standard base64 WITH padding, unlike the
   * base64url `cid` claim of an assertion. Re-encode before comparing the two.
   */
  credential_id: string;
  aaguid?: string;
  attestation_type: AttestationType;
  transports: string[] | null;
  sign_count: number;
  clone_warning: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
  /** Reported at registration only; says nothing about later assertions. */
  user_verified: boolean;
  label?: string;
  rp_id: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
  revoked_reason?: string;
}

export interface RegisterCompleteResult {
  credential: Credential;
  recovery_codes_remaining: number;
}

export type Factor = "webauthn" | "webauthn-uv" | "totp" | "recovery-code";

export interface AssertionSignals {
  sign_count_regression?: boolean;
  binding_changed?: boolean;
  [signal: string]: unknown;
}

export interface AssertionResult {
  subject_id: string;
  /** Compact JWS. Verify it with a `Verifier` before granting anything. */
  assertion: string;
  expires_at: string;
  factors: Factor[];
  /** Absent when there is nothing to report. */
  signals?: AssertionSignals;
}

export interface RecoveryConsumeResult extends AssertionResult {
  recovery_codes_remaining: number;
}

export interface TotpEnrolResult {
  secret_id: string;
  /** Base32 seed without padding. Disclosed here and nowhere else. */
  secret: string;
  provisioning_uri: string;
  algorithm: string;
  digits: number;
  period_seconds: number;
  expires_at: string;
}

export interface TotpConfirmResult {
  secret_id: string;
  confirmed: true;
}

export interface RecoveryIssueResult {
  batch_id: string;
  /** Shown once. Present them to the user at once and do not store them. */
  codes: string[];
  count: number;
  warning: string;
}

export type HealthStatus = "ok" | "degraded" | "error";

export interface Liveness {
  status: HealthStatus;
}

export interface HealthReport {
  status: HealthStatus;
  version: { version: string; commit?: string; [member: string]: unknown };
  uptime_seconds: number;
  database: Record<string, unknown>;
  kek: Record<string, unknown>;
  tls?: Record<string, unknown>;
  audit: Record<string, unknown>;
  open_alerts: Record<string, number>;
  features: Record<string, boolean>;
  timestamp: string;
  last_error?: string;
}

// Client.

export interface ClientOptions {
  /** Base URL of the deployment. https, or http to a loopback host. */
  baseUrl: string | URL;
  /** An `npt_` token. Held in a private field and never printed. */
  apiKey: string;
  /** Budget for one call, body included, in milliseconds. Default 10000. */
  timeoutMs?: number;
  /** Accept plain http to a host that is not loopback. Default false. */
  allowInsecureTransport?: boolean;
  /** Replacement fetch. Default `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
}

export interface CeremonyCompleteInput {
  /** `challenge_id` of the matching begin call. */
  challengeId: string;
  /** The browser's credential in JSON form, forwarded verbatim. */
  credential: PublicKeyCredentialJSON | Record<string, unknown>;
}

/**
 * Client for the `/v1` routes. Methods reject with an `ApiError` subclass when
 * the service refuses and with `TransportError` when no usable response
 * arrived. Nothing is retried.
 */
export class Client {
  constructor(options: ClientOptions);
  readonly baseUrl: string;
  readonly timeoutMs: number;
  /** Omits the API key. */
  toJSON(): { baseUrl: string; timeoutMs: number };

  resolveSubject(subjectRef: string, options?: { displayName?: string }): Promise<SubjectSummary>;
  getSubject(subjectRef: string): Promise<SubjectSummary>;
  beginRegistration(subjectRef: string, options?: { label?: string }): Promise<BeginRegistrationResult>;
  completeRegistration(subjectRef: string, input: CeremonyCompleteInput): Promise<RegisterCompleteResult>;
  beginAssertion(subjectRef: string): Promise<BeginAssertionResult>;
  completeAssertion(subjectRef: string, input: CeremonyCompleteInput): Promise<AssertionResult>;

  /** Passkey flow: no subject is named, and the result reports which one signed in. */
  beginDiscoverableAssertion(): Promise<BeginAssertionResult>;
  completeDiscoverableAssertion(input: CeremonyCompleteInput): Promise<AssertionResult>;
  enrolTotp(subjectRef: string): Promise<TotpEnrolResult>;
  confirmTotp(subjectRef: string, code: string): Promise<TotpConfirmResult>;
  verifyTotp(subjectRef: string, code: string): Promise<AssertionResult>;
  issueRecoveryCodes(subjectRef: string): Promise<RecoveryIssueResult>;
  consumeRecoveryCode(subjectRef: string, code: string): Promise<RecoveryConsumeResult>;
  /** Resolves to `{ status: "error" }` on a 503 liveness body instead of rejecting. */
  health(): Promise<Liveness>;
  healthDetail(): Promise<HealthReport>;
}

// Errors.

export declare const ProblemType: {
  readonly BAD_REQUEST: "urn:n0passtemps:error:bad-request";
  readonly UNAUTHORIZED: "urn:n0passtemps:error:unauthorized";
  readonly FORBIDDEN: "urn:n0passtemps:error:forbidden";
  readonly NOT_FOUND: "urn:n0passtemps:error:not-found";
  readonly CONFLICT: "urn:n0passtemps:error:conflict";
  readonly CEREMONY_FAILED: "urn:n0passtemps:error:ceremony-failed";
  readonly THROTTLED: "urn:n0passtemps:error:throttled";
  readonly PAYLOAD_TOO_LARGE: "urn:n0passtemps:error:payload-too-large";
  readonly UNSUPPORTED_MEDIA_TYPE: "urn:n0passtemps:error:unsupported-media-type";
  readonly APPROVAL_REQUIRED: "urn:n0passtemps:error:approval-required";
  readonly INTERNAL: "urn:n0passtemps:error:internal";
  readonly UNAVAILABLE: "urn:n0passtemps:error:unavailable";
};

/** Base class of every error the SDK throws on purpose. */
export class N0PasstempsError extends Error {
  constructor(message: string, options?: { cause?: unknown });
}

export interface ApiErrorFields {
  status: number;
  type: string;
  title: string;
  detail?: string;
  requestId?: string;
  retryAfterSeconds?: number;
}

/** The service refused the request. Mirrors the RFC 9457 problem document. */
export class ApiError extends N0PasstempsError {
  constructor(fields: ApiErrorFields);
  readonly status: number;
  /** A `urn:n0passtemps:error:*` value, or `about:blank` for a foreign body. */
  readonly type: string;
  readonly title: string;
  readonly detail?: string;
  /** Quote this to the operator: it locates the log and audit entries. */
  readonly requestId?: string;
  readonly retryAfterSeconds?: number;
}

/** The API key was refused. A deployment fault, not the end user's. */
export class UnauthorizedError extends ApiError {}
/** The key lacks the scope, or the authenticator model is not permitted. */
export class ForbiddenError extends ApiError {}
/** Unknown subject. Only `getSubject` reports it. */
export class NotFoundError extends ApiError {}
/** State conflict; `detail` says which. */
export class ConflictError extends ApiError {}
/** A ceremony did not succeed. Carries no reason by design. */
export class AuthenticationFailedError extends ApiError {}
/** Rate limited. Wait `retryAfterSeconds`. */
export class ThrottledError extends ApiError {}
/** A dependency of the service is down. The key is not at fault. */
export class UnavailableError extends ApiError {}
/** No usable response: connection, timeout, redirect, size cap, bad JSON. */
export class TransportError extends N0PasstempsError {}
/** The one outcome of every failed verification. */
export class InvalidAssertionError extends N0PasstempsError {
  constructor();
}

export function apiErrorFromProblem(input: {
  status: number;
  problem: unknown;
  requestIdHeader?: string | null;
  retryAfterHeader?: string | null;
  nowMs?: number;
}): ApiError;

// Assertion verification.

export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  use?: "sig";
  alg?: "EdDSA";
  kid?: string;
}

export interface JwkSet {
  keys: Ed25519Jwk[];
}

export interface KeySource {
  /** Resolve one key by `kid`, or undefined when there is none. */
  get(kid: string): Promise<KeyObject | undefined>;
}

export interface RemoteJwksOptions {
  /** Lifetime of a fetched set in seconds. Default 300. */
  cacheSeconds?: number;
  /** Minimum spacing between two fetches in seconds. Default 10. */
  minRefetchIntervalSeconds?: number;
  /** Budget for one fetch in milliseconds. Default 10000. */
  timeoutMs?: number;
  /** Accept plain http to a host that is not loopback. Default false. */
  allowInsecureTransport?: boolean;
  fetch?: typeof globalThis.fetch;
  /** Clock in seconds, for tests. */
  now?: () => number;
}

export interface AssertionClaims {
  iss: string;
  /** Internal subject identifier, not the application's own reference. */
  sub: string;
  /** Identifier of the API key the ceremony was performed for. */
  aud: string;
  iat?: number;
  nbf?: number;
  exp: number;
  /** The caller must enforce single use of this value until `exp`. */
  jti?: string;
  /** The caller must check this against its own policy. */
  amr: Factor[];
  /** base64url WebAuthn credential identifier. */
  cid?: string;
  tid?: string;
  [claim: string]: unknown;
}

export interface VerifierOptions {
  issuer: string;
  /** The identifier (UUID) of the API key, not the key itself. */
  audience: string;
  keys: KeySource | JwkSet;
  /** Default 30. */
  clockSkewSeconds?: number;
  /** Clock in seconds since the epoch, for tests. */
  now?: () => number;
}

/** RFC 7638 thumbprint of an Ed25519 public JWK, which the service uses as `kid`. */
export function jwkThumbprint(jwk: { kty: string; crv: string; x: string }): string;
/** Key source over a JWK Set held in configuration. */
export function staticKeys(jwks: JwkSet | string): KeySource;
/** Key source over a JWKS endpoint, cached, with rate-limited refetch on an unknown `kid`. */
export function remoteJwks(url: string | URL, options?: RemoteJwksOptions): KeySource;

export class Verifier {
  constructor(options: VerifierOptions);
  /**
   * Rejects with `InvalidAssertionError` for every verification failure, and
   * with `TransportError` when a remote key source cannot supply a key set.
   * The caller must still enforce single use of `jti` and check `amr`.
   */
  verify(token: string): Promise<AssertionClaims>;
}
