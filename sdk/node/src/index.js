// Entry point of the n0passtemps SDK for Node.js.
//
// The browser helpers are re-exported here for server-side rendering and for
// tests. A browser bundle should import "n0passtemps/browser" instead, because
// this module pulls in node:crypto through the verifier.

export { Client } from "./client.js";
export {
  ApiError,
  AuthenticationFailedError,
  ConflictError,
  ForbiddenError,
  InvalidAssertionError,
  N0PasstempsError,
  NotFoundError,
  ProblemType,
  ThrottledError,
  TransportError,
  UnauthorizedError,
  UnavailableError,
  apiErrorFromProblem,
} from "./errors.js";
export { Verifier, jwkThumbprint, remoteJwks, staticKeys } from "./assertion.js";
export {
  base64urlToBuffer,
  bufferToBase64url,
  credentialToJSON,
  toCreateOptions,
  toGetOptions,
} from "./browser.js";
