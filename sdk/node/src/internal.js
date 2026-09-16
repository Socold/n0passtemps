// Helpers shared by client.js and assertion.js. This module is not part of the
// public surface: it is absent from the exports map of package.json.

import { TransportError } from "./errors.js";

/**
 * Upper bound on any response body the SDK will read. The largest legitimate
 * response is a batch of recovery codes or a set of WebAuthn options, a few
 * kilobytes. The cap exists so that a misbehaving or impersonated endpoint
 * cannot make the calling process buffer an unbounded body.
 */
export const MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Report whether a URL hostname designates the local machine.
 *
 * @param {string} hostname As returned by URL.hostname, brackets included for IPv6.
 * @returns {boolean}
 */
export function isLoopbackHost(hostname) {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "[::1]") return true;
  // The URL parser has already normalised every IPv4 spelling (decimal, hex,
  // short forms) to dotted quad by the time hostname is read, so a plain
  // pattern is enough here.
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Parse an endpoint URL and enforce the transport policy.
 *
 * The message never echoes the value: a base URL pasted with credentials in it
 * would otherwise end up in a log through the exception.
 *
 * @param {unknown} value
 * @param {{ what: string, allowInsecureTransport: boolean }} options
 * @returns {URL}
 */
export function parseEndpointUrl(value, { what, allowInsecureTransport }) {
  if (typeof value !== "string" && !(value instanceof URL)) {
    throw new TypeError(`${what} must be a string or a URL`);
  }
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new TypeError(`${what} is not a valid absolute URL`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new TypeError(`${what} must not carry credentials`);
  }
  if (url.protocol === "https:") return url;
  if (url.protocol !== "http:") {
    throw new TypeError(`${what} must use https`);
  }
  if (!allowInsecureTransport && !isLoopbackHost(url.hostname)) {
    throw new TypeError(
      `${what} must use https: plain http is accepted only for a loopback host, ` +
        "or when allowInsecureTransport is set",
    );
  }
  return url;
}

/**
 * Read a response body as text, refusing to buffer more than `limit` bytes.
 *
 * Content-Length is checked first as a cheap early exit, but it is the counted
 * read that enforces the cap: the header can be absent or wrong, and the limit
 * has to hold for the decompressed bytes.
 *
 * @param {Response} response
 * @param {number} [limit]
 * @returns {Promise<string>}
 */
export async function readCappedText(response, limit = MAX_RESPONSE_BYTES) {
  const tooLarge = () => new TransportError(`the response body exceeded ${limit} bytes`);

  const declared = Number(response.headers?.get?.("content-length") ?? Number.NaN);
  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel?.().catch(() => {});
    throw tooLarge();
  }

  if (response.body === null || response.body === undefined) {
    // A substituted fetch may hand back a response with no stream. The cap
    // still applies, after the fact.
    const text = typeof response.text === "function" ? await response.text() : "";
    if (new TextEncoder().encode(text).byteLength > limit) throw tooLarge();
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(joined);
}

/**
 * Describe a failed fetch without echoing anything the caller supplied.
 *
 * @param {unknown} error
 * @param {number} timeoutMs
 * @returns {string}
 */
export function describeFetchFailure(error, timeoutMs) {
  if (error instanceof TransportError) return error.message;
  const name = /** @type {{ name?: string }} */ (error)?.name;
  if (name === "TimeoutError") return `no response within ${timeoutMs} ms`;
  if (name === "AbortError") return "the request was aborted";
  const cause = /** @type {{ cause?: { code?: string, message?: string } }} */ (error)?.cause;
  const reason = cause?.code ?? cause?.message ?? /** @type {Error} */ (error)?.message;
  return typeof reason === "string" && reason !== "" ? reason : "the request failed";
}
