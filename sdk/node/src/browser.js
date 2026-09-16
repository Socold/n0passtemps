// The two conversions every WebAuthn integration gets wrong, for the browser
// half of a ceremony.
//
// WebAuthn's JSON form carries binary members as base64url without padding
// (RFC 4648 section 5), while navigator.credentials wants ArrayBuffers going in
// and hands ArrayBuffers back. The service decodes strictly, so a value that
// reaches it in standard base64, with "+", "/" or "=", is refused rather than
// repaired.
//
// This file has no imports and uses nothing outside the language, atob and
// btoa, so it can go into a browser bundle or be copied into a page as it is.

const BASE64URL = /^[A-Za-z0-9_-]*$/;

function isObject(value) {
  return value !== null && typeof value === "object";
}

function bufferTag(value) {
  // The tag rather than instanceof: a buffer created in another realm, an
  // iframe for instance, fails instanceof against this realm's ArrayBuffer.
  return Object.prototype.toString.call(value);
}

function isBufferSource(value) {
  if (!isObject(value)) return false;
  if (ArrayBuffer.isView(value)) return true;
  const tag = bufferTag(value);
  return tag === "[object ArrayBuffer]" || tag === "[object SharedArrayBuffer]";
}

/**
 * Decode an unpadded base64url string into an ArrayBuffer.
 *
 * @param {string} value
 * @returns {ArrayBuffer}
 * @throws {TypeError} When the value is not base64url.
 */
export function base64urlToBuffer(value) {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.length % 4 === 1) {
    throw new TypeError("expected an unpadded base64url string");
  }
  // atob speaks the standard alphabet and needs a length that is a multiple of
  // four, so translate the two characters and restore the padding.
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard.padEnd(standard.length + ((4 - (standard.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encode an ArrayBuffer or a typed array view as unpadded base64url.
 *
 * @param {ArrayBuffer | ArrayBufferView} buffer
 * @returns {string}
 * @throws {TypeError} When the value is not a buffer.
 */
export function bufferToBase64url(buffer) {
  if (!isBufferSource(buffer)) {
    throw new TypeError("expected an ArrayBuffer or a typed array");
  }
  const bytes = ArrayBuffer.isView(buffer)
    ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
    : new Uint8Array(buffer);
  // In chunks, because spreading a large array into one call overflows the
  // argument limit on some engines. An attestation object with a full
  // certificate chain is large enough to hit it.
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unwrap(serverOptions) {
  if (!isObject(serverOptions)) {
    throw new TypeError("expected the options object of a begin response");
  }
  // The service wraps the options under "publicKey", the shape
  // navigator.credentials takes. The bare inner object is accepted too, since
  // a back end may have unwrapped it before sending it on.
  if (isObject(serverOptions.publicKey)) {
    return { outer: serverOptions, publicKey: serverOptions.publicKey };
  }
  if (typeof serverOptions.challenge === "string") {
    return { outer: {}, publicKey: serverOptions };
  }
  throw new TypeError('the options carry neither "publicKey" nor "challenge"');
}

function decodeDescriptors(list) {
  return list.map((descriptor) => ({ ...descriptor, id: base64urlToBuffer(descriptor.id) }));
}

/**
 * Prepare the `options` of a begin-registration response for
 * `navigator.credentials.create()`.
 *
 * Exactly three kinds of member are binary and are decoded: `challenge`,
 * `user.id` and each `excludeCredentials[].id`. Everything else is copied as it
 * is. The input is not modified.
 *
 * @param {object} serverOptions `options` from `beginRegistration`, as received.
 * @returns {{ publicKey: object }} Argument for `navigator.credentials.create()`.
 */
export function toCreateOptions(serverOptions) {
  const { outer, publicKey } = unwrap(serverOptions);
  if (!isObject(publicKey.user)) {
    throw new TypeError('creation options must carry "user"');
  }
  const converted = {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
    user: { ...publicKey.user, id: base64urlToBuffer(publicKey.user.id) },
  };
  if (Array.isArray(publicKey.excludeCredentials)) {
    converted.excludeCredentials = decodeDescriptors(publicKey.excludeCredentials);
  }
  return { ...outer, publicKey: converted };
}

/**
 * Prepare the `options` of a begin-assertion response for
 * `navigator.credentials.get()`.
 *
 * `challenge` and each `allowCredentials[].id` are decoded; everything else is
 * copied as it is. The input is not modified.
 *
 * @param {object} serverOptions `options` from `beginAssertion`, as received.
 * @returns {{ publicKey: object }} Argument for `navigator.credentials.get()`.
 */
export function toGetOptions(serverOptions) {
  const { outer, publicKey } = unwrap(serverOptions);
  const converted = {
    ...publicKey,
    challenge: base64urlToBuffer(publicKey.challenge),
  };
  if (Array.isArray(publicKey.allowCredentials)) {
    converted.allowCredentials = decodeDescriptors(publicKey.allowCredentials);
  }
  return { ...outer, publicKey: converted };
}

function encodeDeep(value) {
  // Extension outputs such as prf and largeBlob nest ArrayBuffers at depths
  // that vary by extension, so the conversion walks the whole structure.
  if (isBufferSource(value)) return bufferToBase64url(value);
  if (Array.isArray(value)) return value.map(encodeDeep);
  if (isObject(value)) {
    const out = {};
    for (const [name, member] of Object.entries(value)) {
      if (member !== undefined) out[name] = encodeDeep(member);
    }
    return out;
  }
  return value;
}

/**
 * Convert the PublicKeyCredential a browser returned into the JSON form the
 * service expects as `credential`. Works for both ceremonies.
 *
 * The result must then travel to the service without being reshaped: the
 * service parses it with a WebAuthn library, and a member renamed or dropped on
 * the way is a member the library cannot use to verify the signature.
 *
 * The explicit conversion is used even where the browser offers
 * `credential.toJSON()`, so that every browser produces the same structure.
 *
 * @param {PublicKeyCredential | object} credential
 * @returns {object}
 */
export function credentialToJSON(credential) {
  if (!isObject(credential) || !isObject(credential.response)) {
    throw new TypeError("expected a PublicKeyCredential");
  }
  const source = credential.response;

  const response = { clientDataJSON: bufferToBase64url(source.clientDataJSON) };

  if (source.attestationObject !== undefined && source.attestationObject !== null) {
    response.attestationObject = bufferToBase64url(source.attestationObject);
    // getTransports is not implemented everywhere, and the service treats the
    // list as advisory, so its absence is not an error.
    if (typeof source.getTransports === "function") {
      const transports = source.getTransports();
      if (Array.isArray(transports) && transports.length > 0) {
        response.transports = [...transports];
      }
    }
  } else {
    response.authenticatorData = bufferToBase64url(source.authenticatorData);
    response.signature = bufferToBase64url(source.signature);
    // Null for a credential that is not discoverable. The member is left out in
    // that case, as the platform's own toJSON does.
    if (source.userHandle !== undefined && source.userHandle !== null) {
      response.userHandle = bufferToBase64url(source.userHandle);
    }
  }

  const extensions =
    typeof credential.getClientExtensionResults === "function"
      ? credential.getClientExtensionResults()
      : credential.clientExtensionResults;

  const out = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: encodeDeep(extensions ?? {}),
  };
  if (typeof credential.authenticatorAttachment === "string" && credential.authenticatorAttachment !== "") {
    out.authenticatorAttachment = credential.authenticatorAttachment;
  }
  return out;
}
