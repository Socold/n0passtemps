// Types for "n0passtemps/browser". Hand-written; keep in step with browser.js.

/** The WebAuthn JSON form of a credential descriptor, `id` in base64url. */
export interface CredentialDescriptorJSON {
  type: string;
  id: string;
  transports?: string[];
  [member: string]: unknown;
}

/** `options` of a begin-registration response, as the service sends it. */
export interface ServerCreationOptions {
  publicKey: {
    challenge: string;
    user: { id: string; name?: string; displayName?: string; [member: string]: unknown };
    excludeCredentials?: CredentialDescriptorJSON[];
    [member: string]: unknown;
  };
  [member: string]: unknown;
}

/** `options` of a begin-assertion response, as the service sends it. */
export interface ServerRequestOptions {
  publicKey: {
    challenge: string;
    allowCredentials?: CredentialDescriptorJSON[];
    [member: string]: unknown;
  };
  [member: string]: unknown;
}

/** A PublicKeyCredential in the JSON form the service accepts as `credential`. */
export interface PublicKeyCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    transports?: string[];
    authenticatorData?: string;
    signature?: string;
    userHandle?: string;
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: string;
}

/** Decode an unpadded base64url string. Throws TypeError on any other input. */
export function base64urlToBuffer(value: string): ArrayBuffer;

/** Encode a buffer or a typed array view as unpadded base64url. */
export function bufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string;

/**
 * Prepare begin-registration `options` for `navigator.credentials.create()`.
 * Decodes `challenge`, `user.id` and every `excludeCredentials[].id`.
 */
export function toCreateOptions(
  serverOptions: ServerCreationOptions | ServerCreationOptions["publicKey"],
): { publicKey: Record<string, unknown>; [member: string]: unknown };

/**
 * Prepare begin-assertion `options` for `navigator.credentials.get()`.
 * Decodes `challenge` and every `allowCredentials[].id`.
 */
export function toGetOptions(
  serverOptions: ServerRequestOptions | ServerRequestOptions["publicKey"],
): { publicKey: Record<string, unknown>; [member: string]: unknown };

/**
 * Convert a browser PublicKeyCredential, from either ceremony, into the JSON
 * form to forward verbatim as `credential`.
 */
export function credentialToJSON(credential: object): PublicKeyCredentialJSON;
