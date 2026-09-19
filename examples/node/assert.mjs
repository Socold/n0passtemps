#!/usr/bin/env node
//
// assert.mjs - drive an assertion ceremony from the server side.
//
// Usage:
//   N0PASSTEMPS_URL=http://127.0.0.1:8080 \
//   N0PASSTEMPS_API_KEY=npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY \
//   node assert.mjs [subject-reference] [--credential credential.json]
//
// Node 20 or later. No dependencies: fetch is built in.
//
// Run it once with no --credential to obtain the request options, run the
// commented browser block below against those options, save what the browser
// returns to a file, then run it again with --credential pointing at that file.
//
// The ceremony is two round trips and this process sits in the middle of them.
// The state that binds the halves together lives in the service's database,
// keyed by challenge_id, so nothing here can alter the expected challenge, the
// expected user handle or the user-verification requirement between the two.

import { readFile } from "node:fs/promises";
import process from "node:process";

const DEFAULT_SUBJECT_REF = "example-user-0001";

function usage(message) {
  process.stderr.write(`${message}\n\n`);
  process.stderr.write("Usage: node assert.mjs [subject-reference] [--credential file.json]\n");
  process.exit(2);
}

function requireEnv(name, hint) {
  const value = (process.env[name] ?? "").trim();
  if (value === "") {
    process.stderr.write(`${name} is not set. ${hint}\n`);
    process.exit(2);
  }
  return value;
}

// A refusal is an RFC 9457 problem document. The service keeps title and type
// to a class of failure and never explains why one request was refused, so
// request_id is the field that matters: it locates the log and audit entries
// where the real reason was written down.
class ProblemError extends Error {
  constructor(status, document) {
    const parts = [String(status), document.type ?? "(no type)", document.title ?? "(no title)"];
    if (document.detail) parts.push(document.detail);
    if (document.request_id) parts.push(`request_id=${document.request_id}`);
    super(parts.join(": "));
    this.name = "ProblemError";
    this.status = status;
    this.document = document;
  }
}

async function request(baseUrl, apiKey, method, path, body) {
  const headers = { Accept: "application/json" };
  if (method === "POST") {
    // Required on every write route even when there is no body. Without it the
    // service answers 415, which is what stops a form-encoded request being
    // read as an empty JSON object.
    headers["Content-Type"] = "application/json";
  }
  headers.Authorization = `Bearer ${apiKey}`;

  const response = await fetch(new URL(path, baseUrl), {
    method,
    headers,
    body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
  });

  const raw = await response.text();
  const parsed = raw === "" ? null : JSON.parse(raw);

  if (!response.ok) {
    throw new ProblemError(response.status, parsed ?? {});
  }
  return parsed;
}

function parseArgs(argv) {
  let subjectRef = DEFAULT_SUBJECT_REF;
  let credentialFile = null;
  let positionalSeen = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--credential") {
      credentialFile = argv[i + 1];
      if (!credentialFile) usage("--credential needs a file path.");
      i += 1;
    } else if (arg.startsWith("--credential=")) {
      credentialFile = arg.slice("--credential=".length);
      if (!credentialFile) usage("--credential needs a file path.");
    } else if (arg.startsWith("-")) {
      usage(`Unknown option ${arg}.`);
    } else if (!positionalSeen) {
      subjectRef = arg;
      positionalSeen = true;
    } else {
      usage("Too many arguments.");
    }
  }

  return { subjectRef, credentialFile };
}

const BROWSER_BLOCK = `
// ---------------------------------------------------------------------------
// This is the browser's half. It cannot run here: navigator.credentials needs
// a user gesture, a secure context and an authenticator, so this process can
// only hand the options over and take the result back.
//
// Serve the page from an origin the deployment lists in
// server.cors_allowed_origins, and from a host matching webauthn.rp_id. Both
// are server configuration and are never read from a request: WebAuthn's
// security rests on the authenticator signing over an origin and a relying
// party identifier that the server independently expects.
//
//   const beginResponse = await fetch("/your-backend/assert/begin", {
//     method: "POST",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({ subject_ref: subjectRef }),
//   });
//   const { challenge_id, options } = await beginResponse.json();
//
//   // The service sends the WebAuthn fields as base64url strings, and the
//   // browser wants ArrayBuffers. Decode challenge and every
//   // allowCredentials[].id; leave everything else alone.
//   const publicKey = {
//     ...options.publicKey,
//     challenge: base64urlToBuffer(options.publicKey.challenge),
//     allowCredentials: (options.publicKey.allowCredentials ?? []).map((c) => ({
//       ...c,
//       id: base64urlToBuffer(c.id),
//     })),
//   };
//
//   const credential = await navigator.credentials.get({ publicKey });
//
//   // Back the other way for the response. Encode as base64url, not base64:
//   // the service decodes strictly, and a "+" or "/" is refused.
//   const payload = {
//     id: credential.id,
//     rawId: bufferToBase64url(credential.rawId),
//     type: credential.type,
//     response: {
//       clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
//       authenticatorData: bufferToBase64url(credential.response.authenticatorData),
//       signature: bufferToBase64url(credential.response.signature),
//       userHandle: credential.response.userHandle
//         ? bufferToBase64url(credential.response.userHandle)
//         : null,
//     },
//     clientExtensionResults: credential.getClientExtensionResults(),
//   };
//
//   // Forward it verbatim. Do not reshape it, rename a field or drop one that
//   // looks empty: the service parses it with a WebAuthn library, and a field
//   // lost in transit is a field the library cannot use to verify.
//   await fetch("/your-backend/assert/complete", {
//     method: "POST",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({ challenge_id, credential: payload }),
//   });
//
// register.html in this directory contains both conversion helpers in full,
// alongside a working create() ceremony.
// ---------------------------------------------------------------------------
`.trim();

async function main() {
  const { subjectRef, credentialFile } = parseArgs(process.argv.slice(2));

  const baseUrl = requireEnv(
    "N0PASSTEMPS_URL",
    "Set it to the base URL, for example http://127.0.0.1:8080",
  );
  const apiKey = requireEnv(
    "N0PASSTEMPS_API_KEY",
    "Set it to an npt_ token minted by POST /admin/v1/api-keys.",
  );

  const encodedRef = encodeURIComponent(subjectRef);

  const subject = await request(baseUrl, apiKey, "POST", "/v1/subjects", {
    subject_ref: subjectRef,
  });
  process.stdout.write(`subject_id: ${subject.subject_id}\n`);
  process.stdout.write(`credentials: ${subject.credential_count}\n\n`);

  if (subject.credential_count === 0) {
    process.stdout.write(
      "This subject has no registered authenticator, so an assertion cannot\n" +
        "start. Register one with register.html first. The service reports that\n" +
        "condition the same way as a failed ceremony, so the error you would get\n" +
        "does not say which it was.\n",
    );
    return 1;
  }

  if (credentialFile === null) {
    const begin = await request(
      baseUrl,
      apiKey,
      "POST",
      `/v1/webauthn/${encodedRef}/assert`,
      {},
    );

    process.stdout.write(`challenge_id: ${begin.challenge_id}\n`);
    process.stdout.write(`expires_at:   ${begin.expires_at}\n\n`);
    process.stdout.write("Hand these options to the browser unchanged:\n\n");
    process.stdout.write(`${JSON.stringify(begin.options, null, 2)}\n\n`);
    process.stdout.write(`${BROWSER_BLOCK}\n\n`);
    process.stdout.write(
      "Save the browser's credential to a file, adding challenge_id alongside\n" +
        "it, then run:\n\n" +
        `  node assert.mjs ${subjectRef} --credential credential.json\n\n` +
        "The file holds {\"challenge_id\": \"...\", \"credential\": { ... }}. The\n" +
        "challenge expires, so do not leave it overnight.\n",
    );
    return 0;
  }

  let payload;
  try {
    payload = JSON.parse(await readFile(credentialFile, "utf8"));
  } catch (error) {
    process.stderr.write(`Could not read ${credentialFile}: ${error.message}\n`);
    return 2;
  }

  if (!payload?.challenge_id || !payload?.credential) {
    process.stderr.write(
      `${credentialFile} must contain {"challenge_id": "...", "credential": { ... }}\n`,
    );
    return 2;
  }

  const result = await request(
    baseUrl,
    apiKey,
    "POST",
    `/v1/webauthn/${encodedRef}/assert/complete`,
    { challenge_id: payload.challenge_id, credential: payload.credential },
  );

  process.stdout.write(`subject_id: ${result.subject_id}\n`);
  process.stdout.write(`factors:    ${result.factors.join(", ")}\n`);
  process.stdout.write(`expires_at: ${result.expires_at}\n`);
  if (result.signals) {
    process.stdout.write(`signals:    ${JSON.stringify(result.signals)}\n`);
    process.stdout.write(
      "\nA signal did not refuse the authentication. sign_count_regression is\n" +
        "the documented indication of two copies of a credential private key in\n" +
        "use, but plenty of authenticators report a constant zero and a\n" +
        "synchronised platform authenticator does the same, so it is reported\n" +
        "for you to act on rather than enforced.\n",
    );
  }
  process.stdout.write(`\nassertion:  ${result.assertion}\n\n`);
  process.stdout.write(
    "Verify it before granting anything. The 200 above only says the request\n" +
      "reached the service; the detached signature is what removes the need to\n" +
      "trust the network path in between.\n\n" +
      `  N0PASSTEMPS_EXPECTED_AUDIENCE=<api key id> node verify.mjs '${result.assertion}'\n`,
  );
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof ProblemError) {
    process.stderr.write(`The service refused the request: ${error.message}\n`);
    if (error.status === 401) {
      process.stderr.write(
        "A 401 covers a refused API key and a failed ceremony alike. The type\n" +
          "member says which: unauthorized is the key, ceremony-failed is the\n" +
          "ceremony.\n",
      );
    }
    if (error.document?.retry_after_seconds) {
      process.stderr.write(
        `Rate limited. Retry in ${error.document.retry_after_seconds} seconds.\n`,
      );
    }
    process.exitCode = 1;
  } else if (error instanceof TypeError && error.cause) {
    process.stderr.write(`Could not reach the service: ${error.cause.message ?? error.cause}\n`);
    process.exitCode = 1;
  } else {
    throw error;
  }
}
