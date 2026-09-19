// The browser half of a sign-in.
//
// Everything here talks to /api on this origin. The API key is on the other
// side of that boundary and never reaches this file; see the package comment in
// main.go for why that is the one thing to copy out of this kit.
//
// The conversions between WebAuthn's JSON form and the ArrayBuffers
// navigator.credentials wants are in webauthn.js, which is a copy of
// sdk/node/src/browser.js that a test keeps identical. They are the part every
// integration gets wrong, and they are the part nobody should write twice.

import { toCreateOptions, toGetOptions, credentialToJSON } from "./webauthn.js";

const $ = (id) => document.getElementById(id);

const ui = {
  status: $("status"),
  error: $("error"),
  signedOut: $("signed-out"),
  signedIn: $("signed-in"),
};

function say(message) {
  ui.status.textContent = message ?? "";
}

function fail(message) {
  ui.error.textContent = message;
  ui.error.hidden = false;
  say("");
}

function clearError() {
  ui.error.hidden = true;
  ui.error.textContent = "";
}

// call posts to this origin and turns a problem document into an Error whose
// message is what the service said.
//
// The wording is not rewritten. The service is careful about what it discloses
// on a failed ceremony: every failure returns one body, so a caller cannot tell
// a wrong signature from an expired challenge from an unknown credential. An
// integration that invented friendlier messages would be undoing that, and
// would be guessing.
async function call(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });

  const text = await response.text();
  const parsed = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const error = new Error(parsed.detail || parsed.error || "the request failed");
    error.status = response.status;
    error.type = parsed.type;
    throw error;
  }
  return parsed;
}

// A ceremony is always two round trips with a call to the authenticator in the
// middle, whichever direction it goes. Writing it once keeps the four flows
// below to their differences.
async function ceremony({ beginPath, completePath, body, act }) {
  const begin = await call(beginPath, body);
  const credential = await act(begin.options);
  if (credential === null) {
    // The user dismissed the prompt, or there was nothing to offer. Not an
    // error to report as one: they chose not to.
    return null;
  }
  return call(completePath, {
    ...body,
    challenge_id: begin.challenge_id,
    credential: credentialToJSON(credential),
  });
}

async function create(options) {
  return navigator.credentials.create(toCreateOptions(options));
}

async function get(options) {
  return navigator.credentials.get(toGetOptions(options));
}

// ---------------------------------------------------------------------------
// The four ways in
// ---------------------------------------------------------------------------

async function passkey() {
  say("Waiting for your device…");
  // No subject reference: the authenticator offers whichever passkey it holds
  // for this site, and the server reports which subject it turned out to be.
  const result = await ceremony({
    beginPath: "/api/login/begin",
    completePath: "/api/login/complete",
    body: {},
    act: get,
  });
  if (result) showSession(result);
}

async function passkeyFor(subjectRef) {
  say("Waiting for your device…");
  const result = await ceremony({
    beginPath: "/api/login/begin",
    completePath: "/api/login/complete",
    body: { subject_ref: subjectRef },
    act: get,
  });
  if (result) showSession(result);
}

async function enrol(subjectRef, label) {
  say("Waiting for your device…");
  const result = await ceremony({
    beginPath: "/api/register/begin",
    completePath: "/api/register/complete",
    body: { subject_ref: subjectRef, label },
    act: create,
  });
  if (!result) return;

  // Deliberately not a sign-in. The person has proved they hold an
  // authenticator and has not yet used it to authenticate, and treating
  // enrolment as a way in is how an enrolment flow becomes one.
  say("Passkey created. Now use it to sign in.");
  await passkeyFor(subjectRef);
}

// addPasskey enrols another authenticator for the account that is signed in.
// No subject is sent: the backend takes it from the session and refuses a body
// that names a different one.
async function addPasskey(label) {
  say("Waiting for your device…");
  const result = await ceremony({
    beginPath: "/api/register/begin",
    completePath: "/api/register/complete",
    body: { label },
    act: create,
  });
  if (result) say("Passkey added. It will be offered the next time you sign in.");
}

async function totp(subjectRef, code) {
  say("Checking the code…");
  showSession(await call("/api/totp/verify", { subject_ref: subjectRef, code }));
}

async function recovery(subjectRef, code) {
  say("Checking the code…");
  showSession(await call("/api/recovery/consume", { subject_ref: subjectRef, code }));
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function showSession(session) {
  if (!session || !session.signed_in) {
    say("");
    return;
  }
  clearError();
  say("");

  $("who").textContent = session.subject_ref || session.subject_id || "(resolved by the authenticator)";
  $("factors").textContent = (session.factors || []).join(", ") || "—";

  const after = $("after");
  after.replaceChildren();

  // A recovery code is the way back in, not a factor to keep. Saying so at the
  // moment it is used is the only time anybody reads it.
  if (session.enrol_now) {
    const note = document.createElement("p");
    note.className = "warn";
    const remaining = session.recovery_codes_remaining;
    note.textContent =
      `You signed in with a recovery code. ${remaining} ${remaining === 1 ? "code is" : "codes are"}` +
      " left. Enrol an authenticator now; a recovery code is not one.";
    after.append(note);
  }

  // Reported and not acted on, which is all the service claims for them. A
  // signal is a reason for an application to ask for more, not a refusal the
  // service has already made.
  const signals = Object.entries(session.signals || {}).filter(([, on]) => on === true);
  if (signals.length > 0) {
    const note = document.createElement("p");
    note.className = "warn";
    note.textContent = `Signals reported: ${signals.map(([name]) => name).join(", ")}.`;
    after.append(note);
  }

  // A session opened by a passkey alone carries the service's identifier and
  // not the application's reference, and the backend adds a factor only to a
  // session that names its subject.
  const named = Boolean(session.subject_ref);
  $("add-form").hidden = !named;
  $("add-unnamed").hidden = named;

  ui.signedOut.hidden = true;
  ui.signedIn.hidden = false;
}

// openEnrolment is what the backend said about a first passkey with no session.
// It is asked once, when the page loads, and does not change while it runs.
let openEnrolment = false;

function showSignedOut() {
  $("enrol").hidden = !openEnrolment;
  $("enrol-closed").hidden = openEnrolment;
  ui.signedIn.hidden = true;
  ui.signedOut.hidden = false;
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// run keeps every handler to its own business: one place clears the previous
// error, one place reports the next one, and a button cannot be pressed twice
// while a ceremony is open.
function run(element, handler) {
  let busy = false;
  return async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    element.setAttribute("aria-busy", "true");
    clearError();
    try {
      await handler();
    } catch (err) {
      // NotAllowedError is the browser telling us the user dismissed the
      // prompt or it timed out. It is not a failure to report as one.
      if (err && err.name === "NotAllowedError") {
        say("");
      } else {
        fail(err && err.message ? err.message : String(err));
      }
    } finally {
      busy = false;
      element.removeAttribute("aria-busy");
    }
  };
}

const passkeyButton = $("passkey");
passkeyButton.addEventListener("click", run(passkeyButton, passkey));

const namedForm = $("named-form");
namedForm.addEventListener("submit", run(namedForm, () => passkeyFor($("named-ref").value.trim())));

const totpForm = $("totp-form");
totpForm.addEventListener("submit", run(totpForm, () =>
  totp($("totp-ref").value.trim(), $("totp-code").value.trim())));

const recoveryForm = $("recovery-form");
recoveryForm.addEventListener("submit", run(recoveryForm, () =>
  recovery($("recovery-ref").value.trim(), $("recovery-code").value.trim())));

const enrolForm = $("enrol-form");
enrolForm.addEventListener("submit", run(enrolForm, () =>
  enrol($("enrol-ref").value.trim(), $("enrol-label").value.trim())));

const addForm = $("add-form");
addForm.addEventListener("submit", run(addForm, () => addPasskey($("add-label").value.trim())));

const logoutButton = $("logout");
logoutButton.addEventListener("click", run(logoutButton, async () => {
  await call("/api/logout", {});
  showSignedOut();
}));

// Conditional mediation: the browser may offer a passkey from the address field
// itself, with no button pressed, which is the smoothest form this has. It is
// attempted and its failure ignored, because a browser without it must still
// get a working page.
async function offerFromTheField() {
  if (!window.PublicKeyCredential?.isConditionalMediationAvailable) return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;

  const begin = await call("/api/login/begin", {});
  const options = toGetOptions(begin.options);
  const credential = await navigator.credentials.get({ ...options, mediation: "conditional" });
  if (!credential) return;
  showSession(await call("/api/login/complete", {
    challenge_id: begin.challenge_id,
    credential: credentialToJSON(credential),
  }));
}

// Say so rather than offering a button that cannot work.
if (!window.PublicKeyCredential) {
  passkeyButton.disabled = true;
  $("passkey-hint").textContent =
    "This browser does not support passkeys. Use one of the other ways below.";
}

// What the page shows first depends on whether there is already a session.
call("/api/session")
  .then((session) => {
    openEnrolment = session.open_enrolment === true;
    return session.signed_in ? showSession(session) : showSignedOut();
  })
  .then(() => offerFromTheField())
  .catch(() => showSignedOut());
