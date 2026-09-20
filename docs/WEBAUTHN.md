# WebAuthn in this service

How registration and assertion work here specifically, against W3C WebAuthn
Level 2. The code is `internal/webauthn/webauthn.go`, over
`github.com/go-webauthn/webauthn`.

## Who the relying party is

This service is the relying party. `webauthn.rp_id` and `webauthn.origins` are
server configuration and are never read from a request.

Both of the comparisons WebAuthn requires, client data origin against an
expected origin and RP ID hash against the hash of an expected `rpId`, are only
worth making against a value the caller cannot choose. If either were read from
a request body, an attacker would present the origin it is actually operating
from, the check would pass, and the origin binding that makes WebAuthn resistant
to phishing would be gone. See [ADR 0003, The service is the WebAuthn relying
party](adr/0003-the-service-is-the-webauthn-relying-party.md).

Two consequences constrain deployment, and they are worth stating plainly:

- The integrating application has to serve its front end from a configured
  origin. Moving it to a new subdomain is a configuration change here, not a
  client-side one.
- Changing `rp_id` is not backward compatible. Credentials registered under
  `app.example.com` do not validate under `example.com`. A deployment that
  foresees a domain move should set `rp_id` to the registrable suffix from the
  start, and list the specific origins under `origins`.

The configuration validator enforces the relation WebAuthn actually checks:
`rp_id` must equal each origin's host or be a parent of it.

```toml
[webauthn]
rp_id   = "example.com"
origins = ["https://app.example.com", "https://admin.example.com"]
```

The configured `rp_id` is written onto the challenge row and onto the credential
it produces, so the value used at assertion is the value that was in force at
registration. If the configuration changes between the two halves of a ceremony,
`consumeChallenge` refuses the completion rather than validating a response
against an origin the operator has already stopped trusting.

## The ceremony, end to end

Both ceremonies are two round trips. The integrating application proxies them:
it holds the API key server side, so a browser never calls `/v1` directly.

```
browser                  your application              n0passtemps
   |                            |                           |
   |  "register a key"          |                           |
   |--------------------------->|  POST /v1/webauthn/{subject_ref}/register
   |                            |-------------------------->|
   |                            |                           |  create challenge row
   |                            |<--------------------------|  {challenge_id, options, expires_at}
   |<---------------------------|  options                  |
   |                            |                           |
   |  navigator.credentials     |                           |
   |    .create(options)        |                           |
   |--------------------------->|  POST /v1/webauthn/{subject_ref}/register/complete
   |                            |    {challenge_id, credential}
   |                            |-------------------------->|  consume challenge (atomic)
   |                            |                           |  verify, apply AAGUID policy
   |                            |                           |  store credential
   |                            |<--------------------------|  201 {credential, recovery_codes_remaining}
   |<---------------------------|                           |
```

Assertion is the same shape against
`POST /v1/webauthn/{subject_ref}/assert` and
`POST /v1/webauthn/{subject_ref}/assert/complete`, and the completion returns a
signed assertion rather than a credential.

`options` is the `PublicKeyCredentialCreationOptions` or
`PublicKeyCredentialRequestOptions` structure, ready to be handed to
`navigator.credentials.create` or `.get` after the usual base64url decoding of
the binary members. The application forwards the browser's
`PublicKeyCredential` back verbatim as the `credential` field: this service
keeps it as raw JSON and parses it with the WebAuthn library, rather than
through a struct that might drop a field the library needs to verify.

## The challenge store, and why the session is not handed to the client

Each ceremony's state lives in `webauthn_challenges`, keyed by a UUID the
`begin` call returns:

| Column | Holds |
|---|---|
| `id` | The `challenge_id` the caller presents on completion |
| `subject_id` | The subject the ceremony was started for |
| `ceremony` | `registration` or `assertion` |
| `challenge` | The challenge bytes, unique per tenant |
| `rp_id` | The relying party identifier in force when it was issued |
| `session_data` | The library's marshalled session, opaque to the caller |
| `expires_at` | `now + webauthn.challenge_ttl` |
| `consumed_at` | Set by the atomic consume |

The library's session data carries the expected challenge, the expected user
handle and the user-verification requirement. Handing it back to the caller, in
a cookie or in the response body, would let the caller edit any of the three
between the two round trips: the expected challenge could be replaced with one
the attacker knows the response to, and the user-verification requirement could
be relaxed from `required` to `discouraged`. Keeping it server side removes the
possibility rather than signing around it.

Single use is a property of the store, not a convention.
`ConsumeChallenge` marks the row consumed and returns it in one transaction,
conditional on it not being consumed already and not having expired:

```sql
UPDATE webauthn_challenges SET consumed_at = ?
WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL AND expires_at > ?
```

An unknown challenge, an expired one and an already consumed one all return the
same not-found result. Distinguishing them would tell an attacker whether a
challenge they guessed ever existed.

Three further checks run on the consumed row:

1. The challenge's `subject_id` must equal the subject the completion names.
   Without it, a caller holding a valid API key could graft an authenticator
   onto an account it never started a ceremony for.
2. The challenge's `ceremony` must match the endpoint. A registration
   challenge presented to the assertion endpoint would otherwise be validated
   under a different user-verification requirement and a different allow list.
3. The challenge's `rp_id` must still be the configured one.

## The user handle

The handle is the subject's internal identifier, and deliberately not the
reference the integrating application supplied.

`userHandle` takes the subject's UUID and uses its sixteen raw bytes. A subject
identifier that is not a UUID is hashed instead, under the domain separator
`n0passtemps/user-handle/v1`, which keeps the result inside the 64 bytes the
specification permits.

The reason is disclosure. The handle is stored on the authenticator, and a
discoverable credential can hand it to any relying party the user visits with
that key. Putting an application identifier there, which is frequently an email
address whatever the documentation advises, would publish personal data outside
this service and outside the operator's control. The internal identifier is a
random UUID that means nothing anywhere else.

The prompt the authenticator shows uses the optional `label` from the request
body, falling back to `display_name` and then to `subject-` plus the first eight
characters of the identifier. `label` is used only inside the ceremony and is
not persisted by `newUser`, so a caller may pass something human-readable for
the prompt without that value entering the database. The registration route
does persist the label it was given on the credential row, where it exists so an
operator can tell one of a subject's keys from another; it takes part in no
decision.

## Usernameless sign-in

A named assertion starts with the caller saying who is signing in. A
discoverable ceremony does not: the authenticator offers whichever credentials
it holds for this relying party, the user picks one, and the response says
whose it was. That is what a passkey prompt does, and it is what users now
expect, so the service offers it alongside the named flow rather than instead
of it.

Two decisions carry the security of that flow.

**User verification is required, not configured.** Every other ceremony takes
`webauthn.user_verification` from the configuration. This one ignores it and
requires verification. A named assertion is already scoped to a subject the
caller chose, so proving possession of that subject's authenticator answers a
question somebody asked. A discoverable ceremony is scoped to nothing: the
authenticator alone decides which account the response is for. Accepting a
possession-only response would mean a found or stolen passkey signs in as its
owner with nothing else needed, and the caller cannot compensate, because it
did not choose the subject either. A deployment whose authenticators cannot
verify a user therefore cannot offer usernameless sign-in. That is the correct
outcome and not a limitation to work around.

**The subject is resolved from the credential, never from the user handle.**
Both arrive in the same response, and a response is whatever the client chose
to send. They are not equally trustworthy. The credential identifier selects a
stored public key, and that key then has to verify the signature over this
ceremony's challenge; an attacker who names a credential they do not hold gets
no further. The handle is only a value in a JSON document. Resolving the
subject from it would let anyone present their own authenticator alongside
somebody else's handle and be told they are that person.

The handle is still compared against the one the service derives for the
resolved subject, and a mismatch refuses the ceremony. That comparison proves
nothing by itself, and it is not what identifies the subject. It refuses a
response assembled from two different ceremonies, and it means the property
does not rest on the library alone performing the same check.

### Keeping the two flows apart

A discoverable challenge is stored with no subject, because at that point there
is none. That empty value is also the guard. The named completion requires the
challenge to name the subject it was handed; the discoverable completion
requires it to name nobody. Neither ceremony can be finished through the
other's route.

This matters because the two differ in exactly the pair of checks an attacker
would want to choose between: the named flow sends an allow list and takes the
configured verification requirement, the discoverable flow sends no allow list
and requires verification. Letting a challenge cross between them would let the
weaker half of each be combined.

No new ceremony value was added to the challenge table for this. The `assertion`
value covers both, and the subject column tells them apart, so the schema did
not have to change and an existing deployment gains the flow without a
migration.

### What it does not change

A revoked credential authenticates nothing, and an inactive subject
authenticates nothing. Both are checked on the resolved credential before the
signature is verified, which is earlier than the store would refuse the write
at the end of the ceremony.

The lookup is scoped to the tenant and to the configured relying party
identifier, so a credential registered under one tenant cannot resolve a
subject under another.

Everything after validation is shared with the named flow: the same counter
compare-and-swap, the same clone signal, the same binding hash comparison, the
same risk assessment. The two paths converge on one function precisely so that
the part of an assertion easiest to get subtly wrong exists once.

## Attestation policy

`webauthn.attestation_preference` defaults to `none` and
`webauthn.require_attestation` defaults to `false`.

Verifying an attestation statement means checking a certificate chain against
either the FIDO Metadata Service over the network or a metadata blob on disk.
This service is meant to run offline, on premise, with no egress. Attestation is
therefore off by default, and the AAGUID allow list is the recommended control
in its place.

| Setting | Effect |
|---|---|
| `attestation_preference = "none"` | The browser is asked not to convey an attestation statement. |
| `attestation_preference = "direct"` or `"indirect"` | A statement is requested and recorded, but nothing is verified against a root unless `require_attestation` is on. |
| `require_attestation = true` | A credential arriving with attestation type `none` or `self` is refused, and so is one that reports no model (an all-zero AAGUID). The validator refuses this setting unless `attestation_preference` is `direct` or `indirect`, and unless either `metadata_path` or `allowed_aaguids` is set, because with neither there is nothing to verify against. |
| `metadata_path` | A FIDO Metadata Service (MDS3) BLOB on disk, loaded once at startup. The validator refuses a path it cannot read, and the loader refuses a file whose signature does not verify. Refreshing it is an operator duty. |

### The metadata BLOB

The BLOB is read from a file on purpose. The usual arrangement is to fetch it
from the FIDO Alliance at startup and refresh it on a timer, which makes outbound
network access a condition of verifying an attestation, and this service is
meant to run with none. An operator who wants attestation downloads the BLOB
through whatever controlled channel they already use for updates, places it at
`webauthn.metadata_path`, and restarts. The service never reaches out.

The BLOB is a signed JWT. Its signature chain is verified against the FIDO root
certificate compiled into the WebAuthn library, so a file that has been altered
on disk is refused at startup. That check is what makes reading trust anchors
from a local file acceptable at all. Before the library sees the file, the
loader also refuses one that does not claim to be signed: a JWT whose header
declares no algorithm or `none`, names a symmetric algorithm, or carries no
certificate chain. That property is too important to rest on one dependency's
behaviour.

With the BLOB loaded, the provider is strict:

- the attestation's trust path must chain to an anchor in the model's entry;
- an authenticator whose status report marks it revoked or compromised is
  refused;
- when attestation is required, an authenticator with no entry is refused.

The published BLOB routinely contains a handful of entries, out of several
thousand, that do not parse. They are dropped, not fatal. That fails in the safe
direction: a dropped model is an unknown model, and an unknown model is refused
whenever attestation is required.

A stale file fails safe in one direction only. A model certified after the file
was downloaded is unknown, and is refused under `require_attestation`. A model
compromised after the download is still trusted, because the status report
saying otherwise is in a newer file the service has not been given. Refreshing
the BLOB is therefore an operator duty with a security consequence, and nothing
in the service reminds you of it: put the refresh on the same calendar as
certificate renewal.

The attestation type the library reports is normalised onto the six values the
schema's `CHECK` constraint permits: `basic` and `basic_full` become `basic`,
`self` and `basic_surrogate` become `self`, `attca` and `anonca` keep their
names, `indirect` stays, and anything else becomes `none`.

### The AAGUID allow list

An AAGUID identifies an authenticator model. The policy is compiled into two
sets once at startup rather than re-parsed per ceremony:

```toml
[webauthn]
# Only these models may register. Empty means any model.
allowed_aaguids = [
  "ee882879-721c-4913-9775-3dfcce97072a",
  "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
]
# Refuse a model whose firmware has a published flaw, whatever the allow list says.
blocked_aaguids = []
```

The block list is consulted first, so a blocked model is refused even if it also
appears in the allow list. The configuration validator refuses an AAGUID that
appears in both, and refuses anything that is not the canonical 36-character
8-4-4-4-12 hexadecimal form.

This is the one ceremony refusal whose reason is disclosed to the caller:

```json
{
  "type": "urn:n0passtemps:error:forbidden",
  "title": "this authenticator model is not permitted",
  "status": 403
}
```

A user holding an unsupported key needs to be told to use a different one, and
the policy is configuration the operator publishes anyway.

Note the cost recorded in [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md):
the AAGUID is stored in clear, so an attacker with a copy of the database learns
which authenticator models are in use across the population, and an allow list
built from AAGUIDs is visible to them.

## The signature counter

The authenticator's signature counter is the specification's signal for two
copies of a credential private key being in use. This service records a stalled
counter and does not refuse the assertion.

The logic in `CompleteAssertion` is:

| Observation | Interpretation | Action |
|---|---|---|
| Presented counter is 0 and stored counter is 0 | The authenticator does not implement a counter | Not a signal. There is no counter to advance, so `TouchCredential` records `last_used_at` and nothing else. It touches only a credential that is not revoked, so a credential revoked between the listing and this point fails the ceremony |
| Presented counter is greater than stored | Normal use | `AdvanceSignCount` compare-and-swap from the stored value to the presented one |
| Presented counter is at or below stored, and not both zero | The documented clone signal | `MarkCloneWarning`, then `TouchCredential`; `CloneWarning` set in the outcome, the assertion still succeeds |
| The library's own `CloneWarning` flag is set | Same | Same |

Refusing on this signal would lock out a large share of ordinary users. Many
authenticators legitimately report a constant zero, and a platform
authenticator synchronised across a user's devices does the same. What happens
instead:

- `signals.sign_count_regression: true` appears in the assertion response, so
  the calling application may apply its own policy, such as requiring a second
  factor or re-enrolment.
- A `webauthn.sign_count_regression` audit entry records the stored and
  presented values.
- A `webauthn.sign_count_regression` alert is raised, at warning severity, when
  `webauthn.clone_warning_alerts` is on. It is the only durable record that a
  device may have been cloned.

Recording the use matters for the constant-zero case in particular. Most
passkeys report zero for ever, and a review of dormant credentials that read
`last_used_at` would otherwise list every one of them as never used.

Replay of an assertion is prevented by the challenge, which is consumed
atomically, so two concurrent completions of the same assertion have exactly one
winner. Where the authenticator has a counter, the compare-and-swap on it is a
second, independent guard: the loser sees a stale write and is refused. An
authenticator with a constant zero counter has the first guard only.

## The binding hash

`BindingHash` commits to the authenticator characteristics observed at
registration, under the domain separator
`n0passtemps/credential-binding/v1`. It covers four fields:

| Covered | Why |
|---|---|
| AAGUID | The model |
| Attestation type | The normalised statement type |
| Transports, sorted | The advertised transports, sorted so ordering does not change the hash |
| `rp_id` | The relying party the credential belongs to |

It deliberately excludes the signature counter and the backup state, both of
which change on every use.

A later assertion whose characteristics hash differently is recorded, not
refused. A firmware update can change the advertised transports, and a platform
authenticator can gain backup eligibility; neither means the key was swapped.
The response carries `signals.binding_changed: true` and a
`webauthn.binding_changed` audit entry is appended.

The comparison is made against both the hash stored on the row and the hash
recomputed from the stored row's fields, and reports a change only if the
current characteristics match neither. That absorbs a stored hash written by an
earlier build whose field set differed.

## What is stored, and what is not

| Field | Stored as | Note |
|---|---|---|
| `credential_id` | Clear, unique per `(tenant_id, rp_id, credential_id)` | The same authenticator cannot be registered under two subjects |
| `public_key` | Clear, COSE-encoded | A public key needs integrity, not confidentiality. See [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) |
| `aaguid` | Clear | Inventory information an attacker with the database can act on |
| `attestation_type` | Clear, constrained to six values | |
| `transports` | Clear, JSON array | |
| `sign_count` | Integer, advanced by compare-and-swap | |
| `clone_warning` | Flag | Set by `MarkCloneWarning`, never cleared |
| `backup_eligible`, `backup_state`, `user_verified` | Flags from the authenticator data at registration | `user_verified` describes the registration ceremony. It is never used to describe a later assertion |
| `binding_hash` | Digest | |
| `label`, `rp_id`, `created_at`, `last_used_at` | Clear | |
| `revoked_at`, `revoked_reason` | Clear, written once | There is no un-revoke. See [ADR 0010](adr/0010-revocation-is-final.md) |

No store method updates `public_key` after insertion. An attacker with write
access to the database could substitute one, which is detection through the
audit log rather than prevention; [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md)
says so.

## Enrolment limits and exclusions

`BeginRegistration` refuses a subject that already holds
`webauthn.max_credentials_per_subject` credentials, default 10, so a compromised
API key cannot quietly add an unbounded number of authenticators. The refusal is
a 409 with `the subject has reached the credential limit`.

The subject's existing credentials are passed as `excludeCredentials`, so an
authenticator already enrolled cannot be enrolled twice and the browser can tell
the user why. A response that arrives anyway, for a credential identifier
already present under this relying party, is refused with
`this authenticator is already registered`.

`residentKey` is requested as `preferred` and
`userVerification` follows `webauthn.user_verification`, default `required`.

## Platform notes

What differs in practice, on the platforms this has to work on. None of this is
enforced by the service; it is what an integrating application runs into.

| Platform | What to expect |
|---|---|
| Windows Hello | The platform authenticator reports a real signature counter, so a stalled counter here is worth attention rather than routine. Attestation is available and the AAGUID is stable per Windows version family. A user with no biometric hardware falls back to a PIN, which still satisfies `user_verification = "required"`. Windows shows its own account chooser, so the `label` in the prompt matters. |
| macOS and iOS, Touch ID or Face ID | Passkeys synchronise through iCloud Keychain. The signature counter is constantly zero, so `sign_count_regression` never fires for these credentials and the clone signal is not available at all. `backup_eligible` and `backup_state` are both set, and `backup_state` can change between assertions, which is why the binding hash excludes it. Safari requires the ceremony to be triggered by a user gesture: an `options` fetch that takes too long can lose the gesture and the call fails before it reaches the authenticator. |
| iOS specifically | A cross-origin iframe cannot run the ceremony, and the associated-domains file on the origin has to match `rp_id` for autofill to offer the passkey. |
| Linux | There is no platform authenticator in the general case, so registration means a roaming key over USB or NFC. Chrome and Firefox both need the device to be accessible to the browser process: on most distributions that is a `udev` rule granting the logged-in user access to the HID device, and its absence is the single most common cause of an authenticator that the browser does not see at all. |
| Roaming keys generally | The counter advances, attestation is available, transports are reported as `usb`, `nfc` or `ble`. A firmware update can change the reported transports, which is the legitimate cause of `binding_changed`. |
| Android | Passkeys in Google Password Manager behave like the Apple case: zero counter, backup eligible. A hardware-backed key in the device's own keystore reports a counter. |

Two things that are independent of platform:

- `webauthn.challenge_ttl` defaults to 5 minutes, and the validator holds it
  between 30 seconds and 15 minutes. `webauthn.ceremony_timeout` defaults to 2
  minutes and is what the browser displays a timer against. A user who walks
  away and comes back has to start again, which the application should present
  as "start again" rather than as an error.
- A localhost development origin is a secure context by specification, so
  `rp_id = "localhost"` with `origins = ["http://localhost:3000"]` works
  without TLS. The configuration validator permits `http` for `localhost`,
  `127.0.0.1` and `::1` and for nothing else.

## What a successful assertion returns

```json
{
  "subject_id": "0f7a...",
  "assertion": "eyJhbGciOiJFZERTQSIsImtpZCI6...",
  "expires_at": "2026-09-17T09:31:00Z",
  "factors": ["webauthn", "webauthn-uv"],
  "signals": { "sign_count_regression": true }
}
```

`factors` is `webauthn`, plus `webauthn-uv` when the authenticator reported user
verification. The two are distinct on purpose: an application may require user
verification for a sensitive operation, and that must not be inferred from the
bare `webauthn` factor.

User verification is read from the authenticator data of the ceremony in hand
and from nothing else: not from the stored credential, and not from the
credential record the WebAuthn library returns, which merges the flags of every
ceremony with a logical OR and so stays true for ever once a credential has been
registered with verification. This matters under
`webauthn.user_verification = "preferred"`. A stolen security key used without
its PIN produces a possession-only assertion; it succeeds, because `preferred`
permits it, and it is signed with `amr` holding `webauthn` alone. An application
that needs the second property checks for `webauthn-uv` on every assertion.
Under `required`, which is the default, an assertion without user verification
is refused outright.

`signals` is absent when there is nothing to report. It carries conditions worth
surfacing that did not refuse the authentication, so the caller may decide to
step up. It is not a statement that the assertion is invalid.

`assertion` is a compact JWS the application verifies offline against
`GET /v1/.well-known/jwks.json`. Its contents, and what a verifier has to
check, are in [ADR 0004](adr/0004-return-a-signed-assertion-result.md) and in
the README's integration example.

## Related documents

| Document | What it covers |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Every `webauthn.*` key and its validation |
| [TROUBLESHOOT.md](TROUBLESHOOT.md) | The `rp_id` and origin mismatch, which is the most common failure |
| [FAQ.md](FAQ.md) | Attestation by default, replay, and a process that dies mid-ceremony |
| [ADR 0003](adr/0003-the-service-is-the-webauthn-relying-party.md) | Why the relying party identifier is server configuration |
| [ADR 0006](adr/0006-store-webauthn-public-keys-in-clear.md) | Why public keys are not sealed |
| `internal/webauthn/webauthn_test.go`, `authenticator_test.go` | The ceremony layer exercised end to end by a software authenticator: registration, assertion, user verification, the counter cases and the refusals |
