# The reference sign-in and enrolment kit

A page that signs a person in with a passkey, falls back to TOTP and to a
recovery code, and enrols a new authenticator. And the smallest backend that can
sit behind it: one that holds the API key and turns a verified assertion into
its own session.

It is meant to be read, adapted and thrown away. Nothing in the service imports
it, and deleting this directory changes nothing about the server.

## Run it

```bash
export N0PASSTEMPS_URL=http://127.0.0.1:8080
export N0PASSTEMPS_API_KEY=npa_...
go run ./kits/login -addr 127.0.0.1:5173
```

Then open <http://localhost:5173>.

The key needs the `subjects`, `webauthn`, `totp` and `recovery` scopes. Mint it
with those and no others: a key that can also issue enrolment tickets can mint a
secret that enrols an authenticator later, through a channel this page never
touches.

The deployment's `webauthn.rp_id` must match the host the page is served from,
and `webauthn.origins` must list its origin. Both are server configuration and
neither is read from a request: the authenticator signs over an origin and a
relying party identifier that the server independently expects, so a caller
allowed to nominate either would be proving nothing. `http://localhost` is a
secure context for WebAuthn, so trying it needs no certificate.

Your browser's developer tools can provide a virtual authenticator if you have
no security key to hand: in Chrome, More tools → WebAuthn.

## The one thing to copy

**The API key never reaches the browser.**

```
browser  ──POST /api/login/begin──▶  this process  ──Bearer npa_…──▶  n0passtemps
         ◀──── options ────────────                ◀──── options ────
```

`examples/node/register.html` puts the key in the page on purpose, to
demonstrate a ceremony with no backend at all, and says in capitals not to copy
that. This is the shape to copy. The page talks to `/api` on its own origin,
this process talks to the service, and the credential lives on one side of that
line.

A key in the page is a key every visitor holds, carrying whatever scopes it was
minted with: enrol an authenticator for any subject, issue recovery codes for
any subject, learn whether a given person has an account. `kit_test.go` asserts
that no served asset contains one.

## What each file is

| File | What it is |
|---|---|
| `main.go` | The backend. Eleven routes under `/api`, one API key, an in-memory session map |
| `public/index.html` | The page. A passkey first, the fallbacks behind a disclosure, enrolment behind another |
| `public/app.js` | The browser half. Two round trips per ceremony, and nothing else |
| `public/style.css` | No framework, no build step, no web font |
| `public/webauthn.js` | A byte-for-byte copy of `sdk/node/src/browser.js`, kept identical by a test |

## Decisions worth knowing before you adapt it

**Enrolling is not signing in.** Creating a passkey proves somebody holds an
authenticator. It does not prove they used it to authenticate. The page enrols,
then immediately runs an assertion, and only the second one produces a session.
An enrolment flow that hands out a session is a way in.

**A passkey is offered before a field is.** The authenticator already knows
which credentials it holds for this site, so asking who you are first is a
question with no purpose. The named form exists for the case where it does not
work, behind a disclosure, because a fallback presented as an equal choice is
one people take and the fallbacks are the weaker paths.

**Failure messages are not rewritten.** The service returns one body for every
ceremony failure, so a caller cannot tell a wrong signature from an expired
challenge from an unknown credential. The page shows what the service said.
Inventing friendlier wording would be undoing that, and would be guessing.

**A recovery code is not a factor.** Using one signs the person in and says so:
how many are left, and that they should enrol an authenticator now. That message
is the only time anybody reads it.

**Signals are reported and not acted on**, which is all the service claims for
them. `sign_count_regression` and `binding_changed` are reasons for an
application to ask for more, not refusals the service has already made.

## What this is not, and what to add yourself

Not a user portal. It signs a person in and enrols their factors, and stops. No
profile page, no device list, no way to revoke a credential: those belong to the
application, and a kit that grew them would be taking over the part of the
system that is not the authentication service's.

Three things a real deployment needs that are deliberately absent:

- **Verify the assertion.** This kit trusts its own TLS connection to the
  service, which is defensible only because the two are one deployment. An
  application verifies the compact JWS offline against the published JWK Set and
  takes the subject identifier from the verified claims. The Go SDK does it in
  one call; `examples/go/client.go` shows the checks by hand.
- **A real session store.** The map here is in memory and lost on restart.
- **Rate limiting in front of the page.** The service throttles per subject, per
  address and per key, and none of that stops somebody hammering this process.

## Related

- [docs/EXTENSIONS.md](../../docs/EXTENSIONS.md), where this sits and why it is
  not in the core
- [examples/README.md](../../examples/README.md), the smaller illustrations this
  grew out of
- [api/openapi.yaml](../../api/openapi.yaml), the contract the backend calls
