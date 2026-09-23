# 0017. Administrative sign-in with WebAuthn, over a separate credential space

Status: accepted
Date: 2026-09-23

## Context

The administration interface authenticated by having an operator paste a
long-lived bearer token into a form field. A passwordless product whose own
console asks for a pasted secret is an awkward demonstration, and the awkwardness
is not only presentational: the token is the credential itself, so it lands in
browser form history, in a password manager entry nobody audits, and on the
screen of whoever is standing behind the operator. It is typed in full every time
a session expires.

Adding passkeys to the console raises one question that dominates all the others.
The service already stores WebAuthn credentials, for the people the deployment
authenticates. If an administrator's passkey and a user's passkey are the same
kind of thing, then either direction of confusion is a total compromise: an
operator's key signing in as any user, or, far worse, any enrolled user's key
opening the console. The second would make every person this service
authenticates an administrator of it.

Two further constraints came with the feature. The bearer token cannot go away,
because it is how the first administrator exists at all ([0014](0014-bootstrap-by-explicit-command.md))
and it is the way back in when a key is lost. And [0012](0012-server-rendered-administration-interface.md)
counted six screens as the reason this interface has no build toolchain, so a
seventh screen would spend the argument that keeps it simple.

## Decision

An administrator signs in with a discoverable credential, and administrative
credentials are a separate space from subject credentials at every layer.

**Separate tables.** `admin_credentials` names an administrative token where
`webauthn_credentials` names a subject, and neither lookup path reads the other
table. The separation is where a row lives rather than a predicate a query has to
remember to carry. `admin_webauthn_challenges` is separate for the same reason: a
console sign-in ceremony and a subject usernameless ceremony are otherwise
indistinguishable as rows, so one table would let a caller finish one through the
other's endpoint and choose which surface's checks applied.

**Separate user handles.** The relying-party user handle is a digest under
`n0passtemps/admin-user-handle/v1`, disjoint from the subject handle by
construction. An authenticator therefore creates a distinct credential for an
administrative enrolment rather than replacing a subject's, and a response whose
handle belongs to the other space fails the comparison every completion makes.

**A stored invariant.** Neither registration will store a credential identifier
that already exists in the other table. Given the handles that is unreachable,
and refusing on it turns "no credential is both" from a consequence of how
handles are built into a property a later reader can check.

**The role comes from the token.** A credential names an administrative token;
the role, the expiry and the revocation are read from that token at sign-in.
`AdminCredential` has no role field, so a passkey cannot carry or change
authority. Enrolling one is therefore not a privilege change and is not held for
a second administrator: there would be nothing to weigh, and a queue would mean
an administrator who has lost a key cannot enrol another until somebody else is
awake. It is the argument [RBAC.md](../RBAC.md) already makes for rotating your
own token.

**No permission, and no route to anybody else's token.** Enrolling and
withdrawing a passkey for your own sign-in carries no `internal/rbac` permission,
because it is part of how you authenticate rather than something you do as an
administrator, and the console's other authentication routes, signing in and
signing out, carry none either. There is no route that names another
administrator's token, for the reason there is no route to rotate another
administrator's token: what the ceremony produces signs in as that token.

**The session is unchanged.** A completed ceremony mints the session
`handleSignInSubmit` mints, with the same cookie attributes, the same idle and
absolute deadlines, and the same request token on every form. A passkey is
another way to prove who you are, not another kind of being signed in.

**The bearer token stays, and may be closed off per token.**
`admin.passkey_required` refuses a pasted token once *that token* has a passkey.
The scope is the token and not the deployment, and that is the whole design: a
token with no passkey is always accepted, so `-bootstrap-admin` always produces a
credential that can be pasted, and the setting can never leave a deployment with
nobody able to sign in.

**No seventh screen.** Signing in with a passkey is the sign-in screen. Managing
them is a section of the dashboard, beside the rest of what an operator's sign-in
is.

## Consequences

The console can be used without a long-lived secret ever being typed, which is
what the product claims for everybody else.

The recovery path when every passkey is lost runs through the host. Withdrawing
the last passkey reopens the form for that token; if the operator cannot sign in
to withdraw it, somebody with access to the host runs
`n0passtemps-server -bootstrap-admin -force`, and the new token has no passkey.
That is deliberately not a secret anybody can present remotely: whoever can run
the command already holds the configuration, the keyring and the database.

The interface gains its first behaviour that does not work with script disabled.
`navigator.credentials` runs in the browser between the two halves of a ceremony,
so there is no form-only version of this. The controls are rendered hidden and
revealed by the script, so a browser without WebAuthn shows no button that would
do nothing, and the pasted token stays on the screen as the fallback.

A cross-site page cannot drive the two unauthenticated ceremony routes, and the
reason differs from the usual one: a forged form works because the attacker never
reads the response, and here they must, since the completion is refused without
the challenge identifier the first call returned. What remains is that such a
page could cause an operator's authenticator to prompt. The prompt names this
relying party and requires user verification, so there is something visible to
refuse.

Two credential families now carry a signature counter, and only one piece of
bookkeeping advances either. The alternative, a second copy for the second table,
would have been a second place for the clone signal and the replay guard to drift
apart, and that drift is silent: a counter check that stopped refusing a replay
still looks like a working sign-in.

An operator who enrols a passkey on a shared workstation has put a console
credential on that device. Nothing here detects it, and the answer is the same as
for any authenticator: withdraw it, which is final.
