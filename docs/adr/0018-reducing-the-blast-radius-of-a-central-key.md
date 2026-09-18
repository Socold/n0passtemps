# 0018. Reducing the blast radius of a central key: rotate now, split later, and never pretend two files are two keys

Status: accepted
Date: 2026-09-18

## Context

This deployment holds two keys whose loss is not recoverable by anything else it
does, and the threat model has said so in plain words since 1.0.0.

**The assertion signing key.** One Ed25519 private key in one PEM file signs
every assertion. Whoever reads that file can mint a token for any subject, with
any `amr`, that every integrating application accepts, with no ceremony having
happened and nothing in the audit log to show for it. It is the only asset here
whose compromise is an authentication bypass rather than a disclosure. See
[Attacker 3](../THREAT-MODEL.md) and the cross-cutting limit "The signing key is
a single point of forgery".

**The key encryption keyring.** One AES-256 key, current version, wrapping the
data key of every sealed record. With it and a copy of the database an attacker
reads every TOTP shared secret and every sealed subject reference, which is
[Attacker 5](../THREAT-MODEL.md). That is a confidentiality loss and a standing
ability to generate TOTP codes, which is serious, and it is still the smaller of
the two: recovery codes are hashed, API keys and administrative tokens are
digested, WebAuthn private keys were never here, and assertions are signed by a
different file. [ADR 0005](0005-hash-recovery-codes-do-not-encrypt-them.md) and
[ADR 0009](0009-refuse-a-kek-inside-the-data-directory.md) are why that list is
as short as it is.

The question this record answers is what to do about it, and it was asked in the
form most people ask it: should there be two keys, or two people, or is this
something only a larger edition would carry?

Three observations shape the answer.

**Two keys in one trust domain are one key.** A second signing key in a second
file on the same host, read by the same process under the same account, falls to
the same `cat`. Splitting a secret buys nothing unless the halves sit on
different sides of a boundary an attacker has to cross twice. Any design here
that does not name that boundary is decoration, and decoration on a key is worse
than nothing because it is believed.

**Two people is a different control from two keys, and this service already has
it.** Dual approval holds `credential.revoke_bulk`, `subject.erase`,
`admin_token.create` and `kek.rotate` for a second administrator, and
[ADR 0013](0013-approvals-are-redeemed-not-executed.md) makes an approval a
thing redeemed rather than executed. It constrains what an administrator can do
through the API. It does nothing whatsoever about a key read off the filesystem,
because reading a file is not an operation this service mediates. Extending dual
approval is therefore an answer to a different question than the one asked.

**The cheapest real reduction was unavailable.** The threat model named rotation
as the mitigation for a stolen signing key and the service could not perform
one: `JWKS()` published exactly one key, so the outgoing key stopped verifying
at the instant it stopped signing. Rotating refused every assertion still in
flight and every assertion reaching an application whose cached key set predated
the restart. An operator who suspected a compromise had to choose between
leaving the forgery window open and causing an outage. A mitigation that costs
an outage is one that gets postponed, which is the same as not having it.

## Decision

Three parts, in the order their value divided by their cost puts them.

### 1. Make rotation an operation. Now, in this release.

`assertion.retired_public_key_paths` lists public keys the service publishes at
the JWKS route and never signs with. A rotation points `signing_key_path` at a
new key, lists the previous public key, restarts, and removes the entry once the
window has passed. The `kid` header selects between them, so no verifier changes
and no SDK changes. `n0passtemps-wizard assertion-key rotate` performs the swap,
keeps the outgoing pair beside the new key and prints the configuration line.

The window has to close, and the design makes closing it the operator's explicit
act rather than a timer, because a service that withdrew a key on a schedule
would refuse assertions during a clock problem. Every start logs a warning
naming the retired key identifiers for as long as any are listed: the
configuration is the only record that a window is open, and an unread
configuration is how a rotation performed in an incident stays half done for a
year.

What this buys, stated exactly: the response to a suspected compromise becomes
cheap enough to perform, and routine enough to rehearse. It does not detect a
theft, it does not prevent one, and a forgery minted before the rotation lives
out its sixty seconds regardless.

### 2. Do not add a second signing key. Say why in the record.

Rejected, not deferred. A second key held by the same process on the same host
adds a file to steal and a verifier-side change to every SDK and every shipped
example, in exchange for an attacker running one more `cat`. Threshold
signatures are the same trade with more mathematics.

The version worth having is not two keys but one key the process cannot read: a
signer it calls. That is part 3, and calling it "two keys" would obscure the only
property that matters, which is where the boundary is.

### 3. Signing and unwrapping behind an interface, for a later release.

Both `assertion.Issuer` and `kek` already take their key material through a
narrow seam. `Issuer` needs a signer, not a private key; `envelope.Sealer`
already reaches its KEK through a `KEKProvider` interface with `Current` and
`ByVersion`. Neither has to know whether the key is bytes in memory or a handle
to something that will not surrender it.

Behind that seam a deployment could put a PKCS#11 token, a cloud KMS or a TPM.
The property that gains is the one part 2 cannot: the key stops being readable
at all. A host compromise becomes the ability to *use* the key while the
compromise lasts, which is bounded by eviction, counted by the device, and
auditable somewhere the operator of this host does not control, in the same way
and for the same reason the external audit sink of
[ADR 0016](0016-ship-the-audit-chain-to-an-external-witness.md) is.

Not in this release, for reasons that are about honesty rather than effort. A
PKCS#11 backend that nobody has run against real hardware is a configuration
option that fails in production, and this project has no hardware to test it on.
A KMS backend contradicts the product's argument until it is optional, and makes
the service depend on a network call on the assertion path, which needs its own
design for what happens when that call is slow. Both deserve their own record
with a working implementation behind it, not a paragraph here.

### What about "enterprise edition only"

Rejected as a way of deciding any of the above. The property at stake is whether
an operator can respond to a stolen key, and a product that withholds that from
the deployments least able to afford an incident has chosen the wrong thing to
sell. Part 1 is in the free product and always will be. If part 3 ever arrives
and a specific backend turns out to cost real maintenance, that is a question
about that backend, not about the seam.

## Consequences

`retired_public_key_paths` is a new way to be wrong, and the failure is silent
by nature: a key listed here verifies whatever its private half signs. Three
things push against it. The validator refuses an empty entry, a repeated path
and the signing key's own path. The loader refuses a private key given where a
public one was expected, because the file is published. Every start warns while
the list is non-empty. None of that stops an operator who leaves the line in
place for a year, and nothing inside this process can.

The JWK Set grows by one entry during a window, and two entries are normal if a
second rotation happens inside one. Verifiers already select by `kid` and the
shipped SDKs already do; a verifier written to assume the set holds exactly one
key was already wrong and now finds out.

The KEK keeps its single-file arrangement for this release. It is the lesser of
the two exposures, [ADR 0009](0009-refuse-a-kek-inside-the-data-directory.md)
already separates it from the ciphertext, `kek.rotate` already sits behind dual
approval, and rotation there re-wraps rather than re-encrypts. What it does not
have, and part 3 would give it, is any defence once both halves are in one
attacker's hands: rotating afterwards does not change the plaintext already
extracted from a snapshot.

Nothing here closes the gap the threat model states. It converts an untreatable
compromise into a treatable one, and it says which of the three obvious answers,
two keys, two people or two editions, is the one that would have solved it, and
why the other two would not.

## Related

- [ADR 0004](0004-return-a-signed-assertion-result.md), why there is an
  assertion to sign at all
- [ADR 0009](0009-refuse-a-kek-inside-the-data-directory.md), the keyring's
  location
- [ADR 0013](0013-approvals-are-redeemed-not-executed.md), what dual approval is
  and is not
- [ADR 0016](0016-ship-the-audit-chain-to-an-external-witness.md), the same
  argument about a boundary, applied to the audit log
- [THREAT-MODEL.md](../THREAT-MODEL.md), attackers 3 and 5, and the
  cross-cutting limit this record answers
- [CONFIGURATION.md](../CONFIGURATION.md#rotating-the-signing-key), the
  procedure
