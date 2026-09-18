# 0019. Seal the keyring to a TPM, and say plainly that it protects the disk and not the host

Status: accepted
Date: 2026-09-18

## Context

[ADR 0018](0018-reducing-the-blast-radius-of-a-central-key.md) set out three
parts. Part one, making signing key rotation an operation rather than an outage,
shipped. Part two, a second signing key, was rejected. Part three, a key the
process cannot read, was deferred, and the reason given was that a PKCS#11
backend nobody has run against real hardware is a configuration option that
fails in production, and that this project had no hardware to test against.

The second half of that sentence was wrong. There is a TPM 2.0 in essentially
every machine built in the last decade, including the one this is written on,
and `swtpm` is a TPM 2.0 in a process for the cases where there is not, which
includes every continuous integration runner. The blocker was not hardware. It
was that nobody had looked.

What is genuinely blocked is the signing key specifically, and for a reason
worth recording so it is not rediscovered. `internal/assertion` signs with
Ed25519 and says in its package comment that Ed25519 is the only algorithm it
will ever accept. TPM 2.0 parts do ECDSA and RSA; EdDSA is permitted by the
specification and absent from the field. Putting the signing key in a TPM
therefore means issuing ES256, which means every verifier, all three SDKs and
both shipped examples learn a second algorithm, and it means the assertion
format grows the negotiation surface that package exists to not have. That is a
larger decision than a backend, and it is not this one.

The key encryption keyring has none of those problems. It is AES-256, the TPM
never has to perform the AES, and the provider interface it is reached through
already has two implementations.

And it has an exposure with nothing in front of it. Attacker 5 of
[THREAT-MODEL.md](../THREAT-MODEL.md) holds a copy of the database and a copy of
the keyring, and the model says of that position, in as many words, that nothing
is mitigated. The likeliest route there is not a clever attack, it is one backup
archive or one volume snapshot containing both.
[ADR 0009](0009-refuse-a-kek-inside-the-data-directory.md) keeps them on
separate volumes; it cannot keep them out of the same tar file.

## Decision

Add a third KEK provider, `tpm`, which reads a keyring sealed to the machine's
TPM 2.0.

The keyring on disk becomes ciphertext under AES-256-GCM. The key that opens it
is a 32-byte value sealed into a TPM object created under the owner hierarchy's
storage root key, which the TPM re-derives from its own seed and never exports.
Loading unseals that value, decrypts the keyring, parses it as before and
zeroizes both. The indirection exists because a sealed data object holds at most
128 bytes on most parts and a keyring with several versions exceeds that; it is
the same construction as `internal/crypto/envelope` and for the same reason.

`n0passtemps-wizard kek seal` performs the conversion. It unseals what it has
just produced and compares it against the input before writing anything, so a
TPM that seals but will not unseal is found by the operator rather than by the
next start of the service.

**No PCR policy.** The sealed object is bound to the owner hierarchy and to
nothing else. Binding it to platform configuration registers as well sounds
strictly better and is not: every firmware, kernel and bootloader update moves
those registers, so the service stops starting on a Tuesday for a reason nobody
connects to the update, and what operators do then is recover from the plaintext
copy and turn the binding off. It also does nothing about the attacker this is
for, who holds a copy of the disk and no TPM to present it to. Binding to boot
state defends against the same machine booted into a different operating system,
which is a real attack, a different one, and one that would deserve its own
record.

**Not the default, and not proposed as one.** `provider = "file"` stays what a
deployment gets unless it asks for otherwise.

## Consequences

**What this buys, exactly.** A copied volume, a stolen backup, a cloned virtual
disk or a decommissioned drive now carries ciphertext that opens on one machine.
Attacker 5's opening position, both halves in hand, stops being reachable by
copying files.

**What it does not buy, equally exactly.** Nothing against a live compromise of
the host. An attacker running as the service account asks the same TPM to
unseal, exactly as the service does, and the keyring is in process memory
afterwards as it always was. This is protection at rest. Anything else would
mean the KEK never leaving the device, which for key wrapping means a different
object type and a TPM round trip per sealed record, and is a different design.
The package comment says this first, before it says anything about what sealing
achieves, because a control believed to do more than it does is worse than none.

**The recovery hazard, which is the real cost.** A TPM cannot be backed up. A
dead board, a replaced motherboard or a cleared owner hierarchy makes the sealed
file unreadable for ever, and with it every TOTP secret and every sealed subject
reference in the database. Sealing therefore adds a layer in front of the
offline plaintext copy and does not replace it, and an operator who reads
"sealed" as "safe" and deletes the plaintext has built a way to lose their own
data. The wizard says so at every seal, in those terms, after the success
message rather than before it, because the line people read is the last one.

That hazard is the reason this is opt-in rather than a default. It moves a risk
from one column to another rather than removing one: less exposure to a stolen
disk, more exposure to a dead one. Which trade a deployment wants is not this
project's to choose for it.

**Testing.** `internal/crypto/kek` gains tests that skip when there is no TPM,
the same arrangement the PostgreSQL suite uses, and CI starts `swtpm` so they
run there rather than passing vacuously. `make test-tpm` does the same locally.
The suite includes clearing the owner hierarchy and asserting the keyring no
longer opens, which is the property everything else rests on, tested against a
simulator only: clearing a real TPM would invalidate every other sealed object
on that machine, and a test suite has no business doing that to somebody's
laptop.

swtpm is a TPM in a process, not a part. It agrees with the specification, and
hardware only mostly does, so the tests document how to point them at
`/dev/tpmrm0` and say to do it once before trusting a deployment to a device.

**Dependency.** `github.com/google/go-tpm` moves from an indirect dependency,
pulled in by the WebAuthn library for attestation, to a direct one. It is pure
Go, so CGO stays off, the binary stays static and the six cross-compilation
targets are unaffected. This is most of why the TPM was the right first backend
and PKCS#11 was not: a PKCS#11 backend needs cgo and would have had to live
behind a build tag, producing two binaries where the project promises one.

**What is still open.** The signing key, which is the larger of the two
exposures and the one that is an authentication bypass rather than a
disclosure, is untouched by this. ADR 0018's part three remains open for it, and
the obstacle is now named: Ed25519 and TPM 2.0 do not meet, so the options are a
PKCS#11 token behind a build tag, or teaching the assertion format a second
algorithm. Neither is obviously right and this record does not choose.

## Related

- [ADR 0018](0018-reducing-the-blast-radius-of-a-central-key.md), the record this
  implements part of, and the one that set out what a second key does not buy
- [ADR 0009](0009-refuse-a-kek-inside-the-data-directory.md), keeping the key and
  the ciphertext apart on disk, which this extends to keeping them apart inside
  one archive
- [THREAT-MODEL.md](../THREAT-MODEL.md), attacker 5
- [CONFIGURATION.md](../CONFIGURATION.md#kek), `kek.provider` and the sealing
  procedure
