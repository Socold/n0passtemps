# 0021. Bind every sealed record to the row it lives in

Status: accepted
Date: 2026-09-20

## Context

Envelope encryption protected the two columns that hold a symmetric secret,
`totp_secrets.secret_sealed` and `subjects.ref_sealed`, and the record was
authenticated: AES-GCM covers the payload, and the record header is additional
authenticated data for both the wrapped data key and the payload, so the key
version and the wrapped key cannot be swapped between records.

Nothing tied a record to where it was stored. `Seal` took a plaintext and
returned bytes; `Unseal` took bytes and returned a plaintext. A ciphertext
sealed under the key encryption key was therefore valid everywhere: in any row,
in either column, in any tenant. The header authenticates the record against
itself, which proves the bytes have not been edited and says nothing about
where they came from.

The attacker this leaves out is the one the key encryption key exists for:
someone who can write to the database without holding the key. SQL injection,
an administrator of the database, a restored backup, a replica someone can
write to. ADR 0018 is built on the assumption that such an attacker cannot read
the sealed columns. They could not, and they did not need to:

- Enrol TOTP on an account of their own, keep the seed they were shown, and
  copy their own `secret_sealed` over the victim's row. The service unseals it,
  the codes the attacker generates verify, and they hold the victim's second
  factor without ever seeing the victim's seed.
- Copy the `ref_sealed` of a subject in another tenant into a subject of their
  own, then read the plaintext back through the route that discloses a
  reference. The reference is usually an email address. That is personal data
  crossing a tenant boundary, through a route that is working exactly as
  designed.

Neither needs the key. Both are a write to one column.

## Decision

`Seal`, `Unseal` and `Rewrap` take a mandatory binding context, and that
context enters both GCM operations, the wrapping of the data key and the
payload, as additional authenticated data. The record no longer opens anywhere
but where it was sealed.

The context is a struct with named fields, not a string a caller assembles. It
names:

- **the kind of field**, `subject_ref` or `totp_secret`, so a ciphertext from
  one column cannot be opened as if it came from another, and so a column added
  later starts in its own namespace rather than sharing one by accident;
- **the tenant**, so a record cannot cross the boundary that separates two
  customers, which is the boundary this service promises and the one whose
  breach discloses personal data;
- **the identifier of the row**, so a record cannot be moved between two rows
  of the same column in the same tenant;
- **the subject**, for a TOTP secret only. Binding the row alone would leave
  the attack standing: a TOTP row can be inserted whole, so an attacker who can
  write rows would simply bring their own row identifier along with the seed.
  The subject is what the factor authenticates, so it is what the seed is bound
  to. A subject reference leaves this field empty, because there the row
  identifier already is the subject and a second copy of it could only drift.

The context is serialised with a domain separator and a length prefix per
field, not joined by a delimiter. There is no byte that is impossible in a
tenant name today and will stay impossible for the life of the service, and a
delimiter that can appear inside a value lets two different contexts produce the
same bytes. With lengths in front, they cannot.

A context that does not name all of its fields is refused, on every operation,
including on a record in the old format that will not use it. `Seal` refuses to
write a record that binds nothing, and a caller holding an incomplete context
must not discover that it happens to work against the oldest rows.

The context is never stored beside the ciphertext. Storing it would only prove
the ciphertext agrees with itself. It is rebuilt from the row that was read,
which is what makes the check mean anything.

### Migration

Existing records are in the format written before this decision. They cannot be
rewritten without being decrypted, which needs the key encryption key, which
the service holds only while it is running.

The format version already sits in the first byte of every record, so the two
formats tell themselves apart. Version 2 is written from now on. Version 1 is
read, with the authenticated data it was written with, and is rewritten as
version 2 by the next pass of `POST /admin/v1/kek/rewrap`, whether or not its
key version has changed. No schema change and no migration file: the byte that
distinguishes the formats is already in the column, and a column tracking which
rows remain would be a second copy of a fact the data already carries, kept in
step by hand.

That pass also had a defect of the same family, fixed here. It counted a record
already on the current key version as `already_current` from its header alone,
without opening it, so the one job that reads every sealed value in the
deployment declared a corrupted or substituted row to be sound. Every record is
now opened, including one that needs no rewriting.

## Consequences

An attacker who can write to the database but does not hold the key encryption
key can no longer move a sealed record. Not into another row, not into another
column, not into another tenant. Both attacks above fail with the same error a
corrupted record produces, because from the cipher's point of view they are the
same event. What that attacker can still do is destroy: overwriting a sealed
column with anything at all still denies the user their factor, and no key
protects against deletion.

The binding costs nothing at rest. The context is authenticated, not stored, so
a record is the same length it was, and the work added per operation is one
short byte string built and hashed.

The migration costs one rewrap pass per deployment. Until it has run, the
records it has not reached are in the old format and carry exactly the weakness
described above: they still open in any row. This is the honest price of not
being able to rewrite ciphertext without the key, and the window is as long as
an operator leaves it. A pass that reports zero rewrapped and zero failed is
the signal that no record is left on an old key or an old format. The reading
path for version 1 is transitional and commented as such; a later record may
retire it, and should, because for as long as it exists an attacker who can
write to the database can also downgrade a row by writing an old-format record
they obtained from a backup.

This does not extend to material that is not sealed. The WebAuthn credential
public key is stored in clear and without a MAC, by the decision recorded in
ADR 0006, for reasons that still hold: it is a public key, and encrypting it
would put the factor most deployments rely on behind the key encryption key.
The consequence stated there is unchanged and is worth repeating next to this
record, because the two are easy to confuse: the same attacker, with the same
write access, can still insert a credential of their own and authenticate as
any subject. That is a known limit, not an oversight, and it is the reason the
credential table is audited. ADR 0007 states what the audit log can and cannot
prove about it.

Recovery codes are out of scope for the same kind of reason from the other
direction: they are hashed, not encrypted, per ADR 0005, and a hash carries no
ciphertext to move.
