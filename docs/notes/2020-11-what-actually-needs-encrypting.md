# Note: what actually needs encrypting

November 2020

Sketching the storage model. Writing this because my first instinct was wrong
and I want to remember why.

## The instinct

Encrypt everything. It is an authentication database, so every column is
sensitive, so seal the lot under a key and be done.

## Why that is wrong

Encryption buys confidentiality. It costs availability: anything sealed under a
key is gone if the key is gone. So the question for each column is not "is this
sensitive" but "what is lost if it leaks, and what is lost if the key does".

Going column by column:

**WebAuthn credential public keys.** These are public keys. The clue is in the
name. An attacker who reads one learns nothing they could not learn by asking
the authenticator. What matters is that nobody can *change* one, because
swapping in their own public key is a complete account takeover. So: integrity,
not confidentiality. Encrypting these would mean a lost key destroys credentials
that were never secret, which is pure downside.

**TOTP seeds.** Symmetric. The server has to read them to verify a code, and
anyone who reads one can generate codes forever. This is the real case for
encryption at rest.

**Recovery codes.** Interesting one. They are secret, so the instinct says
encrypt. But the server never needs to *read* a recovery code, only to decide
whether a presented one matches. That is a hash, not a cipher. And hashing is
strictly better here: a lost key does not invalidate them, and a stolen database
yields nothing even to someone who also has the key.

**The customer's user identifier.** The documentation will say "send us an
opaque identifier". Every integration will send an email address. So treat it as
personal data regardless. But it also has to be searchable, or logging someone
in requires a table scan. So: a deterministic keyed hash for lookup, and an
encrypted copy for the rare case where a human needs to know who a row is.

## Consequence for key loss

Worth stating plainly because it changes the disaster story. If the key is lost:

- TOTP seeds: gone, users re-enrol
- encrypted identifier copies: gone, lookup still works via the hash
- WebAuthn credentials: unaffected
- recovery codes: unaffected

So a lost key is a bad afternoon, not an extinction event. That is worth
designing for, because keys do get lost.

## Two keys, not one

One more thing. The key that decrypts secrets and the key that turns an email
address into a lookup value should not be the same key. If they are, whoever
holds it can both read the secrets and confirm whether a named person has an
account. Those are different capabilities and they should require different
secrets.
