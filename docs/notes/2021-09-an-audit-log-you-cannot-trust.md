# Note: an audit log you cannot trust

September 2021

## The claim I wanted to make

"The audit log is immutable."

## Why I cannot make it

The deployment model is on-premise. The customer runs it, on their hardware,
with their filesystem. Whatever I do inside the database, the person who owns
the file can open it with the sqlite3 shell and do as they like.

Database triggers refusing UPDATE and DELETE are worth having, because they stop
an application bug from rewriting history. They do not stop anybody who wants
to, and claiming otherwise in the documentation would be dishonest in a way that
matters: an operator who believes the log is tamper proof will treat it as
evidence.

## What is achievable

Not prevention. Detection.

If each entry commits to a hash of the one before it, then altering, removing or
inserting an entry breaks verification for everything after it. Someone with
write access can still rewrite the whole chain consistently, but they have to
rewrite *all of it*, and they have to do so without anyone having recorded the
head hash elsewhere. Selective quiet deletion, which is the realistic threat,
stops working.

That is a genuinely weaker claim than immutability and it is the honest one.

## Two problems I do not have answers to yet

**Retention.** A hash chain and a retention policy are in direct conflict. You
cannot delete the oldest entries without breaking the chain for the rest, unless
the deletion itself is recorded in a way a verifier can resume from. Some kind
of checkpoint, committing to the hash of the last entry removed. Needs thought.

**Erasure.** Worse version of the same problem. If someone exercises a right to
erasure, personal data has to come out of the log. But the hash covers that
data, so removing it breaks the chain.

Leaving the field out of the hash is not acceptable: the subject reference is
exactly the field an attacker would want to alter. Hashing a bare digest of it
is not acceptable either, because a source address has thirty-two bits of
entropy and would be recovered from its digest by exhaustive search in seconds.

Maybe: commit to a *salted* digest of the personal fields, store the salt per
entry, and destroy the salt on erasure. The chain still verifies because the
digest is unchanged, and the digest becomes irreversible because the salt is
gone. I think that works. Needs checking properly before I rely on it.

## Postscript

An external append-only sink solves all of this and I am not going to build one
for version one. Worth saying so in the threat model rather than pretending the
chain is more than it is.
