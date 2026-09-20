# 0016. Ship the audit chain to an external witness, and only the chain fields

Status: accepted
Date: 2026-09-20

## Context

The audit log is hash chained, so altering, removing or inserting an entry
breaks verification for every entry after it. That detects tampering by anybody
who does not hold the database file. It detects nothing done by the party who
does: the operator can edit a row, recompute `prev_hash` and `entry_hash` from
the edit onwards, and the result is indistinguishable from an untouched log.
`GET /admin/v1/audit/verify` reports `intact: true`. Attacker 9 in
[THREAT-MODEL.md](../THREAT-MODEL.md) says so, and says what would close it: a
copy held somewhere the operator cannot rewrite, because a rewritten chain
cannot reproduce hashes somebody else already holds.

Three things make this awkward to build. The recorder runs on the request path,
so a destination that is slow or down must not cost an authentication anything.
The product's argument is that it runs with no outbound network access at all,
so any network code has to be absent rather than merely idle by default. And an
audit entry names a subject and a source address, so a copy held by a third
party is a disclosure of personal data unless the copy is narrower than the
entry.

## Decision

Entries are delivered to an HTTP endpoint with a bearer credential, off unless
`audit.sink.endpoint` is set, and four things are decided with it.

**Only the hash-covered fields are sent.** The chain commits to a salted digest
of the three personal fields rather than to the fields themselves, which is what
lets an entry be erased without breaking verification. So the digest travels and
`subject_id`, `source_ip` and `detail` do not, and neither does the salt, since
a source address has about thirty-two bits of entropy and a receiver holding
both salt and digest would recover it by exhaustive search. The set that remains
is exactly the hash input, which is exactly what a receiver needs to verify and
nothing more. `detail` is the field that would otherwise have been the leak:
nothing models its shape and nothing bounds what a future caller puts in it, so
it is bounded by exclusion rather than by a filter somebody has to maintain.

**The audit log is the buffer.** `Offer` is a non-blocking hand-off onto a
bounded queue, returns nothing and can fail at nothing. An entry the queue
cannot take is dropped, counted, logged and alerted on, and then delivered
anyway, because the shipper falls back to reading the audit log from one past
the last sequence number the receiver acknowledged. A full buffer therefore
costs latency and a database read, never a hole in the witness, and the same
path covers a restart, an out-of-order offer and a failed POST.

**At least once, watermark written last.** A file in the data directory records
how far delivery has got, and it is written only after the receiver has
acknowledged a batch. A process that dies in between sends that batch again.
The other order would be at most once: the marker would move, the entries would
never arrive, and nothing would ever go looking for them.

**The operator declares the trust assumption.** `audit.sink.endpoint` is refused
unless `audit.sink.receiver_outside_operator_control` is set to true. This code
cannot check where the receiver is, and a sink the operator administers is
worthless rather than merely weaker: a file on the same host, a bucket under the
same credentials or a log collector the same root account manages all fall to
the attacker the chain already fails to stop.

A message broker was considered and refused. Kafka or NATS would deliver this
better and would add a dependency, an operator obligation and a second thing to
keep running, for a product whose whole claim is one static binary and one
database. An HTTP endpoint is something every deployment can stand up, and the
one property that matters, that somebody else runs it, is not a property a
broker would add.

## Consequences

A witness that stays level with the deployment can prove the log was not
rewritten, for the entries it holds. It can do so without holding anybody's
personal data, and a reader of the batch cannot tell which subject an entry
concerns.

That last point is also the limit. The copy answers "was this history
rewritten" and nothing else. It cannot be used to investigate an incident, to
answer a subject access request, or to reconstruct the log if the database is
lost, because it carries no subject, no address and no detail. A deployment that
wants an external copy it can read is asking for log shipping, which is a
different feature with a different disclosure.

Delivered entries are beyond this service's reach for ever, an erasure request
included. Nothing personal was delivered, so Article 17 is not engaged by the
contents; what the receiver holds is a commitment nobody can reverse without a
salt that never left the database. An operator who needs the receiver's copy
bounded anyway bounds it with the receiver's own retention, which is why the
configuration makes them declare that they know what they set up.

Retention trimming and the witness pull in opposite directions. Entries trimmed
before they were delivered cannot be delivered, and the receiver sees a gap it
cannot tell from tampering. The shipper reports that case at error level rather
than delivering in silence, and the guidance is unchanged: leave
`audit.retention_days` at 0 and prune deliberately.

A deployment with a sink configured makes outbound connections, which is a
change in what the network policy around this service has to allow, and a new
place a credential has to be rotated. That is the price of the property, and it
is why the default is off and why the shipper refuses to start rather than run
silently without a credential.
