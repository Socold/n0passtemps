# 0015. Enrolment tickets instead of magic links

Status: accepted
Date: 2026-09-17

## Context

Phase 2 of the specification names magic links: a link, sent by email, that
signs the user in. It exists to answer a real question, and one the service
otherwise has no answer to. A user who holds no authenticator and no recovery
code cannot authenticate, and an application that cannot get them back in has
to route around this service entirely.

Implementing it as written costs three things.

It makes the service send email. That means an SMTP dependency, credentials
for it, deliverability as an operational concern, and outbound network access
from a process that currently needs none. The deployment story is a single
static binary with a database; adding a mail client to it is not a small
change to that story.

A magic link is phishable and forwardable. It is a bearer secret in a URL,
delivered over a channel designed to forward things. Everything else this
service offers is built the other way: WebAuthn is origin-bound, TOTP is
short-lived, recovery codes are single-use and explicitly described as the
weakest factor.

It makes the mailbox the root of trust again. The first design note in this
repository, from 2017, identifies exactly that as the problem to get away
from: a reset routed through a mailbox is a credential no stronger than the
mailbox, and the mailbox is usually weaker than the thing it protects. Adding
a mailbox-rooted sign-in to a passwordless product argues against the product.

## Decision

The useful half is kept and the harmful half is dropped.

An enrolment ticket is a single-use, short-lived secret that authorises
exactly one thing: starting and completing one WebAuthn registration for the
subject it names. It never produces a signed assertion. Redeeming one gets a
user an authenticator; it does not get anyone a session.

The service does not deliver it. It returns the ticket once, in the issuing
response, and the integrating application delivers it by whatever channel it
judges appropriate: email, SMS, a printed letter, a support call. Delivery is
the application's responsibility and its risk, which is where the knowledge of
the user and of the channel actually lives.

The secret reuses the recovery-code construction from
`internal/crypto/recovery` unchanged: an indexed selector in clear and an
Argon2id verifier. The two secrets differ in what they authorise and in how
long they live, not in how they are built.

Issuing a ticket for a subject who already holds a usable factor is refused
unless the caller overrides it explicitly. The override is audited and raises
an alert.

## Consequences

A stolen ticket is an enrolment, not a session. The attacker ends up with an
authenticator registered in their own name against the subject, which is
recorded in the audit log, visible in the subject's credential list, alerted
on when it overrode an existing factor, and revocable. A stolen magic link is
a logged-in user.

The service still has no outbound network access and no SMTP configuration.

The channel risk moves to the application, and that is a real transfer rather
than a removal. An application that emails tickets to an address an attacker
controls has the same exposure a magic link would have had, minus the session.
This decision does not make that safe; it makes it the decision of the party
that can see who the user is.

A user who will never hold an authenticator is not served by this. Tickets
lead to a WebAuthn registration and nothing else. For such a user the honest
answer remains TOTP, which the service already offers.

The refusal on an existing factor is a default, not a guarantee. An operator
with the `enrolment_ticket.issue` permission can override it, because a
confirmed TOTP secret on a phone the user no longer has still reads as a
factor to this service and refusing forever would strand them. The override is
the step an attacker who controls delivery needs, which is why it is the one
part of this flow that raises an alert on its own.
