# n0passtemps

Notes towards an on-premise passwordless authentication service.

## Why

Small companies do not have a password strength problem. They have a password
lifecycle problem: accounts that outlive the employee, resets that route through
a weaker mailbox, shared logins created because provisioning a real one was too
much work. A stronger hash addresses none of that.

U2F is the first thing that changes the shape of the problem rather than its
difficulty: the private key never leaves the token, so there is nothing to
screenshot and nothing to share.

## Why not yet

U2F is a second factor. The specification assumes a password underneath, so it
adds a step rather than removing the reset path. What would remove it is an
authenticator that proves identity as well as possession, in one gesture.

The W3C work on that is in draft. Until it stabilises, building this means
building on a moving target.

## Constraints, if it happens

- on-premise, self-hosted, no dependency on a hosted identity provider
- data stays with the operator
- the credential belongs to the customer, not to this service, so leaving costs
  nothing
- simple enough that a company without a platform team can run it

## Status

Thinking, not building. See docs/notes/.
