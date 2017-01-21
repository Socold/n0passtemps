# Note: what problem is actually being solved

January 2017

Writing this down because I keep going round in circles on scope.

## The observation

The small companies I see do not have a password problem in the way the
industry writes about it. They have a password *reset* problem. Nobody is
breaching them with a rainbow table. What happens is:

- somebody leaves and their account stays live for months
- somebody forgets a password and phones whoever is nearest with a keyboard
- the reset goes through an email account with a weaker password than the thing
  it protects
- a shared login exists because setting up a real one was too much work

Every one of those is an identity lifecycle problem wearing a password costume.
A stronger hash does nothing for any of them.

## What second factors have not fixed

SMS codes are worse than nothing in a small company: the phone is often shared,
the number belongs to whoever set up the contract, and porting is trivial. TOTP
is better but it moves the problem to "who has the seed", and the answer is
usually a screenshot of a QR code in someone's inbox.

U2F is the first thing I have seen that changes the shape of the problem rather
than the difficulty of it. The private key never leaves the token, so there is
nothing to screenshot and nothing to share. You either have the key or you do
not.

## Why I have not started building

Two reasons.

The first is that U2F is a second factor, not a replacement. The specification
assumes a password underneath. So U2F on its own cannot remove the reset
problem, it only adds a step. What would remove it is an authenticator that
proves *who* as well as *what*, and the drafts I have read do not do that yet.

The second is that nobody self-hosts identity any more, and I am not sure
whether that is wisdom or fashion. The hosted options are genuinely good. The
argument for on-premise is data residency and not depending on someone else's
availability, and for a ten-person company those are real but not urgent.

## What would change my mind

If the W3C work currently in draft lands with user verification as a first
class thing, so that one gesture proves possession and identity together, then
passwordless stops being a slogan. That is worth building for.

Parking this. Revisit when the specification stabilises.
