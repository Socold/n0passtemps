# 0011. Drop HOTP

Status: accepted
Date: 2024-05-15

## Context

The specification offered two one-time password schemes: time-based passwords
per RFC 6238, and counter-based passwords per RFC 4226.

The two look similar and are not. A TOTP verification needs a shared seed and
the current time, and its replay state is a single high water mark that only
moves forward. HOTP replaces the clock with a counter held on both sides, and
those counters drift apart whenever a user generates a code without submitting
it, which happens constantly with hardware tokens that have a button. Making
HOTP usable therefore requires a look-ahead window, a resynchronisation
procedure, and a policy for how far ahead to search and what to do when a code
matches near the far edge of that window.

Each of those is a place where authentication bugs live. A look-ahead window
that is too wide accepts codes the user generated long ago; resynchronisation is
an authenticated state change driven by unauthenticated input; and the
interaction between look-ahead and rate limiting is a documented source of
bypasses. The deployments this service targets use platform authenticators,
roaming security keys and phone authenticator applications, none of which need a
counter.

## Decision

Support TOTP only, per RFC 6238.

The schema carries a sealed seed, the algorithm, the digit count, the period in
seconds and `last_timestep`, and nothing else. There is no counter column, no
look-ahead setting and no resynchronisation endpoint. A code is accepted only if
its timestep is strictly greater than the stored high water mark, and the update
is a compare-and-swap, so two concurrent requests presenting the same valid code
cannot both succeed.

## Consequences

The verification path has one branch and one piece of mutable state, which is
small enough to test exhaustively. There is no window parameter for an operator
to widen and no resynchronisation call to abuse.

Deployments holding counter-based hardware tokens cannot use them. Those users
have to move to a WebAuthn authenticator or fall back on the recovery codes of
ADR 0005, and for an organisation with an existing stock of HOTP tokens that is
a procurement cost, not a configuration change.

TOTP substitutes a dependency on clocks for the dependency on counters. A server
or client whose time is wrong rejects valid codes, and unmanaged on-premise hosts
without NTP do drift, which is the same exposure noted in ADR 0004.

Adding HOTP later would mean a schema migration and a second verification path,
so this decision is cheap now and not cheap to reverse.
