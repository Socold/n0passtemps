# Note: where the relying party sits

April 2019

WebAuthn Level 1 became a Recommendation last month, which was the condition I
set myself in the 2017 note. So: what would this actually look like.

## The awkward part

WebAuthn is origin bound. The authenticator signs over the origin and the
relying party identifier, and the server checks them against what it expects.
That is the property that makes it unphishable, and it is the whole reason to
bother.

But it means a shared authentication service has an identity problem of its own.
If I run auth.example.com and a customer's app is at app.customer.com, then
whose origin is being signed?

Three options, none free:

**1. The service is the relying party.** Users are redirected to
auth.example.com, the ceremony happens there, the app gets a token back. This is
how every hosted identity provider works. It means every customer's users see my
domain, and a credential registered for my domain is useless to them if they
leave. Lock-in by construction, which is the opposite of the point.

**2. The customer is the relying party.** Their front end runs the ceremony
against their own origin and forwards the result to me for verification. Their
users never see my domain and their credentials stay theirs. But I have to be
told which origins to accept, and that list has to be configuration rather than
something the caller sends, or an attacker just declares their own origin and
the binding proves nothing.

**3. Per-customer subdomains.** auth-customer.example.com. Works, needs
wildcard certificates and DNS automation, and still means the credential is tied
to my infrastructure.

## Leaning towards option 2

It is the only one where a customer can walk away without their users
re-enrolling. Since the pitch is on-premise and no lock-in, anything else
contradicts the premise.

The cost is that configuration becomes load bearing in a way that is easy to get
wrong. rp_id has to be a bare registrable domain, the origin list has to be
exact, and the two have to be consistent with each other. Those are three
different mistakes with the same symptom: the ceremony fails in the browser with
an error that says nothing useful about which one it was.

If I build this, the configuration validator has to check the relationship
between rp_id and each origin at startup, not at ceremony time. Catching it
before the listener comes up is the difference between a five-minute setup and
an afternoon.

## Two round trips means state

The other thing I had not thought about: a ceremony is begin then complete, and
the challenge issued by the first has to be bound to the second. Which means
server-side state, with a lifetime, single use.

Handing the state back to the caller in a cookie is the obvious shortcut and it
is wrong here, because the caller is another server rather than a browser, and
because then the caller can tamper with the expected challenge. So: a table,
with an expiry, and single use enforced by the database rather than by
convention.
