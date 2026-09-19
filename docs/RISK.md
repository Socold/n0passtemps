# Risk signals

This service reports risk. It never refuses an authentication on risk alone.

That sentence is the whole design, and everything below follows from it. The
service runs the ceremony, sees a handful of things worth mentioning, writes
them into the signed assertion and into the audit log, and hands the result to
the integrating application. The application decides whether to ask the user
for something more, because it is the one that knows what the user is about to
do. Reading a document is not transferring money.

## This is not machine learning

It is a table of nine signals, each with a weight, and two thresholds. Adding
the weights of the signals that fired gives a score, and the score maps onto
one of three levels. That is all of it.

There is no model, no training data, no behavioural baseline, no device
fingerprint and no third-party reputation feed. Nothing here needs network
access, nothing changes on its own between one release and the next, and there
is no state that accumulates and later surprises an operator. Two identical
ceremonies produce byte-identical assessments, on any deployment with the same
configuration, for ever.

The reason for that is not modesty about what a model could do. It is that a
user who has been asked for a second factor is entitled to an answer to "why",
and the only answer this service is willing to give is one an operator can read
off a table. A score produced by a model is not an explanation, and an
authentication product that cannot explain its own refusals ends up teaching
its users to click through them.

The feature is therefore called risk signals. It is not called adaptive
authentication, because a handful of thresholds is not adaptation, and an
operator who was promised adaptation would be right to be disappointed.

## The levels

| Level | Meaning | What an application should do |
|---|---|---|
| `low` | Nothing in the ceremony stood out | Carry on. This is most authentications |
| `elevated` | One signal fired that says the ceremony proved less than a full unphishable factor, or that the authenticator was not quite the one enrolled | Proceed for ordinary use. Ask for a second factor, or refuse, before a consequential action: changing a password or an email address, adding a payment method, moving money, exporting data, granting access to someone else |
| `high` | Either one signal that is evidence of an attack rather than of a weaker ceremony, or several weaker signals together | Grant the session, then treat it as untrusted. Ask for another factor before anything consequential, and consider notifying the account holder out of band. An operator gets an alert for every one of these |

A level is never a licence to skip a check the application would otherwise
make. `low` does not mean the person is who they claim to be; it means this
service saw nothing worth reporting about how they proved it.

## The reason table

Each reason is derived from something the service already collected while
completing the ceremony. None of them exists to be collected for this purpose,
and none of them needs data the service was not already holding.

| Reason | Weight | Alone | What it means, and why it is not a refusal |
|---|---|---|---|
| `signature_counter_stalled` | 40 | `high` | The authenticator's signature counter did not advance between two assertions, which is the signal WebAuthn documents for two copies of one credential private key being in use. It is the only signal here that is evidence of a specific attack, which is why it reaches `high` on its own. It is still not a refusal: many authenticators report a constant zero and a synchronised passkey does the same, so refusing would lock out a large share of ordinary users |
| `recovery_code_used` | 25 | `elevated` | A single-use recovery code completed the ceremony. It is the weakest factor the service offers and the one an attacker who has taken over a mailbox or a phone number reaches for. It is also the legitimate way back in for a user who has lost their key, which is exactly why it cannot be a refusal |
| `authenticator_binding_changed` | 20 | `elevated` | The authenticator's observed characteristics differ from those recorded at registration. A firmware update or a change of transport moves them legitimately, so this is reported and not refused |
| `user_verification_absent` | 20 | `elevated` | A WebAuthn assertion where the authenticator proved possession of the device and not the identity of its holder: no PIN, no biometric. This is what a stolen key without its PIN produces. It never fires under the default `webauthn.user_verification = "required"`, because such an assertion does not complete at all |
| `credential_dormant` | 10 | `low` | The credential has not been used for longer than `risk.dormant_after`. A spare key kept in a drawer is dormant because it is a spare, which is why the weight is low; a dormant key waking up alongside another signal is worth seeing. A credential that was enrolled and never used is measured from its registration |
| `credential_new` | 10 | `low` | The credential was registered within `risk.new_credential_within`, so a freshly enrolled authenticator authenticating immediately is visible. Enrolling and then signing in is the normal shape of setting a key up, so on its own this says nothing |
| `recent_failures_subject` | 10 | `low` | At least one attempt against this subject failed inside the current throttle window before this one succeeded. One mistyped code is the common cause, which sets the weight; failures followed by a success on the weakest factor is the shape of a guess that landed |
| `totp_only` | 10 | `low` | The subject holds no WebAuthn credential, so the factor that authenticated them is phishable and there is nothing stronger to fall back on. This is as much a deployment choice as a risk, and a subject with nothing stronger cannot be stepped up to it, so it stays low alone |
| `recent_failures_network` | 5 | `low` | At least one attempt from this source network failed inside the current throttle window. The lightest weight in the table: one corporate gateway carries many users, so failures on a network say much less about this subject than failures against the subject do. The network is the unit the rate limiter buckets on, a /64 for IPv6 |

Some reasons cannot co-occur. `totp_only` needs a TOTP ceremony, so it never
appears with the three WebAuthn signals. `credential_new` and
`credential_dormant` are mutually exclusive under any sane pair of windows.
`user_verification_absent` is asked only of a WebAuthn ceremony, because
scoring it for a code would count the same weakness twice.

## The thresholds

| Setting | Default | Why |
|---|---|---|
| `risk.elevated_at` | 20 | The weight of the lightest single signal that says the ceremony proved less than a full unphishable factor, or that the authenticator was not the one enrolled. Anything at or above it is worth telling the application about |
| `risk.high_at` | 40 | Double `elevated_at`: either one signal that is evidence of an attack rather than of a weaker ceremony, or the weakest factor together with the failures that preceded it |

Both comparisons are inclusive, so a score of exactly 40 is `high`.

The weights are multiples of five so that one can be retuned without
renumbering the rest. The combinations the defaults were chosen for are:

- `recovery_code_used` + `recent_failures_subject` + `recent_failures_network`
  = 40, `high`. A recovery code redeemed right after failures against the same
  account from the same network is the account-takeover shape, and it is the
  one an operator most wants to be told about.
- `user_verification_absent` + `authenticator_binding_changed` = 40, `high`. A
  possession-only assertion from an authenticator whose characteristics no
  longer match the enrolled ones.
- `recent_failures_subject` + `recent_failures_network` = 15, `low`. One
  mistyped code before a success must not escalate anything, or the level stops
  meaning anything.
- `credential_dormant` + `recent_failures_subject` = 20, `elevated`. A key
  unused for ninety days, used immediately after failures against the account.

## Where the assessment appears

**In the signed assertion**, as the `risk` claim:

```json
{
  "iss": "n0passtemps",
  "sub": "...",
  "amr": ["recovery-code"],
  "risk": {
    "level": "high",
    "reasons": ["recovery_code_used", "recent_failures_subject", "recent_failures_network"],
    "score": 40
  }
}
```

This is the only copy an application may act on. It is covered by the Ed25519
signature, so it cannot be rewritten in transit.

The claim is absent entirely when `risk.enabled` is false, so an application
integrated against a deployment that does not report risk sees exactly the
token it saw before this feature existed. A verifier must not require the
claim: an optional claim that a verifier insists on is not optional. `reasons`
is always present inside the claim, as an empty array when nothing fired.

**In the response body**, as `risk_level` and `risk_reasons` beside `factors`.
These are **unsigned**. Anything on the network path between the service and
the caller can rewrite them, including downgrading `high` to `low`. They exist
for logging and for a first look during integration. A caller that reads its
step-up policy out of the response body has thrown away the reason the
assertion is signed at all.

**In the audit log**, as the `risk` key of the detail on
`assertion.completed`, `totp.verified` and `recovery.consumed`. It carries the
same level, reasons and score as the claim, from the same value, so an operator
reading an entry sees exactly what the application was told. Because the
assessment is a pure function of its inputs, anyone can recompute it from the
entry and get the same answer.

**As an alert**, `risk.high`, at warning severity, for a high assessment only.
See [MONITORING.md](MONITORING.md).

## Configuration

See the `[risk]` section of [CONFIGURATION.md](CONFIGURATION.md). In short:
`enabled`, the two thresholds, `dormant_after`, `new_credential_within`, and a
`[risk.weights]` table that overrides individual weights. A reason an operator
wants ignored is given a weight of `0`; it still appears in the list, because
it did fire, and contributes nothing to the score. A negative weight is refused
at startup, because one signal cancelling another out is not something a
threshold policy should be able to express.

## What this does not buy

See [THREAT-MODEL.md](THREAT-MODEL.md) for the full statement. Briefly: every
signal here is a property of the ceremony, not of the person. An attacker who
holds the authenticator and its PIN produces a ceremony that looks exactly like
the legitimate one, and no threshold in this table will say otherwise.
