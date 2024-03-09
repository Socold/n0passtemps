# 0001. Record architecture decisions

Status: accepted
Date: 2024-03-09

## Context

A written specification for this service existed before any code was committed.
A technical review of that document found defects rather than gaps: routes with
no authentication scheme at all, a quickstart that stored the key encryption key
beside the ciphertext it protects, and cryptographic choices that did not match
what the server actually has to do with the material it holds.

The implementation therefore departs from the specification on eleven points.
Each departure is a considered engineering decision, and each one makes the code
disagree with a document that readers will still find in the repository. Without
a record of the reasoning, someone comparing the two has no way to recognise a
deliberate deviation. The likely outcomes are both bad: the specified behaviour
gets reimplemented, reintroducing the defect, or the argument is re-derived from
first principles by every reviewer in turn.

The project is open source under the MIT licence, so contributors arrive without
any of the review context. The record has to live in the repository, be
reviewable in the same change as the code it justifies, and be readable with no
tooling beyond a text editor.

## Decision

Keep a numbered sequence of architecture decision records under `docs/adr`, one
file per decision, in the form described by Michael Nygard: context, decision,
consequences, and nothing else. State the decision in the imperative and state
the costs honestly alongside the benefits.

Treat an accepted record as immutable. A decision that stops holding is
superseded by a new record that references it, never edited in place, so the
history of the design stays legible.

Records 0002 to 0012 document the eleven deviations from the original
specification. `docs/adr/README.md` indexes the set.

## Consequences

Every non-obvious design choice now costs a short document, and reviewers have
to read it. That is deliberate friction.

The records are a second description of the system, and a second description can
drift from the first. An ADR states intent at the date on its header, not the
current state of the code, so a reader who needs present behaviour must still
read the code. Records that have quietly stopped being true are worse than no
records, which means the superseding discipline has to be enforced in review.
