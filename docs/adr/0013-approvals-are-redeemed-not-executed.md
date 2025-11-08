# 0013. Approvals are redeemed, not executed

Status: accepted
Date: 2025-11-08

## Context

The specification asks for a dual-approval queue, "sensitive ops require 2
admins", and says nothing about how an approved operation comes to run. The
obvious reading is a deferred job: the first administrator queues the operation
and it executes at the moment the second one approves.

That reading has two defects. The result of the operation is returned to
whoever made the call that ran it, which is the approver. For
`admin_token.create` the result is a freshly minted token, shown once, and it
would reach the wrong administrator. And an executor that runs at approval time
is a second implementation of every held operation, reached from a different
code path with different checks, which is where an authorisation rule
eventually goes missing.

## Decision

Model an approval as a capability that the original requester redeems.

The first request queues the operation, performs nothing, and answers 202 with
the problem type `approval-required` and the approval identifier. A different
administrator approves it. The requester then repeats the identical request with
the header `X-Approval-Id`, and only that redemption executes, through the same
handler as any other call.

A redemption is accepted only when five checks hold: the approval names the same
operation; the redeemer is the original requester; the payload equals the
approved payload, so what runs is what the second administrator read; the
approval has not expired; and a conditional update from approved to executed
succeeds, so it is spent exactly once under concurrent redemption. Every refusal
is the same 403, and each is audited.

The claim happens before the operation runs. If the operation then fails, the
approval is spent anyway. Failing closed costs a repeated request; failing open
would let one approval run an operation twice.

## Consequences

Each held operation has one implementation and one set of checks, and a secret
produced by it reaches the person who asked for it.

The requester has to make a second call and repeat the body exactly. A changed
reason, or a different subject, is refused as a different request, and the
refusal does not say which check failed, because saying so would let a caller
probe for another administrator's approvals. An administrator who mistypes has
to read the audit log to learn why.

An approval can be burned by a failing operation. A database error between the
claim and the write costs a fresh request and a second approval from a colleague
who may have gone home.

Nothing executes on approval, so an approved operation whose requester never
returns does not happen. It expires after `features.approval_ttl`, and no alert
says so.
