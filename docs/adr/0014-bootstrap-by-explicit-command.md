# 0014. Bootstrap the first administrator by explicit command

Status: accepted
Date: 2026-03-04

## Context

A fresh deployment has no administrative token, and every route that mints one
requires one. The specification does not say where the first token comes from.

The common answer is for the service to mint a token on its first start and
print it. That puts the most powerful credential in the deployment into a log
stream, and log streams are shipped, indexed and retained by systems whose
access rules are looser than those of a credential store. The token sits in
clear in each of them, and revoking it helps only the operator who remembers
to.

## Decision

The running service never writes an administrative token. With no usable full
administrator it logs a warning that names the command.

The first tokens are created by a one-shot invocation of the same binary:
`n0passtemps-server -config <path> -bootstrap-admin`. It mints `admin_full`
tokens, audits each with `bootstrap: true`, prints them to standard output and
exits. It refuses when a usable full administrator already exists.

`-admins N`, from 1 to 5, creates the initial quorum. With dual approval on,
minting a token through the API needs a second administrator, so a deployment
with one can never create its second. An API exemption for a sole administrator
is the wrong answer: a rogue administrator reaches it by revoking the others,
mints a token they control, and approves their own requests from then on. The
API keeps no exemption, and the quorum is created here with `-admins 2`.

`-force` lifts the refusal, for the operator who has lost every token or has to
complete a quorum. Neither flag grants anything new: whoever can run the command
already holds the configuration, the keyring and the database. The audit entry
records `forced: true`.

## Consequences

A token never enters a log pipeline.

The five-minute install has one more step. The service starts, answers its
health probe, and cannot be administered until the command is run; the warning
in the log is the only prompt. Container users have to know `docker compose
run`, which is less familiar than reading a log.

The tokens still appear once in clear, on the operator's terminal, and
scrollback or a recorded session can keep them. That exposure is smaller than a
log pipeline and is not zero. The remedy is unchanged: mint named tokens
and revoke the bootstrap ones.

With `-admins 2` both halves of the two-person rule are on one screen until the
second token is handed over, and nothing verifies that it ever is. An operator
who forgets the flag under dual approval is stuck until they run the command
again with `-force`.
