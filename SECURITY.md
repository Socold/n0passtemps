# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub's private vulnerability reporting, on the
[Security tab](https://github.com/Socold/n0passtemps/security/advisories/new) of
this repository.

Do not open a public issue for a vulnerability. A public issue is visible to
everyone, including to operators who have not yet upgraded, which makes the
people running the affected version less safe rather than more.

There is no security contact email address. The project has no private support
channel of any kind, and adding one for security reports alone would create an
address nobody monitors reliably.

## What to include

A report is easier to act on when it contains:

- the affected version, from `n0passtemps-server --version`
- the configuration, with secrets removed, in particular the `webauthn`,
  `features` and `throttle` sections
- the steps to reproduce, or a proof of concept
- what an attacker gains, and what they need to start with

The last point matters most. A finding that requires an attacker to already hold
a valid administrative token is a real finding, but it is a different severity
from one reachable without credentials, and stating the precondition avoids a
round trip.

## Scope

In scope:

- authentication bypass on any `/v1` or `/admin/v1` route
- privilege escalation between the three administrative roles
- cross-tenant data access
- recovery of plaintext secrets from a stolen database, with or without the key
  encryption key
- replay of a WebAuthn assertion, a TOTP code or a recovery code
- undetected modification of the audit log
- denial of service reachable without authentication

Out of scope:

- an operator who deliberately weakens their own configuration, for example by
  setting `webauthn.user_verification` to `discouraged`. The configuration
  validator refuses the settings known to be unsafe and explains why; a setting
  it permits and documents as a trade-off is a choice, not a vulnerability.
- tampering with the audit log by an operator who holds the database file. The
  hash chain makes this detectable, not impossible, and `docs/THREAT-MODEL.md`
  states so. A report that the chain can be rewritten wholesale by someone with
  write access to the file is describing a documented limitation.
- findings that depend on running the service without TLS on a public interface.
  The configuration validator refuses to serve plain HTTP on any address that
  is not loopback, unless TLS is configured in process, `server.trust_proxy`
  declares the proxy that terminates it, or `server.allow_plaintext` is set.
  That last setting is the operator's explicit statement that something outside
  the process bounds who can reach the port, such as a loopback publish rule or
  a NetworkPolicy. Neither the binary nor the container image sets it; the
  compose files and the Kubernetes ConfigMap under `deploy/` do, each beside
  the rule that makes it true. A deployment that sets it with nothing bounding
  access has been configured to be exposed, and a finding that starts there is
  out of scope. A way to get plain HTTP served on a non-loopback address
  without one of those three settings is in scope.
- missing hardening that has no exploit path, reported from a scanner without
  analysis.

## Supported versions

The most recent minor release receives security fixes. Older minors do not.

| Version | Supported |
|---------|-----------|
| 1.x     | yes       |
| < 1.0   | no        |

## Disclosure

Reports are acknowledged and triaged as time allows. This is a project run by
one person with no commercial support behind it, so no response time is
promised and it would be dishonest to publish one.

Fixes are released as a patch version with an advisory naming the affected
versions and the workaround, if one exists. Credit is given in the advisory
unless the reporter asks otherwise.
