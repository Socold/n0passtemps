# 0008. Split the health endpoint

Status: accepted
Date: 2024-04-20

## Context

The specification defined a single unauthenticated `GET /v1/health` returning
the build version, the key encryption key state, the rotation status and the TLS
certificate expiry date.

Every one of those fields is useful to an attacker before it is useful to an
operator. The version says which published vulnerabilities to try. The KEK state
and rotation status say whether the deployment is mid-rotation, which is the
window in which two key versions are retained and the operator is distracted.
The certificate expiry date gives a date on which the deployment will be
degraded and changes will be made in a hurry. Handing that to an unauthenticated
caller is reconnaissance material, and it contradicts ADR 0002, which removed
anonymous access from the rest of the `/v1` surface.

The constraint is that something must stay unauthenticated. Container runtimes
and load balancers probe over plain HTTP with no credential, and an
authenticated probe means putting a key into every orchestrator that runs the
image.

## Decision

Split the endpoint by audience.

Keep `GET /v1/health` unauthenticated and reduce it to liveness: a fixed
response that says the process is up and serving, with no version, no key state
and no certificate data.

Move the detailed report behind authentication, where it reports the build
version, the storage engine and its reachability, the retained and current KEK
versions, rotation progress and TLS certificate expiry. Authorise it for an
administrative role, so reading it is an audited act by a named token.

## Consequences

Container health checks, Kubernetes probes and load balancer checks keep working
unchanged, with no credential distribution and no per-probe Argon2id cost.

Operators lose the one-command diagnostic. Checking whether a rotation finished
now needs a token in the request, which means monitoring systems that used to
scrape the URL anonymously have to be given credentials, and an operator
debugging at three in the morning has to find one.

The liveness endpoint answers on process health only. A server whose database
has become unreachable still returns a successful liveness response and stays in
the load balancer rotation, because distinguishing the two cases is exactly the
information we declined to publish. Deployments that want to drain such an
instance must probe the authenticated endpoint, or accept that the failure
surfaces as errors on real requests rather than on the probe.
