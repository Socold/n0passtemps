# Note: implementation choices, before writing anything

February 2023

If I build this, these are the decisions I do not want to relitigate halfway
through.

## Language

Go. Not because it is fashionable but because of what the deployment story
demands: one static binary, no runtime to install, cross compilation from one
machine, and a standard library that covers TLS and HTTP without a framework.

For an authentication product the dependency count is a security property, not
an aesthetic one. Every transitive dependency is a package that can be
compromised and that I will not read. Go makes a small dependency list practical
in a way most ecosystems do not.

The cost is that Go's crypto ergonomics are blunt and that generics arrived late
and awkwardly. Neither matters much here.

## Storage

SQLite and PostgreSQL, same schema, one abstraction.

SQLite because the target deployment is ten people in one office and installing
PostgreSQL to support ten users is friction that will lose adoption. A single
file that backs up with cp is a genuine feature.

PostgreSQL because anyone who outgrows that will ask, and retrofitting a second
backend after the fact means discovering every place the first one's behaviour
leaked into the application.

Two things this forces:

- a pure-Go SQLite driver, or the static binary promise dies to cgo
- both engines in continuous integration, or the second one rots

SQLite's concurrency model needs care. WAL allows many readers and exactly one
writer, so a single connection pool produces intermittent busy errors under
write contention. Two pools, one read and one single-connection write, turns
that into a queue in Go instead of an error in SQLite. Worth doing from the
start.

## No frontend framework

The administration interface is six screens. Six screens do not justify an npm
toolchain, a build step, and several hundred transitive dependencies inside an
authentication product. Server-rendered templates, embedded in the binary, and
whatever small amount of dependency-free JavaScript the interactions need.

I expect to be mildly embarrassed about this and to be right about it.

## Configuration

A file plus environment variables, validated once at startup, refusing to start
on anything that would be insecure.

The last part is the one worth being firm about. A misconfigured authentication
server that starts is worse than one that refuses to, because nobody notices the
first. Specifically: refuse plain HTTP on a non-loopback address, refuse a
forwarded-header trust setting without the networks it applies to, refuse the
encryption key stored in the data directory it protects, refuse a wildcard CORS
origin on credentialed endpoints.

And report every problem found, not just the first. Nothing is more tedious than
fixing a configuration one error per restart.

## What I am deliberately not building

- SAML, OIDC, or anything that makes this an identity provider. It verifies a
  factor and returns a signed result. That is the whole surface.
- Multi-tenancy in version one. But the tenant column goes in every table from
  the first migration, because adding it later means rewriting every query and
  every index.
- Session management. The calling application already has sessions. Returning a
  short-lived signed assertion it exchanges for its own session is a smaller and
  more honest contract.
