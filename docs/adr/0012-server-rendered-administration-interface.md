# 0012. Server-rendered administration interface instead of a single-page application

Status: accepted
Date: 2024-06-05

## Context

The specification called for a React single-page application for the
administration interface, while also promising delivery as a single static
binary and naming supply-chain compromise as a tracked risk. Those three
statements cannot all hold.

A React build brings Node.js, a package manager and a lock file whose transitive
closure runs to hundreds of packages, most of them build-time code that executes
on developer machines and in continuous integration with full filesystem access.
Inside an authentication product, that is the highest-value target in the
repository: a compromised build dependency reaches the artefact that operators
install to protect their logins, and it does so without touching any Go code a
reviewer would read. The npm ecosystem has produced this exact incident
repeatedly.

Set against that, the interface is six screens: subjects, credentials, audit
log, alerts, approvals and API keys. They are lists with filters, detail views,
and forms that post. Nothing in them needs client-side routing or a virtual DOM.

## Decision

Render the administration interface server-side with Go `html/template`.

Embed the templates and static assets in the binary with `embed.FS`, so the
single-artefact promise holds and there is no asset directory to deploy or
mismatch. Write the small amount of interactivity that remains, confirmation
dialogues and filter submission, as dependency-free JavaScript served from the
same binary. Keep Node.js out of the build and out of continuous integration
entirely, so `go build` produces the whole product.

## Consequences

The dependency surface of the interface is the Go standard library. A reviewer
can read every line that ships, and the build has no network step beyond the Go
module cache.

The interface behaves like a server-rendered application, because it is one.
Navigation means full page loads, a filter change is a round trip, and anything
resembling live updates or optimistic UI is out of reach without adding the
machinery this decision declined. Contributors who expected a component library
will find each screen hand-written, and the markup duplicated between templates
that a component system would have shared.

Rendering happens in the same process as authentication, so a template that
interpolates into an unexpected context turns an interface bug into a cross-site
scripting flaw in the security domain of the server. `html/template` escapes
contextually by default, which is the reason it was chosen over `text/template`,
but that guarantee is lost the moment a value is marked as trusted HTML.

Changing a stylesheet requires recompiling the binary.
