# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] - 2026-09-21

This release exists so the SDK packages reach their registries. 1.1.2 was cut
for the same reason and did not manage it: both publish jobs ran and both
failed, one on a registry setting that does not exist yet and one on a fault in
the workflow itself. Applications integrating over HTTP need nothing from it,
and the server, the container image and the binaries are unchanged from 1.1.1.

### Fixed

- **The npm publish could not have worked, whatever the registry was told.**
  The job publishes through trusted publishing and deliberately sets no token.
  npm documents that as needing CLI 11.5.1 or later, and Node 22 ships npm 10,
  which has no OIDC support at all and falls back to reading a token out of the
  environment. With none set it failed with a `404` on the PUT, which says
  nothing about the version being the cause. The job now installs a pinned npm
  of its own, for the reason every other tool here is pinned and more so: a
  publish is the one step that cannot be taken back.

### Changed

- **The pinned actions move forward**, and the four CodeQL ones move together.
  Dependabot tracks `init`, `autobuild`, `analyze` and `upload-sarif`
  separately and had opened pull requests for two of them, which would have run
  a version 4 init against a version 3 analyze. `actions/setup-node` reaches
  7.0.0, whose removal of the dummy `NODE_AUTH_TOKEN` helps trusted publishing
  rather than hindering it; `docker/login-action` reaches 4.6.0 and
  `pypa/gh-action-pypi-publish` 1.14.2. `fxamacker/cbor` reaches 2.9.4.

- **The coverage threshold the specification asks for is met**, at 80.0% of
  statements counting the PostgreSQL store and the TPM provider. The WebAuthn
  ceremony routes, which are the product, had no test that ran them over HTTP;
  the software authenticator that internal/webauthn used is now a package both
  it and internal/api share, so a ceremony they both accept was produced by the
  same keys and the same signatures. Beside that: the administrative credential
  store on both engines, the setup wizard over every combination of answers, the
  startup path and the three commands an operator is told to run, the model
  predicates that decide whether a credential still works, and the console's
  approval and acknowledgement actions.

## [1.1.2] - 2026-09-20

### Fixed

- **The SDK packages of 1.1.1 are published.** The release workflow refuses to
  publish a package whose version does not match the tag, and the three SDK
  version strings were left at 1.1.0 when 1.1.1 was cut, so npm and PyPI
  received nothing while the server release went out complete.

  The tag was not moved to repair it. A published tag that changes is the
  problem [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) raises about depending on
  one, and v1.1.1 already carried an attested set of archives and a container
  image. This release carries the same SDK changes under a version that matches.

  Applications integrating over HTTP need nothing from this release. The server,
  the container image and the binaries of 1.1.1 are unchanged.

## [1.1.1] - 2026-09-20

### Security

This release is the result of a security review of the whole service. Findings
that could be used against a running deployment were fixed first and are
described here in the terms an operator needs to judge their own exposure; the
reproduction steps are not, and each one that warrants it carries a published
advisory.

- **The reference sign-in backend gave a visitor the run of the API key it
  holds.** Every route in `kits/login` relayed `subject_ref` from the request
  body and checked its own session on none of them, so anybody who could reach
  the page could issue a subject's recovery codes, spend one, and be signed in
  as them. The five routes that add or replace a factor now require a session
  and take the subject from it. Only deployments that copied or ran the kit are
  affected; the server was never the weak part.

- **Dual approval could be satisfied by one administrator.** An `admin_full`
  token could queue an operation, rotate itself, approve with the successor and
  redeem with the predecessor, because an administrator was identified by the
  identifier of their token and a rotation mints a new one while the old stays
  valid. Migration 0006 adds `principal_id`, which a rotation carries forward,
  and the rule compares principals. No backfill is required.

- **An unauthenticated caller could grow the process without bound.** The
  request method was used as a Prometheus label unchanged, and `net/http`
  accepts any token as a method, so each invented one created a counter and a
  histogram that live as long as the process. Methods outside the standard set
  are folded into `other`.

- **One visitor could lock out every user of an application, or one user's
  passkey.** The `/v1` routes are called from an application's backend, so the
  only address the service saw belonged to the caller and every failure shared
  one bucket; and every failure was charged to one bucket per subject, so wrong
  TOTP codes locked that subject out of their authenticator as well. The
  per-address limit now follows the address the application declares in
  `X-End-User-IP`, the per-subject budget is per factor, and the WebAuthn budget
  is counted and reported without being enforced, because nothing in that
  ceremony is guessed and enforcing it only ever served the attacker.

- **An action could be taken without an audit entry.** Events are recorded after
  the change they describe has committed, and a failed append was logged while
  the request succeeded. Closing the connection at that moment, or putting a NUL
  in a free-text field, which PostgreSQL refuses in JSONB and SQLite accepts,
  was enough. The append no longer ends with the request, and a NUL is replaced
  before it is stored.

- **A sealed record could be moved between rows, subjects and tenants.** The
  envelope bound a ciphertext to nothing but its own header, so somebody who
  could write to the database without holding the keyring could put their own
  TOTP seed on a victim's row, or move another tenant's sealed reference into a
  subject of their own and read it back. Sealing now takes a binding context;
  see [ADR 0021](docs/adr/0021-bind-sealed-records-to-the-row-they-live-in.md).
  Existing records stay readable and are lifted by the next `kek/rewrap` pass,
  which is also the pass that proves none are left.

- **A console session outlived the token it was made with.** Revoking an
  administrator left their open session working for the rest of its lifetime,
  including deciding approval requests. The token is read on every console
  request.

- **`require_attestation` verified nothing without a metadata BLOB**, because
  the library returns early when it holds none and the AAGUID that
  `allowed_aaguids` matches on is declared by the client. The combination is
  refused at startup. With a BLOB loaded, a key could register and then never
  sign in again, which is also fixed.

- **The console's passkeys accepted any origin the public surface accepted**,
  which is the anti-phishing property a passkey exists for.
  `webauthn.admin_origins` names the console's own.

- **The audit chain could be truncated without the verifier noticing**: a
  checkpoint was attested by nothing, an erased entry's personal fields were
  covered by nothing, and one entry written by a machine with a backwards clock
  could take every recent entry with it at the next retention pass. All three
  are closed, and the external sink refuses redirects, follows `prev_hash`
  rather than the numbering, and sends a heartbeat so silence is visible.

- **An erasure left identifiers behind** in the alerts table and in the free
  text of erasure requests, and the SQLite database was left readable by any
  local account when the data directory already existed at 0755.

### Added

- **A coverage floor the build enforces**, `COVER_MIN` in the Makefile, checked
  by `make cover` and by a step of its own in CI.

  The specification makes coverage above 80% a gate before merge. What existed
  was an upload to a coverage service configured with `fail_ci_if_error: false`,
  and no `codecov.yml` setting a threshold, so nothing failed a build at any
  percentage. The reasoning behind that flag is right and is kept: a coverage
  service having an outage is not a reason to block a merge. It is the wrong
  place for the gate, not the wrong judgement, so the floor is now read out of
  the Makefile and enforced against the profile the job already produces, and
  the service stays advisory.

  The floor is set to 65, which is where the suite actually is, rather than to
  the 80 the specification asks for. A gate declared above the line and switched
  off is the failure mode this replaces. [docs/ROADMAP.md](docs/ROADMAP.md)
  carries the distance still to cover.

- **Two tests that hold the documentation to the code.** Both are the shape of
  `TestTheCatalogueIsTheVocabulary`, which already does this for the audit event
  names, and both were written because the drift they catch had happened.

  `TestTheSpecificationIsTheAPISurface` compares every route `router.go`
  registers against every operation `api/openapi.yaml` declares, in both
  directions. `GET /v1/metrics` shipped, was scraped, was documented in
  MONITORING.md and in EXTENSIONS.md, and was absent from the specification,
  which for a product whose support model is documentation is the one file an
  integrator cannot work around.

  `TestTheCatalogueIsTheAlertTypes` holds the alert table in MONITORING.md to
  what `internal/alerts` declares, names and severities both, and
  `TestTheReadmeCountsTheAlertTypes` holds the prose count in README.md to the
  same set. The count had read "ten" through three additions. It is worth
  saying that the test found a third occurrence that a careful reading of the
  file had missed, which is the entire argument for having it.

- **A keyring sealed to the machine's TPM**, `kek.provider = "tpm"`, with
  `n0passtemps-wizard kek seal` to convert an existing one.

  Attacker 5 of [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) holds a copy of the
  database and a copy of the keyring, and the model said of that position, in as
  many words, that nothing was mitigated. The likeliest route there is not a
  clever attack: it is one backup archive or one volume snapshot containing both.
  [ADR 0009](docs/adr/0009-refuse-a-kek-inside-the-data-directory.md) keeps them
  on separate volumes and cannot keep them out of the same tar file. Sealing
  does: the keyring on disk becomes AES-256-GCM ciphertext under a key that
  exists only inside one TPM, so a copied volume, a stolen backup, a cloned
  virtual disk or a decommissioned drive carries nothing usable.

  **It closes nothing against a live compromise of the host**, which asks the
  same TPM to unseal exactly as the service does. Protection at rest, not
  protection in use. The package comment says this before it says anything about
  what sealing achieves, because a control believed to do more than it does is
  worse than none.

  **It is opt-in, and the reason is the recovery hazard.** A TPM cannot be backed
  up. A dead board, a replaced motherboard or a cleared owner hierarchy makes the
  sealed file unreadable for ever, and with it every TOTP secret and every sealed
  subject reference. Sealing adds a layer in front of the offline plaintext copy;
  it does not replace it. The wizard says so at every seal, after the success
  message rather than before it. It also unseals what it has just produced and
  compares it against the input before writing anything, so a TPM that seals but
  will not unseal is found by the operator rather than at the next start.

  No PCR binding, deliberately: every firmware and kernel update moves those
  registers, so the service would stop starting for a reason nobody connects to
  the update, and it does nothing about an attacker who holds the disk and no
  TPM. The sealed object is bound to the owner hierarchy, which the suite proves
  by clearing it and asserting the keyring no longer opens.

  `github.com/google/go-tpm` becomes a direct dependency, having been an indirect
  one through the WebAuthn library. It is pure Go, so CGO stays off, the binary
  stays static and the six cross-compilation targets are unaffected. That is most
  of why the TPM was the right first backend and PKCS#11 was not.

  See [ADR 0019](docs/adr/0019-seal-the-keyring-to-a-tpm.md), which also records
  what this does not do for the assertion signing key, and why: Ed25519 and
  TPM 2.0 do not meet in the field.

- **[kits/login](kits/login/README.md)**, a reference sign-in and enrolment page
  with the backend that belongs behind it.

  A passkey offered first and with no field to fill, the named ceremony, TOTP and
  recovery codes behind a disclosure, enrolment behind another, and conditional
  mediation where the browser supports it. The backend holds the API key, calls
  the service through `sdk/go`, and turns a verified assertion into its own
  session.

  The shape is the point. `examples/node/register.html` puts the API key in the
  page on purpose, to demonstrate a ceremony with no backend, and says in
  capitals not to copy that; nothing showed the arrangement to copy. Here the
  browser talks to `/api` on its own origin, the backend talks to the service,
  and `kit_test.go` asserts that no served asset contains a credential.

  It is its own Go module with a `replace` pointing at the SDK in this
  repository, so it cannot become a dependency of the service and so it
  demonstrates the API the server actually serves rather than the last tagged
  one. `make test-kits` builds it, and CI runs that, because a separate module is
  one `go build ./...` does not reach and a reference integration that stopped
  compiling is worse than none.

  `public/webauthn.js` is a byte-for-byte copy of `sdk/node/src/browser.js`, kept
  identical by a test: `go:embed` cannot reach outside its package, and two
  versions of the base64url conversions would be one version that is wrong.

- **A Prometheus endpoint**, `GET /v1/metrics`, behind a new `metrics` scope.
  Three series: `n0passtemps_build_info`, `n0passtemps_http_requests_total` by
  route, method and status, and a `n0passtemps_http_request_duration_seconds`
  histogram by route and method.

  It is authenticated for the reason
  [ADR 0008](docs/adr/0008-split-the-health-endpoint.md) split the health
  endpoint: request rates by route, the shape of the 401 and 429 curves and the
  version of the running binary are reconnaissance before they are diagnostics.
  Prometheus reads a bearer token from a file, so a scrape configuration costs
  two lines; [docs/MONITORING.md](docs/MONITORING.md) has it.

  The scope is its own rather than part of `health`, because a scrape credential
  lives in a configuration file, is shared with whoever runs monitoring and is
  rarely rotated, and should therefore do one job.

  The exposition format is written here rather than taken from
  `prometheus/client_golang`, which is the argument `internal/assertion` makes
  about JWT libraries: a format this small is cheaper to write than to depend on,
  and it avoids a default registry that collects Go runtime metrics whether or
  not anyone asked. What is given up is listed in the package comment.

  The `route` label is the matched pattern and never the path. A Prometheus
  series lives as long as the process, so a label taken from a request is
  unbounded memory with a caller holding the pen, and on the routes that name a
  subject it would be a list of users.

  A deployment with no registry answers 503 with a problem document rather than
  an empty body, because an empty document scrapes clean and reads as "nothing
  has happened".

- **[docs/EXTENSIONS.md](docs/EXTENSIONS.md)**, the standing answer to "could it
  also do X": what is core and stays core, what is an adapter, what would be a
  different product, and a list of candidates in the order their value divided by
  their cost puts them. Nothing in it is built.

  The position is that the engine stays narrow and that optional modules around
  it are open. What decides which is which is not the category but whether the
  thing is on the trust path: key providers and the audit sink are, whatever
  their category, and SDKs, user interfaces and packaging are not. The extension
  boundary is the HTTP API rather than a Go package, because `internal/` stays as
  it is and an adapter that has to speak HTTP can be written in any language.

  See [ADR 0020](docs/adr/0020-core-and-adapters.md), which is proposed rather
  than accepted.

- **`make lint-cleared` and `make test-tpm`.** The first runs every linter except
  the style budget categories that still have findings, so a cleared category
  stays cleared; CI runs it on every push. The second starts a software TPM and
  runs the sealing suite against it, because those tests skip when there is no
  TPM and a skipping test that reports success is worse than one that is absent.

- **Rotating the assertion signing key without an outage.**
  `assertion.retired_public_key_paths` lists Ed25519 public keys the service
  publishes at `/v1/.well-known/jwks.json` and never signs with, and
  `n0passtemps-wizard assertion-key rotate` performs the swap.

  The threat model has named one key as a single point of forgery since 1.0.0,
  and named rotation as the mitigation. The service could not perform one. It
  published exactly one key, so the outgoing key stopped verifying at the instant
  it stopped signing: every assertion issued in the last minute was refused, and
  so was every assertion reaching an application whose cached copy of the key set
  predated the restart. An operator who suspected a theft had to choose between
  leaving the forgery window open and causing an outage, and a mitigation that
  costs an outage is one that gets postponed. The comment on `KeyID` has claimed
  since 1.0.0 that two keys could be published side by side during a rotation;
  nothing could publish them.

  The `kid` header selects between the keys, so no verifier changes and none of
  the three SDKs does either. The window has to close, because a retired key goes
  on verifying whatever its private half signs, which is the thing the rotation
  exists to stop. Closing it is the operator's act rather than a timer: a service
  that withdrew a key on a schedule would refuse assertions during a clock
  problem. What pushes against forgetting is a warning at every start naming the
  retired key identifiers, since the configuration is the only record that a
  window is open. The validator refuses an empty entry, a repeated path and the
  signing key's own path, and the loader refuses a private key given where a
  public one was expected, because the file is published to every caller.

  `assertion-key rotate` loads the outgoing key before it writes anything, keeps
  both halves beside the new key, replaces the live key last and prints the
  configuration line with the arithmetic for the window. Everything that can fail
  happens before the live key is touched, so a refused rotation leaves the
  deployment as it was. The published half is derived from the key that was
  loaded rather than copied from disk, so what is published is provably the key
  that was signing.

  See [ADR 0018](docs/adr/0018-reducing-the-blast-radius-of-a-central-key.md),
  which also records what this deliberately does not do: a second signing key in
  the same trust domain is one key, dual approval constrains the API and not the
  filesystem, and the version worth building is a signer the process calls rather
  than a file it opens.

- **[docs/SIEM.md](docs/SIEM.md)**, the integration document: the two streams and
  what each is for, the field mapping to ECS 8 and OCSF 1, the closed audit event
  vocabulary, the receiver contract for `audit.sink`, and a starting set of
  rules.

  It also says why there is no syslog client here and gives the journald and
  rsyslog configuration that does the job instead, including the message size
  limit that silently truncates a long line into JSON that parses as nothing.

  The vocabulary is published as a closed set, so it is checked against
  `internal/audit/events.go` by a test rather than by hand, in both directions.

- **Registry publication for the Node and Python SDKs**, as `sdk-npm` and
  `sdk-pypi` in `release.yml`, on the same `v*` tag as everything else and after
  the GitHub release exists.

  Both publish through trusted publishing, so no API token is stored in this
  repository or anywhere else: the registry verifies an OIDC claim naming this
  repository, this workflow file and the deployment environment. The npm job
  also passes `--provenance`, which gives the tarball the signed statement the
  container image already had. Both refuse to publish a version the tag does not
  name, which is the one mistake neither registry lets anybody take back.

  The jobs are skipped until the deployment environments exist, so a release
  does not fail on a registry nobody has set up yet.
  [docs/ROADMAP.md](docs/ROADMAP.md) lists the three settings that remain with
  the maintainer.

- **A test suite for the administrative credential store**, on both engines.

  `internal/store/sqlite/admincred.go` had fourteen functions and no test. It is
  the table [ADR 0017](docs/adr/0017-administrative-sign-in-with-webauthn.md)
  added to keep an operator's authenticator apart from a subject's, and the ADR
  says in as many words that getting that separation wrong in one direction
  turns every enrolled user into an administrator. The PostgreSQL half is a
  deliberate near-copy rather than a shared table of cases, because the
  statements differ between the engines and a behaviour that matches should
  match because both were written to, not because one file ran twice.

- **A test suite for the setup wizard**, covering every combination of answers.

  The property it checks is the one the tool promises and an operator cannot
  check for themselves: that the generated `config.toml` loads and validates.

### Changed

- **`server.allow_plaintext` is no longer set by the container image.** A
  `docker run -p 8080:8080` that relied on it now stops at the validator. The
  compose files set it next to the loopback publication that justifies it.

- **Configurations that were accepted are now refused at startup**: a
  `trusted_proxy_cidrs` or `ip_allow_list` prefix wide enough to admit
  everything, an administrative surface reachable beyond loopback with no allow
  list whether or not the console is enabled, a zero read, write or idle
  timeout, a `max_body_bytes` above 16 MiB, an unknown operation in
  `dual_approval_operations`, risk weights that are all zero, and `LITE_MODE`
  contradicting its prefixed form. Under lite mode, settings named by the
  environment are now honoured rather than silently overridden.

- **A tag no longer publishes on its own.** The release workflow runs the gate
  and an integration pass first, the container scans block on fixable findings,
  and the archives carry a provenance attestation and an SBOM.

- **Kubernetes ingress is closed until a namespace is labelled.** The policy
  named every namespace; the example allow list is now a documentation range
  that has to be replaced.


- **`(*Config).Validate` is one method per section.** It was a single function
  over every setting in the file, at 134 branches the largest thing in the
  repository by a wide margin, and it was already organised into sections by
  comment: Tenant, Server, Database, KEK, and so on down to Features. Each of
  those is now a method returning its own problems, in the shape
  `validateAuditSink` already had, and `Validate` is the list of them.

  Nothing about what is checked changed, and the check that says so is the
  useful part: the file carries 102 message literals and carries the same 102
  after the move. `validateAdmin` is the one section that writes as well as
  reads, forcing the session cookie Secure behind TLS, and its comment now says
  so rather than leaving it to be discovered.

- **The style budget is closed and `make lint` runs whole in CI.** All six
  categories report nothing, `UNCLEARED_LINTERS` is gone from the Makefile, and
  `lint-cleared` survives only as an alias so older scripts keep working.

  Five were cleared by fixing findings. `gocyclo` was closed by moving its
  threshold from 15 to 35, which is the one place the budget lost its argument
  rather than winning it, so it is written down as such. 15 was set on the
  reasoning that anything above it is a function doing two jobs; that was true
  of `(*Config).Validate` at 134 and false of the other thirteen, which are a
  SQL statement splitter tracking quote state, the startup path, a JWS verifier,
  an interactive setup and four handlers. 35 is one above the largest function
  in the tree, so it holds the line where it is and would still have caught
  Validate by a factor of four.

  Two `gocritic` checks are refused by name in `.golangci.yml` rather than
  cleared, with the reasoning beside them, as `sloppyReassign` already is.
  `hugeParam` and `rangeValCopy` both ask to replace a copy with an alias, and
  every site they fire on is a descriptor the callee must not change.
  `Recorder.Success`, `.Failure`, `.Denied` and `.Errored` each set `ev.Outcome`
  on their own copy of an `audit.Event` before passing it on, so taking a
  pointer there would write the outcome back into the caller's event: a style
  fix that silently changes what gets audited.

  Clearing `revive` was not only doc comments. `openStore` took a
  `context.Context` that neither engine's `Open` accepts and
  `clientThrottleDims` took the `*Caller` left behind when the per-key dimension
  moved to `MeterAPIKey`; both parameters are removed rather than renamed to
  `_`. Two tests whose parameter is unused because the race detector and a nil
  dereference are what fail them now say so, so that the next reader does not
  add an assertion that tests nothing.

- **`api.APIError` is `api.Error`.** The package is imported as `api`, and
  `url.Error` and `net.Error` are the shape the standard library uses for this.
  Internal to `internal/api`, so nothing outside the module sees it.

### Fixed

- **The setup wizard refused to write anything for any listener that was not
  loopback**, and blamed itself while doing it.

  Answering `0.0.0.0:8080` to the listen address question -- the obvious answer
  for a container, and the address the compose file the wizard itself generates
  publishes behind -- ended the run on:

  > the generated configuration does not validate, which is a bug in this tool
  > rather than in your answers

  and left the directory empty. It was right that it was a bug in the tool.
  `renderConfig` wrote the TLS paths, the proxy settings and the console's allow
  list as commented examples, so the file it validated before writing was one
  the service refuses, and the two questions whose answers would have made it
  valid were never asked. In a product whose support model is documentation and
  a GitHub issue tracker, an operator met a tool telling them it was broken and
  had nothing to go on.

  The listen address is now probed like the relying party and the origin already
  were, so a malformed one is re-asked. A listener that needs TLS accounted for
  asks one further question, with the three arrangements the validator itself
  names: this process terminates TLS, a reverse proxy in front does, or
  something outside constrains who can reach the port, which is what the
  generated compose file arranges by publishing to `127.0.0.1`. Enabling the
  console on such a listener asks for its allow list. The answers are written as
  settings rather than as comments.

  A test now renders every combination of answers and loads the result, which is
  what the interactive path cannot do.

- **`make ci` could not pass on any machine.** `test-race` inherited the
  `export CGO_ENABLED := 0` the Makefile sets for everything, and the race
  detector is built on cgo, so the target failed with "-race requires cgo"
  wherever it was run. It went unnoticed because the CI workflow does not call
  it: that job runs the same command inline with `CGO_ENABLED` set to 1 in the
  step. The gate CONTRIBUTING.md asks a contributor to run before opening a pull
  request was the only one that was broken, which is the worst of the three
  places it could have been.

- **`make secrets` could not install the scanner it names.** gitleaks moved to
  the `gitleaks` organisation and its module still declares the path
  `github.com/zricethezav/gitleaks/v8`, so `go install github.com/gitleaks/...`
  ends in a version constraints conflict rather than a binary. CI calls the
  action instead, so again only the local gate was affected.

- **`make sec` produced a goroutine dump rather than a scan.** The pinned
  `govulncheck` v1.1.4 vendors `golang.org/x/tools` v0.29.0, whose SSA builder
  panics with `unexpected expr: *ast.KeyValueExpr` on the toolchain this project
  builds with. Raised to v1.8.0, which reports no vulnerability in any code this
  module calls. This is the same failure as the golangci-lint pin recorded in
  [docs/ROADMAP.md](docs/ROADMAP.md): a pinned analyser eventually stops
  understanding the language it is pointed at, and a pin is a thing to revisit
  rather than a thing to set.

- **`GET /v1/metrics` was missing from `api/openapi.yaml`.** The scope was
  described in the document's prose and the route was not in `paths`, so a
  client generated from the specification had no metrics endpoint. Added with
  the exposition's content type and the `503` a deployment with no registry
  answers. A test now checks the whole surface both ways.

- **README.md said there were ten alert types.** There are thirteen:
  `risk.high`, `enrolment_ticket.factor_override` and `audit.sink_failing` were
  added without the three prose statements that count them being revisited.
  MONITORING.md was correct throughout.

- **The `route` log field carried the path, not the matched route.** On the
  ceremony routes the path is the subject reference, and the documentation asks
  for an opaque identifier while applications supply email addresses. So
  `logging.redact_subject_refs` was on, worked, replaced `subject_ref` with a
  digest, and the address travelled in the field immediately after it.

  `routePattern` was written to prevent exactly this and says so in its comment,
  and [docs/MONITORING.md](docs/MONITORING.md) describes the field as the matched
  pattern. Both were true of the function and neither of the caller: `RequestLog`
  wraps the multiplexer from outside, the multiplexer fills in `Request.Pattern`
  as it dispatches, and the read happened before the dispatch, so the fallback to
  the path ran on every request.

  The summary line now reads the pattern after the handler returns, and a
  `RouteLabel` middleware mounted on every route adds the field to the
  request-scoped logger so that handler, authentication and authorisation lines
  carry it too.

- **Two audit event types were not part of the vocabulary.**
  `admin.subjects_listed` and `admin.subject_ref_revealed` existed only as string
  literals at four call sites, one of them already quoted in
  [docs/MONITORING.md](docs/MONITORING.md) as a query worth saving. The package
  comment says the names are constants because they are written into a persisted,
  hash-covered record and renaming one silently changes the meaning of history; a
  typo at one of four literals would have created a second event family that no
  saved query selects. They are constants now.

- **The `govet` (`shadow`) style budget is at zero.** 179 sites, not the 175
  recorded, for the same measurement reason as `lll` below. 152 were an `if`
  statement's init in the same function as the variable they shadowed, with
  nothing reading that variable before it was written again, and became `=`. 8
  were in closures over an enclosing function's variable, where writing to the
  capture is a different program, and were renamed. 18 declared another variable
  as well and were restructured, usually by assigning straight into the field the
  temporary was copied to. Which site was which was decided by a program over the
  syntax tree rather than by eye; [docs/ROADMAP.md](docs/ROADMAP.md) records the
  division and the bug in the first version of that program.

  **`gocritic`'s `sloppyReassign` is disabled as a consequence**, with the
  reasoning in `.golangci.yml`. It and `shadow` contradict each other on exactly
  these lines and cannot both be at nought: clearing `shadow` moved 51 findings
  into `gocritic`. `shadow` stays because it catches a bug and the other catches
  a looseness.

- **The `lll` style budget is at zero, and it was never 119.** 127 lines were
  past 120 columns; the missing eight appeared as soon as the other linters were
  switched off. A count taken from a run that enables everything is a lower
  bound, and [docs/ROADMAP.md](docs/ROADMAP.md) now says so. Almost all of them
  are function declarations wrapped at a parameter; nothing changes behaviour.

- **`make ci` could not pass.** It ran the full `make lint`, which cannot pass
  while the style budget is not empty, so the gate `CONTRIBUTING.md` asks
  contributors to pass locally was unpassable. It runs `make lint-cleared` now.

- **The release workflow was a file GitHub refuses.** The rewrite that turned the
  release into draft, fill, verify, publish left the previous action's `uses` and
  `with` block attached to the step that replaced it. A step cannot both run a
  script and use an action, so every push produced a run that failed in zero
  seconds with no log. It was never seen because the file had not been pushed. No
  release was ever cut from it.

## [1.1.0] - 2026-09-18

### Added

- **API key rotation**, `POST /admin/v1/api-keys/{key_id}/rotate`, behind the
  new permission `api_key.rotate`, which `admin_full` holds. It mints a
  successor with the same name, scopes and tenant, and gives the predecessor an
  expiry of now plus `grace`, in one store transaction. Replacing a key used to
  mean an outage, if the old one was revoked first, or an overlap nobody
  remembered to close, if it was revoked second; the overlap is now explicit and
  closes by itself. A predecessor that already expires sooner keeps its earlier
  expiry, so rotating a credential never extends its life. The successor does
  not inherit the predecessor's expiry, and the response reports `no_expiry` as
  minting does. A revoked or expired key is refused with `409`.
- **Self-service rotation of an administrative token**,
  `POST /admin/v1/admin-tokens/self/rotate`, behind the new permission
  `admin_token.rotate_self`, which all three roles hold. The token rotated is
  the one that authenticated the request, and the successor keeps its name and
  role. It changes no authority, so it is not held for approval, and it is the
  one write `admin_auditor` may perform, because it touches nothing but the
  caller's own credential. The successor cannot outlive the token it replaces:
  an expiry is inherited, and `expires_in_days` may only bring it forward.
  There is deliberately no route for rotating another administrator's token,
  since the response would hand the caller that person's successor credential.
  The permission count goes from twenty-five to twenty-seven.
- **`features.rotation_grace`**, default `24h`, environment variable
  `N0PASSTEMPS_FEATURES_ROTATION_GRACE`: the overlap used when a rotation
  request names none. `0s` stops the predecessor at once. The maximum is `168h`,
  enforced in configuration validation and again per request, where a longer
  `grace` is refused with `400`.
- **Audit events `api_key.rotated` and `admin_token.rotated`**. The detail
  carries the predecessor and successor identifiers, the grace and the instant
  the predecessor stops. It never carries the token.
- **`RotateAPIKey` and `RotateAdminToken` on the store interface**, implemented
  for SQLite and PostgreSQL as one transaction each: a conditional update of the
  predecessor, then the insert of the successor. A missing, foreign or revoked
  predecessor yields `ErrNotFound` and nothing is inserted.
- **Enrolment tickets**, the answer to the magic-link question in
  [docs/ROADMAP.md](docs/ROADMAP.md) section 2.2. A ticket is a single-use,
  short-lived secret that permits exactly one thing: starting and completing one
  WebAuthn registration for the subject it names. It never produces a signed
  assertion, so a stolen ticket lets an attacker enrol an authenticator of their
  own, which is audited and revocable, rather than hand them a session. The
  service does not deliver tickets and has no SMTP dependency: it returns the
  ticket once, in the issuing response, and delivery is the integrating
  application's responsibility, which is where the knowledge of the user and of
  the channel actually lives.

  The secret uses the recovery-code construction unchanged, from
  `internal/crypto/recovery`: twenty characters of Crockford base32 split into a
  six-character indexed selector and a fourteen-character verifier stored as an
  Argon2id PHC string. Four routes:

  - `POST /v1/subjects/{subject_ref}/enrolment-ticket`, scope `tickets`, for
    onboarding a user who holds no authenticator yet.
  - `POST /admin/v1/subjects/{subject_id}/enrolment-ticket`, permission
    `enrolment_ticket.issue`, for a user who has lost every authenticator they
    had.
  - `POST /v1/enrolment/register` and `POST /v1/enrolment/register/complete`,
    scope `tickets`, the only two routes that accept a ticket.

  The ticket travels in the request body on both redemption routes, never in a
  path. A path reaches the access log of every reverse proxy, load balancer and
  monitoring agent in front of the service, and a `Referer` header and browser
  history besides; a body does not. The routes are therefore named for what they
  do rather than for a parameter they do not carry, which is the same choice
  already made for `POST /v1/recovery/{subject_ref}/consume`.

  Starting the ceremony does not spend the ticket, because consumption records
  which credential the ticket produced and that does not exist until the
  ceremony completes; a browser that refuses the prompt would otherwise send the
  user back to the helpdesk. Single use is a compare-and-swap in the store,
  conditional on the ticket being unconsumed, unrevoked and unexpired, with
  exactly one winner under concurrency. If the swap loses after the credential
  was created, that credential is revoked and the request refused.

  A wrong ticket, an expired one, a consumed one, a revoked one and one whose
  subject is locked or pending erasure all produce the same `401` with no
  detail. The reason is audited as `enrolment_ticket.rejected`. Redemption is
  rate limited per source address and per ticket selector, so guessing one
  ticket costs the per-subject failure budget and spraying across many costs the
  per-address budget.
- **`enrolment_ticket.issue`**, a new permission held by `admin_operator` and
  `admin_full`. It guards issuing and, deliberately, withdrawing: whoever may
  put a ticket into circulation must be able to take it out, and an operator who
  had to find a full administrator to withdraw their own mis-delivery would in
  practice wait for the expiry instead. `POST
  /admin/v1/enrolment-tickets/{ticket_id}/revoke` is that route. The permission
  count goes from twenty-seven to twenty-eight, and `admin_operator` from
  seventeen to eighteen.
- **`tickets` scope** on the public surface, covering the issuing route and both
  redemption routes. It is separate from `webauthn` even though redemption runs
  a registration ceremony: a key holding `webauthn` can enrol an authenticator
  only for a user who is present, while a key holding `tickets` can mint a
  secret that enrols one later through a channel the key does not control.
- **`[tickets]` configuration**, two keys. `tickets.ttl`, default `1h`,
  environment variable `N0PASSTEMPS_TICKETS_TTL`, bounds how long a ticket may
  be redeemed for; the maximum is 24h, enforced in validation, because the
  lifetime is the whole window in which an intercepted ticket can be used and
  anything longer is a standing credential rather than a hand-off.
  `tickets.require_existing_factor_default`, default `true`, environment
  variable `N0PASSTEMPS_TICKETS_REQUIRE_EXISTING_FACTOR_DEFAULT`, refuses to
  issue a ticket with `409` for a subject who already holds an active
  authenticator or a confirmed TOTP secret. A request may override it with
  `require_existing_factor: false`, which is the caller stating that the
  existing factor is unusable. Both the refusal and the override are audited,
  and the override raises an alert: a ticket is a way in for someone with no
  factor, and issued silently for an account that has factors it is an
  account-takeover primitive for whoever controls delivery. An unconfirmed TOTP
  secret does not count as a factor, because the user has not proved they can
  produce codes from it.
- **Audit events `enrolment_ticket.issued`, `.redeemed`, `.rejected` and
  `.revoked`**. The issuance detail records the expiry, the reason, what factors
  the subject held and whether the guard was overridden; the redemption detail
  records which credential the ticket produced. The registration a ticket drives
  is also audited in the ordinary `webauthn.registration.*` family, with `via:
  enrolment_ticket` and the ticket identifier in the detail, so an operator
  reviewing enrolments sees it without knowing to look for tickets.
- **Alert `enrolment_ticket.factor_override`**, warning severity, raised on
  every ticket issued over an existing factor. It is a warning rather than
  critical because critical is reserved for a control that has failed on its
  own, and here a control was overridden deliberately by an authorised caller
  with a legitimate use; it is not informational because the override is exactly
  the step an attacker who controls delivery needs. The alert count goes from
  ten to twelve, with the risk signal above.
- **`TicketStore` on the store interface**, implemented for SQLite and
  PostgreSQL. `ReplaceEnrolmentTicket` revokes any live ticket for the subject
  and inserts the new one in one transaction, so tickets never accumulate; a
  partial unique index over unconsumed, unrevoked rows per subject is the
  backstop. `ConsumeEnrolmentTicket` records the credential the redemption
  produced. `DeleteExpiredEnrolmentTickets` is the janitor sweep, cross-tenant
  like the others, and is counted in its result.
- **Migration `0003_enrolment_tickets`** for both engines.
- **A new attacker in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)**: whoever
  controls ticket delivery. Not delivering tickets transfers that risk whole to
  the integrating application, which is the right place for it and is not the
  same as making it disappear, so the section says what the transfer costs.
- **Risk signals**, reported on every completed authentication and never
  enforced. A new `internal/risk` package assesses a ceremony against a table of
  nine reasons, each with a weight, and two score thresholds, and reports one of
  `low`, `elevated` or `high`. The service never refuses an authentication on
  risk alone: it knows how the subject proved themselves and the integrating
  application knows what they are about to do, so the application takes the
  step-up decision. The nine reasons are `signature_counter_stalled`,
  `authenticator_binding_changed`, `user_verification_absent`,
  `recovery_code_used`, `credential_dormant`, `credential_new`,
  `recent_failures_subject`, `recent_failures_network` and `totp_only`. Every
  one is derived from a signal the service already collected while completing
  the ceremony, so nothing new is collected about anyone. There is no model, no
  training data and no third-party feed, which is why the feature is called
  risk signals and not adaptive authentication. `risk.Assess` is a pure
  function of its inputs, so an assessment can be recomputed from the audit
  entry that recorded it. See [docs/RISK.md](docs/RISK.md).
- **An optional `risk` claim on the assertion**, `{"level", "reasons",
  "score"}`, attached through the new `assertion.WithRisk` issue option. It is
  omitted from the token entirely when `risk.enabled` is false, rather than
  present and empty, so a verifier written against a deployment that does not
  report risk is unaffected by one that does. The verifier does not require it,
  and will not: an optional claim a verifier insists on is not optional.
- **`risk_level` and `risk_reasons` on the three completion responses**, beside
  `factors`. They are unsigned, so a caller must take its step-up decision from
  the verified assertion and not from the response body; the handler comments,
  the OpenAPI description and [docs/RISK.md](docs/RISK.md) all say so.
- **A `risk` key on the `assertion.completed`, `totp.verified` and
  `recovery.consumed` audit details**, carrying the same level, reasons and
  score as the claim, from the same value.
- **Alert type `risk.high`** at warning severity, raised when an assessment
  comes out high. Nothing has failed when it fires, since the ceremony verified
  and every control held, so it is not critical; it is more specific than a
  failure burst and concerns an authentication that succeeded, so it is not
  informational either. It collapses by fingerprint onto one row per subject.
  `elevated` raises nothing, because an ordinary recovery-code redemption
  reaches it and alerting on that would bury the rest of the stream. The alert
  count goes from eleven to twelve.
- **A `[risk]` configuration section**: `enabled` (default true), `elevated_at`
  (20) and `high_at` (40), `dormant_after` (`2160h`), `new_credential_within`
  (`1h`), and a `[risk.weights]` table of per-reason overrides. The scalars are
  settable as `N0PASSTEMPS_RISK_*`; the weight table is file-only, because the
  weights are the policy and belong in the reviewed file rather than in one
  deployment's environment. Validation refuses an unknown reason key, a
  negative weight, a threshold below one and `elevated_at` at or above
  `high_at`, and it does so whether or not reporting is enabled, so that
  turning it on later cannot turn a file that loaded yesterday into one that
  refuses to.
- **`throttle.Result.Counters`**, the per-dimension attempt and failure counts
  the limiter already read. Risk reporting takes the per-subject and
  per-network failure counts from there, so the two failure reasons cost no
  extra query on the authentication path.

- **The `risk` claim in all three SDKs.** `Claims.Risk` in Go (with
  `HasRiskReason` and the `RiskLow`/`RiskElevated`/`RiskHigh` constants),
  `Claims.risk` in Python (a frozen `Risk` dataclass) and `claims.risk` in
  Node. An absent claim reads as "the deployment does not report risk", which
  is deliberately not the same value as a low assessment: treating the two
  alike would turn every step-up off the day an operator disabled the feature,
  and each SDK says so where a caller will read it. A claim that is present
  but malformed invalidates the assertion in all three, because accepting the
  token and dropping the claim would report "risk was not reported" when it
  was, failing open on the one signal the application asked for. Unknown
  members and unrecognised reasons are carried through, so a deployment newer
  than the library stays verifiable.

- **Usernameless sign-in**, `POST /v1/webauthn/assert/discoverable` and
  `.../complete`, behind the existing `webauthn` scope. There is no
  `subject_ref` in the path: the options carry no allow list, so the browser
  offers whichever passkeys the authenticator holds for this relying party, and
  the completion response reports which subject the credential belonged to.
  This is what users now expect from a passkey, and the ceremony layer was most
  of the way there already.

  Two decisions carry its security. **User verification is required**, whatever
  `webauthn.user_verification` is configured to: a named ceremony is scoped to a
  subject the caller chose, but this one is scoped to nothing, so a
  possession-only response would let a found or stolen passkey sign in as its
  owner with nothing else needed, and the caller cannot compensate because it
  did not choose the subject either. A deployment whose authenticators cannot
  verify a user therefore cannot offer the route, which is the correct outcome.
  **The subject is resolved from the credential identifier and never from the
  user handle**: both arrive in the same client-supplied response, but the
  credential identifier selects a stored public key that then has to verify the
  signature, whereas the handle is only a value in a JSON document. The handle
  is still compared against the one the service derived for the resolved
  subject, so a response assembled from two ceremonies is refused.

  A failed usernameless ceremony is never recorded against a subject, because
  it has not established which subject it was for. Recording it against
  whichever subject the response named would be a lockout primitive against any
  account an attacker could name a credential for. It counts against the
  calling key and the source network only.

  No migration. The challenge row's subject column is already nullable, and the
  empty value is what keeps the two flows apart: the named completion requires
  the challenge to name its subject, the usernameless completion requires it to
  name nobody, so neither ceremony can be finished through the other's route.
  That matters because the two differ in exactly the pair of checks an attacker
  would want to choose between, the allow list and the verification
  requirement.

  All three SDKs gained the pair of calls, and
  [docs/WEBAUTHN.md](docs/WEBAUTHN.md) has the reasoning under "Usernameless
  sign-in".

- **A multi-replica janitor lock**, from [docs/ROADMAP.md](docs/ROADMAP.md)
  section 2.4. The janitor runs in process, so a deployment of several replicas
  used to perform every sweep once per replica. Each sweep is an idempotent
  conditional delete, so that was waste rather than damage, and the lock removes
  the waste without taking on any correctness duty in exchange: a pass that
  loses the lock is skipped, not failed, and a deployment whose lock never
  worked would be as correct as one whose lock does and merely busier.

  `TryAcquireJanitorLock` joins the store interface, with the new sentinel
  `ErrLockHeld` for the attempt that loses. The two engines implement it
  differently, because they offer different primitives. On PostgreSQL it is a
  session-level advisory lock, `pg_try_advisory_lock` on one connection held for
  the length of the pass, which the server drops the moment the holder's
  connection dies: a replica killed with SIGKILL mid-sweep frees it as fast as
  the kernel closes its sockets, and no expiry has to run out first. On SQLite
  it is a lease row with an expiry, in the new `janitor_leases` table, taken for
  exactly as long as one sweep may run, which is two minutes; a holder killed
  mid-sweep therefore costs nothing at the default five-minute interval. It is a
  real lease there and not a no-op: one process and one file is the only
  supported arrangement, but nothing prevents two processes from opening one
  file over a network mount, and the engine's own write lock does nothing about
  two processes that have each taken their turn at it and moved on to the sweep.
  The PostgreSQL migration declares `janitor_leases` and leaves it empty, so
  that both engines still declare the same schema.

  What an operator reads: the first pass a replica skips logs
  `janitor pass skipped: another replica holds the sweep lock` at info, every
  pass after it logs the same message at debug, and taking the lock again logs
  `janitor sweep lock taken after a skipped pass` at info. A replica doing
  nothing because a sibling holds the lock is therefore distinguishable from a
  broken one without a line every interval for the life of the deployment. There
  is no new alert type, deliberately: a skipped pass is the correct steady state
  of every replica but one. A lock that cannot be taken at all, as opposed to
  one held elsewhere, is a database that will not answer and is logged at error.

  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) has what is supported per engine
  under "Running more than one replica", and
  [docs/MONITORING.md](docs/MONITORING.md) has the log lines.

- **A `verify` subcommand on the wizard**, from
  [docs/ROADMAP.md](docs/ROADMAP.md) section 2.4, which answers whether a
  database, a keyring and a pepper still open together. The three are backed up
  separately on purpose, and nothing until now confirmed that a given trio
  fits; the moment an operator found out was during a restore. It unseals real
  records
  under the keyring and recomputes a subject's lookup value under the pepper,
  so it reports whether the keyring opens what this database holds rather than
  whether three files parse. AES-GCM rejects a wrong key instead of returning
  plausible plaintext, which is what makes one decryption sufficient. Sampling
  is one record per key version per sealed column; `-all` sweeps every record.
  The key version is read out of each record's header, which needs no key, so a
  keyring taken before a rotation produces a diagnosis and not a shrug: `the
  keyring has no key version 2, which 143 records in totp_secrets.secret_sealed
  are sealed under`. Messages are deliberately precise here, unlike the API
  surface: this runs on the operator's own host against their own backup, for
  somebody who already holds all three secrets. Counts, versions, identifiers
  and verdicts are printed; key material, the pepper, tokens, recovery codes
  and subject references are not.

  The exit status is the interface, because the command belongs in a cron job.
  `0` the trio opens, `1` it does not, `2` verification could not run and no
  verdict was reached. A missing file is in the second class, because it cannot
  be told apart from a path typed wrongly; a file that is there and wrong is in
  the first. A truncated database, a keyring of the wrong mode, a pepper of the
  wrong length and a sealed column damaged in place each produce their own
  verdict rather than a panic.

  The database is opened read-only, and structurally so. SQLite's `mode=ro`
  gives the file an `O_RDONLY` handle and refuses every write against it,
  including a migration, and the command does not use the store package at all,
  so the migration runner is not reachable from it. `immutable=1` was rejected
  deliberately: it makes SQLite ignore the write-ahead log, so a database copied
  together with its log would verify against a stale view of itself.

  SQLite only, with the reason in the help text. A PostgreSQL backup is a
  `pg_dump` archive, which cannot be read without restoring it into a server
  first, and once restored the promise that verification cannot write would rest
  on the role's privileges rather than on how a file was opened.
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) gives the restore-and-check sequence
  for those deployments instead.

  `subject.DecodePepper` and `subject.RefHMAC` are exported so a tool outside
  the server can read a pepper and recompute a lookup value without building a
  `subject.Service`, which needs a store and a sealer. The HMAC construction
  and its domain separator still exist once: a second copy would drift, and a
  drifted separator makes every existing subject unfindable.

  [docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md) has the routine and the cron entry
  under "Verifying a backup", [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) has it
  beside each form's backup procedure, and
  [docs/TROUBLESHOOT.md](docs/TROUBLESHOOT.md) has every verdict and what to do
  about it.

- **An external audit sink**, from [docs/ROADMAP.md](docs/ROADMAP.md) section
  2.4, off unless `audit.sink.endpoint` is set. The hash chain makes tampering
  detectable by anybody who kept an earlier head; it does not survive the
  operator of the server, who owns the database file and can therefore edit a
  row and recompute every hash from the edit onwards, after which
  `/admin/v1/audit/verify` reports the log as intact. A copy held where that
  operator cannot rewrite it is the only thing that closes this, because a
  recomputed chain cannot reproduce hashes somebody else already holds. The
  destination is a plain HTTP endpoint with a bearer credential: every
  deployment can stand one up, it adds no dependency, and the one property that
  matters, that somebody else runs it, is not a property a message broker would
  have added.

  **Only the hash-covered fields are sent**, which is exactly what a receiver
  needs in order to recompute the hashes and notice a gap. The subject, the
  source address and the entry detail are not: the chain commits to a salted
  digest of those three rather than to the fields themselves, which is what lets
  an entry be erased without breaking verification, and it is that digest which
  travels. The per-entry salt stays in the database, because a source address
  carries about thirty-two bits of entropy and a receiver holding both the salt
  and the digest would recover it by exhaustive search. `detail` would otherwise
  have been the leak: nothing models its shape and nothing bounds what a future
  handler puts in it, so it is bounded by exclusion rather than by a filter
  somebody has to maintain. The consequence is stated rather than hidden: the
  witness proves the history was not rewritten and cannot be used to investigate
  an incident or to rebuild the log.

  **Nothing about delivery can gate an authentication.** The recorder hands the
  entry over after the append has committed, through a call that does not block,
  cannot fail and returns nothing; delivery happens on one background goroutine
  that nothing waits for. An entry the buffer cannot take is dropped, counted,
  logged once per episode and alerted on, and then delivered anyway: the audit
  log is the real buffer, so the shipper falls back to reading it from one past
  the last sequence number the receiver acknowledged. A full buffer therefore
  costs a database read and some latency, never a hole in the witness, and the
  same fallback covers an out-of-order offer, a failed POST and a restart.

  **At least once, with the watermark written last.** A file in the data
  directory records how far delivery has got, written by a temporary file, an
  fsync and a rename, and only after the receiver has acknowledged the batch. A
  process that dies in between sends that batch again, which is why a receiver
  de-duplicates on `seq` and treats a second, differing copy of a sequence
  number as evidence rather than as a correction. The other order would have
  been at most once: the marker would move, the entries would never arrive, and
  nothing anywhere would know.

  **The trust assumption is configuration, not documentation.** An endpoint is
  refused unless `audit.sink.receiver_outside_operator_control` is set to true,
  because this code cannot check where the receiver is and a sink the operator
  administers is worthless rather than merely weaker. Plain HTTP is refused
  except towards loopback, a `token_env` naming an empty variable stops the
  start, and so does a watermark directory that cannot be written.

  `ReadAuditRange` joins the store interface, reading entries by sequence number
  across every tenant for the reason `VerifyChain` already does: an entry
  recorded against the reserved system tenant sits between two ordinary ones,
  and a tenant-scoped read would hand a witness a contiguous chain full of
  holes. No migration: the watermark is a file, not a table, so a restored
  backup cannot put it back out of step with the receiver.

  What an operator reads: a new `audit_sink` block in the detailed health
  report, carrying the endpoint, how far delivery has got, how far behind it is
  and how many hand-offs the buffer refused, `degraded` while the last attempt
  is failing; and one new alert type, `audit.sink_failing`, at warning. See
  [ADR 0016](docs/adr/0016-ship-the-audit-chain-to-an-external-witness.md), the
  `audit.sink` section of [docs/CONFIGURATION.md](docs/CONFIGURATION.md),
  attacker 9 in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what it closes
  and what it does not, and [docs/MONITORING.md](docs/MONITORING.md) for how
  delivery failing becomes something somebody sees.

- **Administrative sign-in with WebAuthn**, from
  [docs/ROADMAP.md](docs/ROADMAP.md) section 2.4. An administrator signs in to
  `/admin` with a passkey instead of pasting a long-lived bearer token into a
  form field. A passwordless product whose own console asks for a pasted secret
  was an awkward demonstration, and the secret is the credential itself: it ended
  up in browser form history, in a password manager entry nobody audits, and on
  the screen of whoever was standing behind the operator.

  **An administrative credential is not a subject credential, in either
  direction.** This is the property the feature turns on, because the second
  direction would make every enrolled user of a deployment an administrator of
  it. Three things enforce it, and each would do on its own. The rows live in
  separate tables, `admin_credentials` and `webauthn_credentials`, and neither
  lookup path reads the other, so a forgotten predicate cannot reach across
  because no such predicate exists. The relying-party user handle is derived
  under a different domain separator, so an authenticator creates a distinct
  credential for an administrative enrolment rather than replacing a subject's,
  and a response carrying a handle from the other space fails the comparison
  every completion makes. And neither registration will store a credential
  identifier the other table already holds, which turns "no credential is both"
  into a stored fact rather than a consequence of how handles are built. The
  ceremony state is separated the same way, in `admin_webauthn_challenges`: a
  console sign-in and a subject usernameless sign-in are otherwise
  indistinguishable as rows, so one table would let a caller start one and finish
  it through the other's endpoint. Both cross-use directions have tests.

  **A passkey carries no authority.** The role, the expiry and the revocation are
  read from the administrative token the credential names, and `AdminCredential`
  has no role field. Enrolling one is therefore not a privilege change and is not
  held for a second administrator: there would be nothing to weigh, and a queue
  would mean an administrator who has lost a key waits for somebody else to wake
  up. It carries no `internal/rbac` permission either, because it is part of how
  you authenticate rather than something you do as an administrator, and
  `/admin/sign-in` and `/admin/sign-out` carry none. What bounds it is that every
  route acts on the caller's own token and there is no form that names another
  administrator's, for the reason there is no route to rotate one.

  **The session is the one the console already issues**, with the same cookie
  attributes, the same idle and absolute deadlines and the same request token on
  every form. A refused passkey says one fixed sentence whether the credential is
  unknown, withdrawn, or attached to a token that has expired or been revoked;
  which of them it was is on the `admin.auth_failed` entry, because the operator
  reading the history is the defender. A successful sign-in is `admin.authorised`
  with `"method": "passkey"`, and a pasted token now carries
  `"method": "sign-in token"`, so the two are one query. Enrolment and withdrawal
  are `admin_credential.enrolled` and `admin_credential.revoked`.

  **The bearer token does not go away.** It is how the first administrator exists
  at all and the way back in when a key is lost. The new
  `admin.passkey_required` refuses a pasted token once *that token* has a
  passkey; the scope is the token and not the deployment, so a token with no
  passkey is always accepted, `-bootstrap-admin` always produces one that can be
  pasted, and the setting can never leave a deployment with nobody able to sign
  in. Withdrawing the last passkey reopens the form immediately.

  No seventh screen: signing in with a passkey is the sign-in screen, and
  managing them is a section of the dashboard. Migration
  `0005_admin_credentials` adds the two tables for both engines; the janitor's
  existing challenge sweep collects the new challenge table too, rather than
  gaining a sweep of its own. See
  [ADR 0017](docs/adr/0017-administrative-sign-in-with-webauthn.md), the passkey
  section of [docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md), `admin` in
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and the cross-cutting limit in
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) that says what this does not
  close.

### Fixed

- **Alerts never reached the database.** `alerts.Engine.Raise` built the row
  without an identifier, and both store backends refuse an alert that has none,
  so every condition the service detected was logged as "alert could not be
  recorded" and dropped. The engine now mints the identifier. The row that wins
  the fingerprint conflict keeps the one it already had, so the value is used
  only for a first occurrence. Nothing else changes: the alert table was empty
  on every deployment before this, and starts filling now.

  It went unnoticed because the double stood in for the store too generously:
  `fakeStore.RaiseAlert` minted the identifier itself, so twelve tests walked
  every alert type through a subsystem that had never written a row and went
  green. The double now refuses the same four preconditions both backends
  refuse, and `internal/api/alert_delivery_test.go` provokes a lockout over
  HTTP and reads the row back out of a real SQLite database, which is the seam
  nothing was testing.
- **`make lint` analysed nothing.** The pinned `golangci-lint v2.6.0` cannot
  read the export data of the Go toolchain this project builds with, so every
  run ended with one `typecheck` error against `internal/version` and no
  analysis at all. The pin moves to `v2.13.2`. Running it revealed 702
  findings, of which the correctness linters accounted for none once three
  genuine misconfigurations were corrected: `misspell` was set to the US
  locale against a codebase whose prose is British throughout (182 findings,
  and "unauthorized" is now exempt because it is the wire spelling of an HTTP
  status and of an RFC 9457 problem type, not prose); `errcheck` duplicated
  gosec's G104 with `check-blank`, which reports the same lines without
  requiring the written justification `.gosec.json` demands; and the embedded
  gosec did not inherit the G101 entropy thresholds. `errorlint` is configured
  not to read `fmt.Errorf("%w: %v", ErrSentinel, err)` as a mistake, since the
  `%v` is what keeps a third-party error's own type out of the chain a caller
  matches on. The remaining 430 are style budget and are recorded in
  [docs/ROADMAP.md](docs/ROADMAP.md).
- **`rows.Err()` was not checked** in the SQLite smoke test, where an
  iteration cut short would have read as a schema with fewer tables than it
  has.

- **The wizard discarded the error from closing a file it had just written.**
  `writeFile` is what puts a keyring, a signing key or a configuration file on
  disk, and a close that fails is how a short file comes to exist: the bytes
  are accepted by the kernel and never reach the disk. The error is now checked
  and reported, so an artefact that looks written and does not open is refused
  at the moment it is created rather than discovered by `verify` long
  afterwards.
- **`-bootstrap-admin` could lose an administrative token silently.** The
  tokens are minted, stored as a digest and audited before they are printed, so
  a write to standard output that failed left the deployment with a full
  administrator nobody holds while the command still exited zero. Redirecting
  the output to a file on a full disk was enough to cause it. Every write is
  now checked and a failure is reported, naming what was lost and what to do
  about it.

## [1.0.0] - 2026-09-16

First release. An on-premise passwordless authentication server: WebAuthn and
FIDO2, TOTP, single-use recovery codes, one static binary, SQLite or PostgreSQL.

### Added

- **WebAuthn and FIDO2 ceremonies**, per W3C WebAuthn Level 2. Registration and
  assertion, each as two round trips, with the ceremony state held server side
  in `webauthn_challenges` and consumed atomically. Platform and roaming
  authenticators, an AAGUID allow list and block list, and a configurable
  credential limit per subject. User verification is reported from the
  authenticator data of the ceremony in hand and from nothing else, so a
  possession-only assertion is never signed as user-verified, whatever the
  credential did at registration. The ceremony layer is tested end to end
  against a software authenticator.
- **Optional attestation verification, offline.** `webauthn.metadata_path`
  names a FIDO MDS3 BLOB on disk. Its JWT signature is verified against the FIDO
  root, so a file altered on disk is refused, and it is never fetched over the
  network. Entries that do not parse are dropped, which fails safe: an unknown
  model is refused when attestation is required.
- **TOTP**, per RFC 6238 over the HMAC counter construction of RFC 4226. SHA1,
  SHA256 or SHA512; six or eight digits; a period between 15 and 120 seconds; a
  shared secret of at least 160 bits; enrolment confirmed by the user producing
  a code before the secret becomes usable; a replay high-water mark advanced by
  compare-and-swap.
- **Single-use recovery codes**. Twenty characters of Crockford base32 with `I`,
  `L`, `O` and `U` removed, split into a six-character indexed selector and a
  fourteen-character verifier stored as an Argon2id PHC string. Issuing a batch
  retires every unused code from the previous one in the same transaction.
- **A signed assertion result**. A compact JWS (RFC 7515) signed with Ed25519
  under the `EdDSA` algorithm of RFC 8037, carrying JWT claims including an
  `amr` array naming the factor used, a unique `jti`, and a 60 second lifetime.
  The verification key is published as a JWK Set (RFC 7517) with a `kid` that is
  its RFC 7638 thumbprint, so an integrating application verifies offline.
- **Two authenticated HTTP surfaces**. `/v1` for an integrating application,
  behind an API key; `/admin/v1` for an operator, behind an administrative
  token, a network allow list and a per-route permission. Errors follow
  RFC 9457, with a URN type per class and a `request_id` on every response.
- **Three administrative roles and twenty-five permissions**, enforced where
  each route is mounted rather than inside its handler. `admin_auditor` reads
  and changes nothing; `admin_operator` adds the operations that recover a
  locked-out user; `admin_full` holds everything.
- **Dual approval as a redeemable capability**, for four operations by default:
  `subject.erase`, `admin_token.create`, `credential.revoke_bulk` and
  `kek.rotate`. The first request queues the operation and performs nothing,
  answering 202 with the problem type `approval-required`. A different
  administrator approves it; self-approval is refused in the same transaction
  as the state change. The original requester then repeats the identical request
  with the header `X-Approval-Id`, and only that redemption runs the operation.
  An approval is bound to the operation, the requester and the payload, expires
  after `features.approval_ttl`, and is spent exactly once by a conditional
  update made before the operation runs. See
  [ADR 0013](docs/adr/0013-approvals-are-redeemed-not-executed.md).
- **API key scopes**: `subjects`, `webauthn`, `totp`, `recovery` and `health`,
  one per public route family, enforced where each route is mounted. An unknown
  scope is refused with 400 when the key is minted. An empty list means
  unrestricted, and the minting response carries `unrestricted` so that the
  choice is visible. A key that calls outside its scopes gets 403 and the
  attempt is audited.
- **Revoking every authenticator of a subject in one call.**
  `POST /admin/v1/subjects/{subject_id}/credentials/revoke-all` revokes all
  WebAuthn credentials and the TOTP secret in one transaction, requires a
  reason, leaves the recovery codes alone and reports how many remain.
- **A keyring rewrap route.** `POST /admin/v1/kek/rewrap` moves every sealed
  record onto the current key version and reports `versions_in_use`, which is
  what tells an operator that an older version can be deleted from the keyring
  file. It completes the rotation that `n0passtemps-wizard kek rotate` starts.
- **A hash-chained audit log**. Every security-relevant event, with a SHA-256
  chain committing each entry to its predecessor, a verification route that
  reports the first entry that does not reproduce its hash, and append-only
  guards in both engines. Erasure and retention are the two narrow, attested
  exceptions, each of which records itself.
- **Rate limiting on three dimensions at once**, per subject, per source network
  and per API key, plus a per-administrator revocation burst. The per-key
  request volume, `throttle.max_requests_per_key`, is metered by a middleware on
  every public route, not only on those that record an authentication outcome.
  Buckets are keyed
  by a digest of a domain-separated, length-prefixed tuple, so a caller cannot
  choose which bucket their failures land in. IPv6 sources are bucketed by
  `/64`.
- **Ten alert types**, deduplicated by fingerprint so that a brute-force attempt
  produces one row with a rising occurrence count. Each is logged at the level
  its severity deserves, so a deployment that ships logs but does not query the
  table still sees the critical ones.
- **Two health reports.** An unauthenticated liveness probe carrying a single
  field, and an authenticated report carrying the version, the storage engine
  and its latency, the keyring state and rotation status, the TLS certificate
  expiry, the audit chain head, the open alert counts and the active feature
  set.
- **GDPR Article 15 and Article 17 support.** An audited reveal of the
  application's subject reference, and a two-phase erasure that blocks a subject
  immediately and purges after a configurable retention window, while leaving
  the audit chain verifiable. Cancelling an erasure inside the window restores
  the subject, who can authenticate again at once.
- **Both storage engines.** SQLite, with a two-pool arrangement and
  `BEGIN IMMEDIATE` write transactions; PostgreSQL, with one pool and an
  advisory lock on the audit append. Identical schema, asserted in CI by
  `make migrate-check`.
- **A server-rendered administration interface**, with its templates and assets
  embedded in the binary, servable at `/admin` behind the network allow list, or
  disabled entirely.
- **PostgreSQL DSN validation that parses the DSN.** Both the URL form and the
  `key=value` form are read. A DSN with no `sslmode` is refused, `prefer` and
  `allow` are always refused, and `sslmode=disable` is accepted towards loopback,
  a Unix socket directory or an empty host. Towards any other host it needs the
  explicit `database.allow_plaintext`, because the validator cannot see network
  topology and the operator has to say that the link is private.
- **Strict configuration validation.** Defaults, then a TOML file with unknown
  keys refused, then the environment. Every problem is reported at once rather
  than one per restart, and each refusal explains itself.
- **Two binaries.** `n0passtemps-server`, with `-config`, `-check-config`,
  `-migrate`, `-bootstrap-admin`, `-admins`, `-force` and `-version`; and
  `n0passtemps-wizard`, which generates the keyring, the Ed25519 signing key and the subject pepper, writes a
  configuration, rotates and inspects a keyring, and validates a configuration
  file. Nothing the wizard does is required: every file it writes can be written
  by hand.
- **Bootstrap administrators, created by an explicit command.**
  `n0passtemps-server -config <path> -bootstrap-admin` is a one-shot run of the
  binary that mints the first administrative tokens, prints each once to the
  operator's terminal and exits. `-admins N`, from 1 to 5, creates the initial
  quorum: with dual approval on, one administrator cannot mint a second through
  the API, and the API carries no exemption for a sole administrator, because a
  rogue administrator could reach one by revoking the others. The command
  refuses when a usable full administrator exists, unless `-force` is passed by
  an operator who has lost every token or has to complete a quorum. The running
  service never prints a token: with no administrator it logs a warning that
  names the command, with `-admins 2` when dual approval is on. With compose the
  command is `docker compose run --rm n0passtemps -bootstrap-admin -admins 2`.
  The tenant named by `tenant.id` is provisioned at every start. See
  [ADR 0014](docs/adr/0014-bootstrap-by-explicit-command.md).
- **An in-process janitor**, running every `features.janitor_interval`. Five
  sweeps: abandoned WebAuthn challenges, stale throttle buckets, undecided
  approval requests, erasure requests past their retention window, and audit
  entries past `audit.retention_days`. Each sweep is independent, so a failure
  in one does not stop the others, and each is idempotent, so a multi-replica
  deployment repeating them is wasteful rather than harmful. The same pass
  raises the `kek.rotation_overdue` alert when `features.kek_rotation_reminder`
  is on and the current key version is older than `kek.rotation_interval`.
- **Four deployment forms**, in `deploy/`: a single container with SQLite,
  compose with PostgreSQL, a hardened systemd unit, and Kubernetes manifests
  with a restricted Pod Security profile and a default-deny NetworkPolicy. Every
  form passes every secret: the subject pepper comes from `.env`, the systemd
  environment file or the Kubernetes Secret, and the signing key sits beside the
  keyring under `/etc/n0passtemps/kek`. The image owns that directory as uid
  65532 and ships the wizard, so a fresh named volume is populated with
  `docker run --entrypoint /usr/local/bin/n0passtemps-wizard` and no root
  helper. The `config.toml` bind mount is relabelled for SELinux hosts. The two
  compose files and the Kubernetes ConfigMap set `server.allow_plaintext`, the
  explicit acknowledgement that the container binds every interface while
  something outside the process constrains who can reach the port, and the
  PostgreSQL compose file sets `database.allow_plaintext` for its private bridge
  network. A test in
  `internal/config` fails when a file in `deploy/`, `config/`, `examples/`,
  `.github/` or the `Makefile` names a prefixed variable that nothing reads.
- **The documentation set** listed in the README, including fourteen architecture
  decision records.

### Security

- **Every route on both surfaces requires a credential.** The only exceptions
  are the liveness probe and the JWK Set, both listed explicitly in the router
  so that a third is a visible decision. An unauthenticated registration route
  would let anyone enrol an authenticator against any subject and then assert as
  them, which is a complete authentication bypass and the condition OWASP API
  Security Top 10 2023 records as API2:2023.
- **The relying party identifier and the origin list are server configuration**
  and are never read from a request. A caller able to nominate either could
  declare its own origin, and the binding that makes WebAuthn resistant to
  phishing would prove nothing.
- **Envelope encryption for the material that genuinely needs it.** AES-256-GCM
  under a per-record data key, wrapped under a versioned key encryption key,
  with the record header as additional authenticated data so that a KEK version
  and a wrapped key cannot be swapped between records. Rewrapping a record keeps
  its data key and always opens and authenticates the payload, even for a record
  already on the current version, so a rewrap error is a reliable integrity
  report. Key versions in the
  keyring are canonical decimal starting at 1: `"01"` and `"0"` are refused.
- **The keyring is refused if it lives in the data directory**, with symbolic
  links resolved on both sides, and refused if its mode grants anything to group
  or other. A key stored beside the ciphertext it protects gives no
  confidentiality once the volume is copied. It is never generated implicitly at
  startup.
- **Recovery codes are hashed, not encrypted**, so losing the keyring does not
  destroy the codes that exist to be used when other things have gone wrong, and
  a stolen database yields no usable code even to an attacker who holds the
  keyring.
- **WebAuthn public keys are stored in clear**, so losing the keyring does not
  destroy enrolments that were never secret. The cost of a lost keyring is
  therefore the TOTP secrets and the readable subject references, and nothing
  else.
- **Subject references are pseudonymised at rest**: an HMAC-SHA256 under a
  server-held pepper for lookup, and an envelope-encrypted copy for disclosure.
  The pepper is a separate secret from the keyring, so the key able to decrypt
  secrets is not also the key able to confirm whether a given person has an
  account. There is no substring search, because the encryption exists precisely
  to make scanning impossible. The pepper's encoding is never guessed: a `hex:`,
  `base64:` or `raw:` prefix names it, unprefixed hexadecimal and unprefixed
  base64 of at least 32 bytes are accepted, and anything else is refused.
- **Bearer credentials carry 160 bits of verifier entropy**, are shown once, and
  are stored as a selector plus a SHA-256 digest bound to the credential kind
  and the selector, so a stored digest cannot be moved between rows or between
  the two tables. Verification is one indexed lookup and a constant-time
  comparison.
- **Uniform refusals.** Every credential failure returns one response and every
  ceremony failure returns another, with no detail, so a caller cannot
  distinguish an unknown selector from a wrong verifier, or an expired challenge
  from a bad signature from a subject that does not exist. The real reason is
  logged and audited. A credential-store outage is not a refusal: it answers 503
  with the problem type `unavailable` and is not audited as a rejected
  credential.
- **No administrative token in a log stream.** A log is shipped and retained by
  systems with looser access rules than a credential store, so the long-running
  service never writes a token; only the one-shot bootstrap command does, to the
  terminal of the operator who ran it.
- **Replay is closed at the store, not by convention.** The challenge
  consumption, the TOTP timestep advance, the signature counter advance and the
  recovery code consumption are each a single conditional statement, so two
  concurrent attempts have exactly one winner.
- **A forwarded client address is honoured only from a configured proxy
  network.** Trusting `X-Forwarded-For` from any source would let a caller
  choose the address that rate limiting and audit entries key on, turning both
  controls off.
- **Security headers on every response**, including error responses: a
  restrictive Content-Security-Policy, `nosniff`, `frame-ancestors 'none'`,
  `no-referrer`, and HSTS only over a request that actually arrived on TLS.
- **Secrets are carried as `[]byte` and overwritten when done**, through a
  helper the optimiser cannot eliminate. The limits of that are documented
  rather than implied. In logs, a value wrapped in `logging.Secret` is redacted
  wherever it appears, including inside a struct.
- **Six direct dependencies**, each argued for, with the JWS assembled by hand
  rather than taken from a JWT library, and no Node.js in the build or in CI.
  Every GitHub Action is pinned to a commit SHA and every tool version is pinned
  in the `Makefile`.
- **A supported CI security gate**: `gosec`, `govulncheck`, `gitleaks` over the
  working tree and the history, CodeQL, Trivy and dependency review, on every
  push and weekly on a schedule.

### Notes

- **The implementation deviates from the original specification on eleven
  points.** `cdc-n0passtemps-v3-complet.html` at the repository root is that
  specification, and it remains in the repository because it is useful for the
  product framing. Where it disagrees with the code, the code is authoritative.
  Each deviation is recorded, with its context, its decision and its costs, in
  [docs/adr](docs/adr/README.md): records 0002 to 0012. A reader comparing the
  two documents should start there, so that a considered decision is not
  mistaken for drift. Records 0013 and 0014 cover two questions the
  specification leaves open: how an approved operation comes to run, and where
  the first administrative token comes from.

  In brief: the public API surface is authenticated rather than anonymous
  (0002); the relying party is this service and its identifier is server
  configuration (0003); a completed ceremony returns a signed assertion rather
  than a bare 200 (0004); recovery codes are hashed rather than sealed (0005);
  WebAuthn public keys are stored in clear rather than sealed (0006); the audit
  log is hash-chained rather than protected by triggers alone (0007); the health
  endpoint is split by audience (0008); a keyring inside the data directory is
  refused rather than warned about (0009); revocation is final rather than
  reversible for 24 hours (0010); HOTP is not offered (0011); and the
  administration interface is server-rendered rather than a React
  single-page application (0012).

- **The audit chain is tamper-evident, not tamper-proof.** An operator holding
  the database file can rewrite it consistently, and detecting that needs a
  witness outside their control. Shipping the chain head to an append-only
  external sink is not in this release.
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) states this and the other
  accepted limits plainly.

- **Multi-tenancy is prepared but not offered.** Every table carries a tenant
  identifier and every query filters on it, so the schema and the access paths
  are ready. The tenant is read from configuration rather than from the caller's
  credential, so one deployment serves one tenant. The check that refuses a
  credential from another tenant exists so that a database carried over from
  another deployment fails loudly, not as a multi-tenancy control.

- **An API key minted without scopes is unrestricted.** That is the default, so
  a deployment that never names scopes has keys that reach every `/v1` route.
  The minting response says `"unrestricted": true`; nothing refuses it.

- **A redeemed approval is spent before the operation runs.** If the operation
  then fails, the approval is gone and a new request and a new approval are
  needed. Nothing executes at approval time, so an approved operation whose
  requester never returns expires unperformed. For `admin_token.create` the
  approval is bound to the name and the role, not to `expires_in_days`.

- **A keyring rotation has three steps, and the middle one is a restart.**
  `n0passtemps-wizard kek rotate` adds a version to the file; the service reads
  the keyring once, at startup, so it has to be restarted before
  `POST /admin/v1/kek/rewrap` can target the new version. An older version may
  be deleted from the file only when the response shows `versions_in_use`
  holding the current version alone and `failed` at zero.

- **The metadata BLOB is only as fresh as the operator keeps it.** A model
  certified after the file was downloaded is unknown, and refused when
  attestation is required. A model compromised after the download is still
  trusted. The service never fetches the file.

- **Migrations are forward-only.** There is no down migration. A rollback across
  a schema change means restoring the database, and an applied migration is
  immutable: the runner records each file's SHA-256 and refuses to proceed if an
  already applied version hashes differently.

- **The 60 second assertion lifetime is unforgiving on hosts whose clocks
  drift**, which is common on unmanaged on-premise machines without NTP. The
  failure looks like a signature problem rather than a clock problem. The same
  exposure applies to TOTP, where the default tolerance is one period of 30
  seconds either side.

- **Support is GitHub issues and nothing else.** No email address, no chat, no
  call booking. No response time is promised, because one person maintains this
  project.

[1.1.2]: https://github.com/Socold/n0passtemps/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Socold/n0passtemps/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Socold/n0passtemps/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Socold/n0passtemps/releases/tag/v1.0.0
