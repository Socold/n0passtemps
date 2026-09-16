// Package n0passtemps is the Go client for the n0passtemps authentication
// server: WebAuthn, TOTP and single-use recovery codes, called server to
// server with an API key.
//
// The package has two halves, and an integration needs both.
//
// Client calls the /v1 routes. It resolves subjects, carries the two round
// trips of each WebAuthn ceremony, enrols and verifies TOTP, and issues and
// consumes recovery codes. The WebAuthn options and credential payloads pass
// through as json.RawMessage, because a field dropped while re-modelling them
// is a field the server can no longer verify.
//
// Verifier checks the signed assertion that a successful ceremony returns. It
// is a compact JWS signed with Ed25519, and verifying it is what frees the
// application from trusting the network path between itself and the server.
// The checks are fixed by this package and none of them is chosen by the
// token: the algorithm is always EdDSA, the key is selected by "kid" alone,
// and no claim is read before the signature holds.
//
// The package depends on the standard library only and keeps no global state.
package n0passtemps
