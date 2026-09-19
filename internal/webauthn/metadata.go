package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/x/revoke"

	"github.com/Socold/n0passtemps/internal/config"
)

// loadMetadata builds an attestation trust provider from a FIDO Metadata
// Service BLOB held on disk.
//
// The BLOB is read from a file on purpose. The usual arrangement is to fetch it
// from the FIDO Alliance at startup and refresh it on a timer, which makes
// outbound network access a condition of verifying an attestation, and this
// service is meant to run with none. An operator who wants attestation
// downloads the BLOB through whatever controlled channel they already use for
// updates, and the service never fetches it.
//
// Loading it makes no outbound request. While it verifies the signature chain,
// the library's decoder asks its revocation package
// (github.com/go-webauthn/x/revoke) about each certificate in the chain, and
// that package would request the CRL distribution points and OCSP responders
// named in the certificate. sealRevocationChecks replaces the client it uses
// with one that refuses to dial, so those requests never leave the process;
// see that function for why refusing is the right answer rather than a loss.
//
// The BLOB is a signed JWT. The decoder verifies its signature chain against
// the FIDO root certificate compiled into the library, so a file that has been
// altered on disk is refused here rather than trusted. That check is what makes
// reading trust anchors from a local file acceptable at all.
//
// The provider is configured strictly:
//
//   - the attestation's trust path must chain to an anchor in the entry
//   - an authenticator whose status report marks it revoked or compromised is
//     refused
//   - when attestation is required, an authenticator with no entry is refused
//
// A stale BLOB fails safe in one direction only: a model certified after the
// file was downloaded is unknown and is refused under require_attestation,
// while a model compromised after the download is still trusted. Refreshing the
// file is therefore an operator duty, which is why the payload's own nextUpdate
// is read and a file long past it is refused rather than used in silence.
//
// The second return value is that nextUpdate, so the service can report how
// fresh its trust anchors are. It is the zero time when no BLOB is configured.
func loadMetadata(cfg config.WebAuthn) (metadata.Provider, time.Time, error) {
	if cfg.MetadataPath == "" {
		return nil, time.Time{}, nil
	}

	raw, err := os.ReadFile(cfg.MetadataPath)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: read metadata blob: %w", err)
	}
	if err = requireSignedBlob(raw); err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: metadata blob %q: %w", cfg.MetadataPath, err)
	}

	sealRevocationChecks()

	// The published BLOB routinely contains a handful of entries, out of several
	// thousand, that do not parse. Refusing the whole file over them would make
	// the feature unusable, so they are dropped. That fails in the safe
	// direction: a dropped model is an unknown model, and an unknown model is
	// refused whenever attestation is required.
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: build metadata decoder: %w", err)
	}

	payload, err := decoder.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: metadata blob %q did not verify: %w",
			cfg.MetadataPath, err)
	}

	parsed, err := decoder.Parse(payload)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: parse metadata blob: %w", err)
	}

	nextUpdate := parsed.Parsed.NextUpdate
	if err = checkMetadataFreshness(nextUpdate, time.Now().UTC()); err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: metadata blob %q: %w", cfg.MetadataPath, err)
	}

	provider, err := memory.New(
		memory.WithMetadata(parsed.ToMap()),
		memory.WithValidateEntry(cfg.RequireAttestation),
		memory.WithValidateEntryPermitZeroAAGUID(!cfg.RequireAttestation),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
	)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("webauthn: build metadata provider: %w", err)
	}
	return provider, nextUpdate, nil
}

// metadataStaleGrace is how far past its own nextUpdate a BLOB may be before it
// stops being usable as a source of trust anchors.
//
// The FIDO Alliance publishes monthly and sets nextUpdate a month ahead, so a
// file inside this window is one an operator has merely not got round to
// replacing yet. Past it, the status reports the BLOB carries are old enough
// that a model withdrawn since the download would still be accepted as sound,
// which is the one direction in which a stale file is not safe. Three months is
// long enough that an ordinary maintenance cycle never trips it and short
// enough that a file forgotten for a year does.
const metadataStaleGrace = 90 * 24 * time.Hour

// checkMetadataFreshness refuses a BLOB whose own nextUpdate is long past.
//
// A payload with no nextUpdate is accepted: the field is one the specification
// now discourages, and inventing a deadline for a file that declares none would
// refuse something the FIDO Alliance still considers valid. Everything the BLOB
// says is otherwise checked against its signature, so the date is as
// trustworthy as the rest of the payload.
func checkMetadataFreshness(nextUpdate, now time.Time) error {
	if nextUpdate.IsZero() {
		return nil
	}
	deadline := nextUpdate.Add(metadataStaleGrace)
	if !now.After(deadline) {
		return nil
	}
	return fmt.Errorf("the payload declares nextUpdate %s and is %d days past it, beyond the "+
		"%d days this service tolerates; a model withdrawn since it was downloaded would "+
		"still be trusted, so download a current BLOB from https://mds3.fidoalliance.org/ "+
		"and restart",
		nextUpdate.Format(time.DateOnly),
		int(now.Sub(nextUpdate)/(24*time.Hour)),
		int(metadataStaleGrace/(24*time.Hour)))
}

// revocationSealed makes sealRevocationChecks idempotent, and gives every
// caller of it a happens-before edge onto the single assignment.
var revocationSealed sync.Once

// sealRevocationChecks stops the metadata decoder reaching the network.
//
// The decoder asks github.com/go-webauthn/x/revoke about every certificate in
// the BLOB's chain, and that package fetches the CRL distribution points and
// OCSP responders each certificate names through a package-level client, which
// by default is http.DefaultClient with no deadline of its own. Two things are
// wrong with leaving it there. A deployment that drops outbound packets rather
// than rejecting them waits for every one of those connections to time out
// before the service finishes starting. And the certificates whose URLs are
// dialled come out of a file that has not yet been shown to chain to the FIDO
// root, because the revocation check runs before the chain is verified: the
// file therefore chooses the destination, which is a request this process makes
// on behalf of whoever wrote it.
//
// Refusing outright rather than shortening the deadline costs nothing that was
// being collected. The check already fails soft, so with egress denied, which
// is how this service is meant to run, every answer was "could not tell" and
// the BLOB loaded regardless. What replaces it is the signature over the whole
// payload and the status reports inside it, both of which are checked, and the
// freshness bound above, which is what makes those reports worth having.
//
// The client is set rather than the transport alone so that a future release
// which reaches for the client's own Do method is bounded as well.
func sealRevocationChecks() {
	revocationSealed.Do(func() {
		revoke.HTTPClient = &http.Client{
			Transport: refusingTransport{},
			Timeout:   5 * time.Second,
		}
	})
}

// refusingTransport answers every request with an error instead of dialling.
type refusingTransport struct{}

// RoundTrip refuses the request. The error text names the host so that a
// deployment which did want revocation checking can see what it would have
// contacted.
func (refusingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("webauthn: outbound request to %q refused: this service verifies "+
		"metadata offline", req.URL.Host)
}

// requireSignedBlob refuses a metadata file that does not even claim to be
// signed, before the library sees it.
//
// The decoder verifies the signature chain, and that remains the real check.
// This one exists because that property is too important to rest on a single
// dependency: releases of the library before 0.18 accepted a BLOB whose header
// declared "alg":"none", which means anyone able to write the file could supply
// their own trust anchors and have authenticators they manufactured accepted as
// genuine. The pinned version is not affected, but a future downgrade, a fork
// or a vendored copy could be, and the test that guards this behaviour should
// not pass or fail depending on which version happens to be resolved.
//
// A BLOB must therefore be a three-part JWS whose protected header names a real
// signature algorithm and carries the certificate chain to verify it with.
func requireSignedBlob(raw []byte) error {
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 || parts[2] == "" {
		return errors.New("not a signed JWT: expected three non-empty segments")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return fmt.Errorf("unreadable JWT header: %w", err)
	}
	var header struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("unreadable JWT header: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(header.Alg)) {
	case "", "none":
		return errors.New("the JWT declares no signature algorithm; " +
			"an unsigned file cannot be a source of trust anchors")
	}
	if strings.HasPrefix(strings.ToUpper(header.Alg), "HS") {
		// A symmetric algorithm has no place here: the verifier holds no
		// shared secret, so accepting one invites the public-key-as-HMAC-key
		// confusion.
		return errors.New("the JWT declares a symmetric algorithm, which a published BLOB never uses")
	}
	if len(header.X5C) == 0 {
		return errors.New("the JWT carries no certificate chain to verify its signature against")
	}
	return nil
}
