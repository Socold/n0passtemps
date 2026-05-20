package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"

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
// updates, and the service never reaches out.
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
// file is therefore an operator duty, and the documentation says so.
func loadMetadata(cfg config.WebAuthn) (metadata.Provider, error) {
	if cfg.MetadataPath == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(cfg.MetadataPath)
	if err != nil {
		return nil, fmt.Errorf("webauthn: read metadata blob: %w", err)
	}
	if err := requireSignedBlob(raw); err != nil {
		return nil, fmt.Errorf("webauthn: metadata blob %q: %w", cfg.MetadataPath, err)
	}

	// The published BLOB routinely contains a handful of entries, out of several
	// thousand, that do not parse. Refusing the whole file over them would make
	// the feature unusable, so they are dropped. That fails in the safe
	// direction: a dropped model is an unknown model, and an unknown model is
	// refused whenever attestation is required.
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, fmt.Errorf("webauthn: build metadata decoder: %w", err)
	}

	payload, err := decoder.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("webauthn: metadata blob %q did not verify: %w", cfg.MetadataPath, err)
	}

	parsed, err := decoder.Parse(payload)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse metadata blob: %w", err)
	}

	provider, err := memory.New(
		memory.WithMetadata(parsed.ToMap()),
		memory.WithValidateEntry(cfg.RequireAttestation),
		memory.WithValidateEntryPermitZeroAAGUID(!cfg.RequireAttestation),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: build metadata provider: %w", err)
	}
	return provider, nil
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
		return errors.New("the JWT declares no signature algorithm; an unsigned file cannot be a source of trust anchors")
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
