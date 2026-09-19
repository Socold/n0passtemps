package webauthn

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/x/revoke"

	"github.com/Socold/n0passtemps/internal/config"
)

// TestLoadMetadataWithoutAPathIsANoOp covers the default deployment, which
// verifies no attestation and must not require a file.
func TestLoadMetadataWithoutAPathIsANoOp(t *testing.T) {
	p, nextUpdate, err := loadMetadata(config.WebAuthn{})
	if err != nil || p != nil || !nextUpdate.IsZero() {
		t.Fatalf("loadMetadata with no path = %v, %v, %v; want nil, the zero time and nil",
			p, nextUpdate, err)
	}
}

// TestLoadMetadataRefusesAnUnsignedFile checks that trust anchors are never
// read from a file that does not carry the FIDO Alliance signature.
//
// Reading the BLOB from disk instead of fetching it is only acceptable because
// its signature is verified. If an arbitrary JSON document were accepted here,
// anyone able to write the file could add their own root certificate and have
// the service trust authenticators they manufactured.
func TestLoadMetadataRefusesAnUnsignedFile(t *testing.T) {
	for name, body := range map[string]string{
		"empty":        "",
		"plain json":   `{"entries":[]}`,
		"unsigned jwt": "eyJhbGciOiJub25lIn0.eyJlbnRyaWVzIjpbXX0.",
		// {"alg":"none"} with a signature segment present. Releases of the
		// library before 0.18 accepted this, which is why the refusal is made
		// explicitly rather than left to the decoder.
		"alg none with a fake signature": "eyJhbGciOiJub25lIn0.eyJlbnRyaWVzIjpbXX0.c2ln",
		// {"alg":"HS256"}: a symmetric algorithm has no place on a published BLOB.
		"symmetric algorithm": "eyJhbGciOiJIUzI1NiJ9.eyJlbnRyaWVzIjpbXX0.c2ln",
		// {"alg":"ES256"} with no certificate chain to verify against.
		"no certificate chain": "eyJhbGciOiJFUzI1NiJ9.eyJlbnRyaWVzIjpbXX0.c2ln",
		"random text":          "not a metadata blob",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blob.jwt")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadMetadata(config.WebAuthn{MetadataPath: path}); err == nil {
				t.Fatal("a file without a valid FIDO signature was accepted as a source of trust anchors")
			}
		})
	}
}

// TestLoadMetadataRealBlob runs against a genuine BLOB when one is supplied.
//
// The file is ten megabytes and changes monthly, so it is not vendored. Set
// N0PASSTEMPS_TEST_MDS_BLOB to a copy downloaded from
// https://mds3.fidoalliance.org/ to run it. It checks the two properties that
// matter: a genuine file loads with no network access, and the same file with
// one bit flipped is refused.
func TestLoadMetadataRealBlob(t *testing.T) {
	path := os.Getenv("N0PASSTEMPS_TEST_MDS_BLOB")
	if path == "" {
		t.Skip("N0PASSTEMPS_TEST_MDS_BLOB is not set")
	}

	_, nextUpdate, err := loadMetadata(config.WebAuthn{MetadataPath: path, RequireAttestation: true})
	if err != nil {
		t.Fatalf("a genuine blob did not load: %v", err)
	}
	if nextUpdate.IsZero() {
		t.Error("the loader reported no nextUpdate, so nothing can say how old the trust anchors are")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	tampered := filepath.Join(t.TempDir(), "tampered.jwt")
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadMetadata(config.WebAuthn{MetadataPath: tampered}); err == nil {
		t.Fatal("a blob altered on disk was accepted")
	}
}

// TestAMetadataBlobLongPastItsNextUpdateIsRefused covers the one direction in
// which a stale BLOB is not safe.
//
// A model certified after the download is unknown and is refused. A model
// withdrawn after the download is still trusted, because the status report
// saying so is in a file the service has not been given. Loading a file from
// two years ago without a word is therefore trusting a list of anchors that
// nobody has checked since.
func TestAMetadataBlobLongPastItsNextUpdateIsRefused(t *testing.T) {
	now := time.Date(2026, time.September, 20, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name       string
		nextUpdate time.Time
		wantErr    bool
	}{
		{
			name:       "a payload that declares no next update is accepted",
			nextUpdate: time.Time{},
		},
		{
			name:       "a current blob is accepted",
			nextUpdate: now.Add(20 * 24 * time.Hour),
		},
		{
			name:       "a blob a fortnight past its date is accepted",
			nextUpdate: now.Add(-14 * 24 * time.Hour),
		},
		{
			name:       "a blob at the edge of the tolerance is accepted",
			nextUpdate: now.Add(-metadataStaleGrace),
		},
		{
			name:       "a blob a day beyond the tolerance is refused",
			nextUpdate: now.Add(-metadataStaleGrace - 24*time.Hour),
			wantErr:    true,
		},
		{
			name:       "a blob two years old is refused",
			nextUpdate: now.AddDate(-2, 0, 0),
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMetadataFreshness(tc.nextUpdate, now)
			if tc.wantErr && err == nil {
				t.Fatalf("a blob whose nextUpdate was %s was accepted at %s",
					tc.nextUpdate.Format(time.DateOnly), now.Format(time.DateOnly))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a usable blob was refused: %v", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "nextUpdate") {
				t.Errorf("the refusal reads %q and does not name the date an operator has to act on", err)
			}
		})
	}
}

// TestSealedRevocationChecksMakeNoOutboundRequest pins the behaviour the
// metadata loader depends on: the revocation package it cannot configure per
// call is given a client that refuses to dial.
//
// The certificates whose distribution points would be contacted come out of the
// BLOB before the chain has been shown to reach the FIDO root, so the file
// chooses the destination. See sealRevocationChecks.
func TestSealedRevocationChecksMakeNoOutboundRequest(t *testing.T) {
	sealRevocationChecks()

	req, err := http.NewRequest(http.MethodGet, "http://crl.example.test/some.crl", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := revoke.HTTPClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the revocation client performed a request: a hostile blob would choose where to")
	}
	if revoke.HTTPClient.Timeout <= 0 {
		t.Error("the revocation client has no deadline, so a dropped packet would stall startup")
	}
}
