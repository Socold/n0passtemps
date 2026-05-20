package webauthn

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Socold/n0passtemps/internal/config"
)

// TestLoadMetadataWithoutAPathIsANoOp covers the default deployment, which
// verifies no attestation and must not require a file.
func TestLoadMetadataWithoutAPathIsANoOp(t *testing.T) {
	p, err := loadMetadata(config.WebAuthn{})
	if err != nil || p != nil {
		t.Fatalf("loadMetadata with no path = %v, %v; want nil, nil", p, err)
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
			if _, err := loadMetadata(config.WebAuthn{MetadataPath: path}); err == nil {
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

	if _, err := loadMetadata(config.WebAuthn{MetadataPath: path, RequireAttestation: true}); err != nil {
		t.Fatalf("a genuine blob did not load: %v", err)
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
	if _, err := loadMetadata(config.WebAuthn{MetadataPath: tampered}); err == nil {
		t.Fatal("a blob altered on disk was accepted")
	}
}
