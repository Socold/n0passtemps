package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/assertion"
)

// newSigningKey writes a signing key the way assertion-key init would.
func newSigningKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	privPEM, _, err := assertion.GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}
	if err := os.WriteFile(path, privPEM, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	priv, err := assertion.LoadPrivateKeyPEM(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM: %v", err)
	}
	return priv
}

// TestAssertionKeyRotateKeepsTheOutgoingKey checks the property the whole
// command exists for: after it runs, the public half of the key that was
// signing is on disk in a form the service can publish.
func TestAssertionKeyRotateKeepsTheOutgoingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "assertion-key.pem")
	before := newSigningKey(t, keyPath)

	prefix := filepath.Join(dir, "previous")
	if err := assertionKeyRotate([]string{"-file", keyPath, "-keep-prefix", prefix}); err != nil {
		t.Fatalf("assertionKeyRotate: %v", err)
	}

	after, err := assertion.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		t.Fatalf("the rotated signing key does not load: %v", err)
	}
	if after.Equal(before) {
		t.Fatal("the signing key was not replaced")
	}

	retired, err := assertion.LoadPublicKeyPEM(prefix + ".pub.pem")
	if err != nil {
		t.Fatalf("the retired public key does not load: %v", err)
	}
	if !retired.Equal(before.Public()) {
		t.Error("the retired public key is not the half of the key that was signing")
	}

	// The outgoing private key is kept, because a rotation done in a hurry is
	// one that may have to be undone.
	keptPriv, err := assertion.LoadPrivateKeyPEM(prefix + ".pem")
	if err != nil {
		t.Fatalf("the outgoing private key was not kept: %v", err)
	}
	if !keptPriv.Equal(before) {
		t.Error("the kept private key is not the one that was replaced")
	}

	// An issuer built as the server builds it must publish both.
	iss, err := assertion.NewIssuer(after, "https://auth.example.com", 60_000_000_000, 0,
		assertion.WithRetiredKeys(retired))
	if err != nil {
		t.Fatalf("NewIssuer with the retired key: %v", err)
	}
	kids := iss.RetiredKeyIDs()
	if len(kids) != 1 || kids[0] != assertion.Thumbprint(retired) {
		t.Errorf("RetiredKeyIDs = %v, want the outgoing key %q", kids, assertion.Thumbprint(retired))
	}
}

// TestAssertionKeyRotateLeavesTheLiveKeyAloneOnFailure pins the ordering.
//
// Everything that can fail happens before the live key is touched, so a
// rotation that refuses leaves a deployment exactly as it was rather than
// half rotated with no record of the key it was using.
func TestAssertionKeyRotateLeavesTheLiveKeyAloneOnFailure(t *testing.T) {
	t.Run("the destination already holds a previous rotation", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "assertion-key.pem")
		before := newSigningKey(t, keyPath)

		prefix := filepath.Join(dir, "previous")
		if err := os.WriteFile(prefix+".pub.pem", []byte("older rotation\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		err := assertionKeyRotate([]string{"-file", keyPath, "-keep-prefix", prefix})
		if err == nil {
			t.Fatal("the rotation overwrote a previous one")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("error %q does not say the file already exists", err)
		}

		after, err := assertion.LoadPrivateKeyPEM(keyPath)
		if err != nil {
			t.Fatalf("the signing key no longer loads: %v", err)
		}
		if !after.Equal(before) {
			t.Error("the signing key was replaced although the rotation failed")
		}
	})

	t.Run("the file is not a signing key", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "assertion-key.pem")
		const content = "not a key\n"
		if err := os.WriteFile(keyPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		if err := assertionKeyRotate([]string{"-file", keyPath, "-keep-prefix", filepath.Join(dir, "previous")}); err == nil {
			t.Fatal("the rotation accepted a file that is not a signing key")
		}

		raw, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(raw) != content {
			t.Error("the file was overwritten although it could not be loaded")
		}
	})
}

func TestAssertionKeyRotateDefaultsItsKeepPrefix(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "assertion-key.pem")
	newSigningKey(t, keyPath)

	if err := assertionKeyRotate([]string{"-file", keyPath}); err != nil {
		t.Fatalf("assertionKeyRotate: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var pubs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pub.pem") {
			pubs = append(pubs, e.Name())
		}
	}
	if len(pubs) != 1 {
		t.Fatalf("found %v, want exactly one retired public key", pubs)
	}
	// The default prefix carries a timestamp, so a second rotation the same day
	// does not collide with the first.
	if !strings.HasPrefix(pubs[0], "assertion-key.") || len(pubs[0]) <= len("assertion-key..pub.pem") {
		t.Errorf("retired key %q does not carry a distinguishing suffix", pubs[0])
	}
	if _, err := assertion.LoadPublicKeyPEM(filepath.Join(dir, pubs[0])); err != nil {
		t.Errorf("the retired key written by default does not load: %v", err)
	}
}
