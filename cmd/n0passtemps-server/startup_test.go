package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
)

// The startup path is the only code in this repository an operator meets before
// anything works, and every failure in it is one they have to diagnose from a
// single line on stderr with no service to ask. That is why these functions
// spend more of themselves on error messages than on logic, and why the
// messages are what is checked here as much as the returns: a keyring that
// cannot be opened has to say how to create one, and a retired public key that
// cannot be read has to say where the entry came from.

// quietLogger discards output, so a failing test prints its own assertion
// rather than the service's startup log.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testConfig is a valid loopback configuration with the paths a test supplies.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Tenant.ID = "acme"
	cfg.Tenant.Name = "Acme Ltd"
	cfg.Database.Driver = "sqlite"
	cfg.Database.DSN = filepath.Join(t.TempDir(), "store.db")
	return &cfg
}

// keyringDocument returns a one-key keyring in the form both providers parse.
func keyringDocument(t *testing.T) string {
	t.Helper()
	key := make([]byte, kek.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"current": 1,
		"keys":    map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
	})
	if err != nil {
		t.Fatalf("encode keyring: %v", err)
	}
	return string(body)
}

// writeKeyring puts a usable keyring at path, outside any data directory.
func writeKeyring(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(keyringDocument(t)), 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
}

// TestOpenKeyringNamesTheCommandThatFixesIt is the property that decides
// whether a first run ends in a fixed deployment or in a search.
func TestOpenKeyringNamesTheCommandThatFixesIt(t *testing.T) {
	cfg := testConfig(t)
	cfg.KEK.Provider = "file"
	cfg.KEK.Path = filepath.Join(t.TempDir(), "keyring.json")

	_, err := openKeyring(cfg)
	if err == nil {
		t.Fatal("a keyring that does not exist was opened")
	}
	if !strings.Contains(err.Error(), "n0passtemps-wizard kek init") {
		t.Errorf("the error does not say how to create one:\n%v", err)
	}
	if !strings.Contains(err.Error(), cfg.KEK.Path) {
		t.Errorf("the error does not name the path it looked at:\n%v", err)
	}
}

// TestOpenKeyringReadsEachProvider covers the three the switch accepts and the
// refusal for anything else.
func TestOpenKeyringReadsEachProvider(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.KEK.Provider = "file"
		cfg.KEK.Path = filepath.Join(t.TempDir(), "keyring.json")
		writeKeyring(t, cfg.KEK.Path)

		ring, err := openKeyring(cfg)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, _, err := ring.Current(); err != nil {
			t.Errorf("current key: %v", err)
		}
	})

	t.Run("env", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.KEK.Provider = "env"
		cfg.KEK.EnvVar = "N0PASSTEMPS_TEST_KEK"

		// The variable carries the whole keyring document, not a bare key, so
		// that a rotation is expressible without changing the provider.
		t.Setenv(cfg.KEK.EnvVar, keyringDocument(t))

		ring, err := openKeyring(cfg)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, _, err := ring.Current(); err != nil {
			t.Errorf("current key: %v", err)
		}
	})

	t.Run("an unknown provider", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.KEK.Provider = "hsm"
		if _, err := openKeyring(cfg); err == nil {
			t.Fatal("an unsupported provider was accepted")
		}
	})

	// The tpm provider needs a device and is covered by internal/crypto/kek
	// against swtpm. What is checked here is that the startup path's message
	// names the command that seals one, since that is this function's own
	// contribution.
	t.Run("tpm without a device", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.KEK.Provider = "tpm"
		cfg.KEK.Path = filepath.Join(t.TempDir(), "sealed.bin")
		cfg.KEK.TPMDevice = filepath.Join(t.TempDir(), "no-such-tpm")

		_, err := openKeyring(cfg)
		if err == nil {
			t.Skip("a TPM answered at the test path; nothing to assert here")
		}
		if !strings.Contains(err.Error(), "n0passtemps-wizard kek seal") {
			t.Errorf("the error does not say how to seal one:\n%v", err)
		}
	})
}

// TestOpenKeyringRefusesAKeyBesideItsCiphertext is ADR 0009, checked at the
// startup path because that is where the data directories are known.
func TestOpenKeyringRefusesAKeyBesideItsCiphertext(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t)
	cfg.Database.DSN = filepath.Join(dir, "store.db")
	cfg.Database.DataDir = dir
	cfg.KEK.Provider = "file"
	cfg.KEK.Path = filepath.Join(dir, "keyring.json")
	writeKeyring(t, cfg.KEK.Path)

	if _, err := openKeyring(cfg); err == nil {
		t.Fatal("a keyring inside the data directory was accepted; a copied volume would carry both")
	}
}

// TestLoadRetiredKeysStopsTheStartOnAnUnreadableEntry is the behaviour its
// comment argues for.
//
// Skipping the entry would refuse exactly the assertions it exists to keep
// working, and would do it at a verifier rather than here where an operator is
// watching.
func TestLoadRetiredKeysStopsTheStartOnAnUnreadableEntry(t *testing.T) {
	dir := t.TempDir()

	if keys, err := loadRetiredKeys(nil); err != nil || keys != nil {
		t.Errorf("no paths returned %v, %v; want nil, nil", keys, err)
	}

	good := filepath.Join(dir, "retired.pem")
	writePublicKeyPEM(t, good)

	keys, err := loadRetiredKeys([]string{good})
	if err != nil {
		t.Fatalf("a readable key was refused: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(keys))
	}

	missing := filepath.Join(dir, "absent.pem")
	_, err = loadRetiredKeys([]string{good, missing})
	if err == nil {
		t.Fatal("a retired key that cannot be read did not stop the start")
	}
	if !strings.Contains(err.Error(), "retired_public_key_paths") {
		t.Errorf("the error does not say which setting the entry came from:\n%v", err)
	}
}

// writePublicKeyPEM writes the public half of a fresh Ed25519 key.
func writePublicKeyPEM(t *testing.T, path string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestOpenStoreReportsTheDriverItCannotServe covers the switch and its default.
func TestOpenStoreReportsTheDriverItCannotServe(t *testing.T) {
	cfg := testConfig(t)
	st, err := openStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Errorf("close: %v", err)
	}

	cfg.Database.Driver = "mysql"
	if _, err := openStore(cfg, quietLogger()); err == nil {
		t.Error("an unsupported driver was accepted")
	}
}

// newTestStore opens and migrates a SQLite store for the startup helpers that
// need one.
func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := sqlite.Open(sqlite.Options{DSN: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// TestEnsureTenantIsIdempotent is what makes a restart safe.
//
// It runs on every start, so provisioning twice would either fail the second
// start or write a second audit entry claiming a tenant was created that has
// existed for months.
func TestEnsureTenantIsIdempotent(t *testing.T) {
	cfg := testConfig(t)
	st := newTestStore(t)
	rec := audit.NewRecorder(st, quietLogger())
	ctx := context.Background()

	if err := ensureTenant(ctx, cfg, st, rec, quietLogger()); err != nil {
		t.Fatalf("first start: %v", err)
	}
	got, err := st.GetTenant(ctx, cfg.TenantID())
	if err != nil {
		t.Fatalf("the tenant was not provisioned: %v", err)
	}
	if got.Name != cfg.Tenant.Name {
		t.Errorf("name = %q, want %q", got.Name, cfg.Tenant.Name)
	}

	before := countAuditEntries(t, st)
	if err := ensureTenant(ctx, cfg, st, rec, quietLogger()); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if after := countAuditEntries(t, st); after != before {
		t.Errorf("a restart wrote %d more audit entries; provisioning is not idempotent", after-before)
	}
}

// countAuditEntries reads the chain head, which is the number of entries
// written.
func countAuditEntries(t *testing.T, st store.Store) int64 {
	t.Helper()
	seq, _, err := st.ChainHead(context.Background())
	if err != nil {
		t.Fatalf("chain head: %v", err)
	}
	return seq
}

// TestVerifyChainOnStartAcceptsAnIntactLog covers the path an operator who
// turns the setting on takes on every start.
func TestVerifyChainOnStartAcceptsAnIntactLog(t *testing.T) {
	cfg := testConfig(t)
	st := newTestStore(t)
	rec := audit.NewRecorder(st, quietLogger())
	ctx := context.Background()

	if err := ensureTenant(ctx, cfg, st, rec, quietLogger()); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for range 5 {
		if err := rec.Success(ctx, audit.Event{
			TenantID:  cfg.TenantID(),
			EventType: audit.EventServiceStarted,
			ActorType: store.ActorSystem,
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	if err := verifyChainOnStart(ctx, cfg, rec, nil, quietLogger()); err != nil {
		t.Fatalf("an intact chain was refused: %v", err)
	}
}

// TestEnsureTenantReportsAStoreItCannotRead checks that a store failure stops
// the start rather than being read as "no tenant yet".
//
// The distinction matters: ErrNotFound means provision, and anything else means
// the database is not answering, which is not a reason to write to it.
func TestEnsureTenantReportsAStoreItCannotRead(t *testing.T) {
	cfg := testConfig(t)
	st := newTestStore(t)
	rec := audit.NewRecorder(st, quietLogger())

	// A cancelled context is the simplest way to make the read fail with
	// something that is not ErrNotFound.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ensureTenant(ctx, cfg, st, rec, quietLogger())
	if err == nil {
		t.Fatal("a store that cannot be read was treated as an unprovisioned tenant")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Errorf("the failure was reported as ErrNotFound: %v", err)
	}
}

// testLogger writes to w, so a test can assert on what the startup path said.
func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// auditEntriesOfType reads the chain back, in sequence order.
func auditEntriesOfType(t *testing.T, st store.Store, eventType string) []*store.AuditEntry {
	t.Helper()
	got, err := st.QueryAudit(t.Context(), "acme", store.AuditFilter{EventType: eventType, Limit: 50})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return got
}
