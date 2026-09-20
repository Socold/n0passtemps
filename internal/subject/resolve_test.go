package subject

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
)

// Resolve, Lookup and RevealRef are the three methods that touch the store, so
// the existing tests, which pass a nil store deliberately, could not reach
// them. They are also the three that decide what an integrating application's
// user reference becomes here: a lookup key derived under the pepper, and
// optionally a sealed copy that only the keyring opens.
//
// The property worth holding is that the plaintext reference never reaches a
// column. Everything else in this package exists to make a stored reference
// unusable to somebody who has the database and not the pepper.

const resolveTenant = "acme"

// newStoredService builds the service over a real store and a real sealer, so
// what lands in the row is what a deployment would write.
func newStoredService(t *testing.T, seal bool) (*Service, store.Store) {
	t.Helper()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keyring.json")
	key := make([]byte, kek.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	doc, err := json.Marshal(map[string]any{
		"current": 1,
		"keys":    map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := kek.LoadFileProvider(keyPath)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	st, err := sqlite.Open(sqlite.Options{DSN: filepath.Join(dir, "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err = st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = st.CreateTenant(context.Background(), &store.Tenant{
		ID: resolveTenant, Name: "Acme", Status: "active",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	t.Setenv(testPepperEnv, hex.EncodeToString(key32(3)))
	svc, err := New(config.Subject{
		PepperEnv: testPepperEnv, MaxRefLength: 256, SealReference: seal,
	}, st, envelope.NewSealer(keyring), func() time.Time {
		return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc, st
}

// TestResolveIsIdempotentForOneReference is what lets an application call it on
// every sign-in without accumulating subjects.
func TestResolveIsIdempotentForOneReference(t *testing.T) {
	svc, _ := newStoredService(t, false)
	ctx := context.Background()

	first, err := svc.Resolve(ctx, resolveTenant, "user@example.com", "User One")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := svc.Resolve(ctx, resolveTenant, "user@example.com", "User One")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("one reference produced two subjects, %s and %s", first.ID, second.ID)
	}

	other, err := svc.Resolve(ctx, resolveTenant, "someone-else@example.com", "Other")
	if err != nil {
		t.Fatalf("resolve other: %v", err)
	}
	if other.ID == first.ID {
		t.Error("two references resolved to one subject")
	}
}

// TestThePlaintextReferenceNeverReachesTheRow is the point of the whole design.
func TestThePlaintextReferenceNeverReachesTheRow(t *testing.T) {
	const ref = "someone@example.com"

	for name, seal := range map[string]bool{"sealed": true, "not sealed": false} {
		t.Run(name, func(t *testing.T) {
			svc, _ := newStoredService(t, seal)
			sub, err := svc.Resolve(context.Background(), resolveTenant, ref, "Someone")
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}

			if len(sub.RefHMAC) == 0 {
				t.Error("no lookup key was derived")
			}
			if string(sub.RefHMAC) == ref {
				t.Error("the lookup key is the reference itself")
			}
			// The sealed copy is ciphertext, so it must not contain the
			// plaintext either.
			if seal && len(sub.RefSealed) == 0 {
				t.Error("seal_reference is on and nothing was sealed")
			}
			if !seal && len(sub.RefSealed) != 0 {
				t.Error("seal_reference is off and a sealed copy was written anyway")
			}
			if string(sub.RefSealed) == ref {
				t.Error("the sealed copy is the plaintext reference")
			}
		})
	}
}

// TestLookupFindsWhatResolveWrote, and finds nothing for a reference that was
// never resolved.
func TestLookupFindsWhatResolveWrote(t *testing.T) {
	svc, _ := newStoredService(t, false)
	ctx := context.Background()

	created, err := svc.Resolve(ctx, resolveTenant, "known@example.com", "Known")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	found, err := svc.Lookup(ctx, resolveTenant, "known@example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("lookup found %s, want %s", found.ID, created.ID)
	}

	if _, err = svc.Lookup(ctx, resolveTenant, "never-seen@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown reference returned %v, want ErrNotFound", err)
	}

	// Another tenant's lookup of the same reference finds nothing, which is
	// the isolation every query in this repository is keyed on.
	if _, err = svc.Lookup(ctx, "other-tenant", "known@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant found the subject: %v", err)
	}

	// An invalid reference is refused before it reaches the store.
	if _, err = svc.Lookup(ctx, resolveTenant, ""); err == nil {
		t.Error("an empty reference was looked up")
	}
}

// TestRevealRefReturnsTheReferenceOnlyWhenItWasSealed is the article 15 path
// and its precondition.
func TestRevealRefReturnsTheReferenceOnlyWhenItWasSealed(t *testing.T) {
	const ref = "subject-of-access-request@example.com"

	sealed, _ := newStoredService(t, true)
	sub, err := sealed.Resolve(context.Background(), resolveTenant, ref, "Data Subject")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := sealed.RevealRef(sub)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if got != ref {
		t.Errorf("revealed %q, want %q", got, ref)
	}

	// With sealing off there is nothing to reveal, and the error says why
	// rather than reading as a decryption failure.
	plain, _ := newStoredService(t, false)
	unsealed, err := plain.Resolve(context.Background(), resolveTenant, ref, "Data Subject")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	_, err = plain.RevealRef(unsealed)
	if err == nil {
		t.Fatal("a subject with no sealed reference revealed one")
	}
	if !strings.Contains(err.Error(), "seal_reference") {
		t.Errorf("the error does not name the setting that would have sealed it:\n%v", err)
	}
}

// TestASealedReferenceDoesNotOpenUnderAnotherIdentity is the binding the
// envelope's associated data provides.
//
// A sealed reference moved into another subject's row, or another tenant's,
// has to fail to open rather than be disclosed under the wrong identity.
func TestASealedReferenceDoesNotOpenUnderAnotherIdentity(t *testing.T) {
	svc, _ := newStoredService(t, true)
	ctx := context.Background()

	alice, err := svc.Resolve(ctx, resolveTenant, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("resolve alice: %v", err)
	}
	bob, err := svc.Resolve(ctx, resolveTenant, "bob@example.com", "Bob")
	if err != nil {
		t.Fatalf("resolve bob: %v", err)
	}

	// Alice's ciphertext in Bob's row.
	forged := *bob
	forged.RefSealed = alice.RefSealed
	if _, err = svc.RevealRef(&forged); err == nil {
		t.Error("a sealed reference opened under another subject's identity")
	}

	// And in another tenant's.
	forged = *alice
	forged.TenantID = "other-tenant"
	if _, err = svc.RevealRef(&forged); err == nil {
		t.Error("a sealed reference opened under another tenant's identity")
	}
}

// TestDecodePepperIsTheExportedWrapper keeps the two in step.
func TestDecodePepperIsTheExportedWrapper(t *testing.T) {
	want := key32(5)
	got, err := DecodePepper("hex:" + hex.EncodeToString(want))
	if err != nil {
		t.Fatalf("DecodePepper: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the exported wrapper decoded something other than the unexported one")
	}
	if _, err = DecodePepper("too-short"); err == nil {
		t.Error("a pepper below the minimum was accepted")
	}
}
