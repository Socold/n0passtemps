package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

const (
	testTenant = "default"
	testRPID   = "login.example.test"
	testOrigin = "https://login.example.test"
)

// Two authenticator models, so the AAGUID policy has something to tell apart.
var (
	modelA = uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a")
	modelB = uuid.MustParse("ee882879-721c-4913-9775-3dfcce97072a")
)

// testClock is advanced by hand so that challenge expiry can be crossed
// without sleeping.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time      { return c.t }
func (c *testClock) add(d time.Duration) { c.t = c.t.Add(d) }

// fixture is the service over a real SQLite store.
//
// The store is the real one because the properties under test (single use,
// expiry, the counter compare-and-swap) are implemented by its conditional
// updates. A fake store would have to reimplement them, and the tests would
// then be checking the fake.
type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *sqlite.Store
	clock *testClock
	cfg   config.WebAuthn
	svc   *webauthn.Service
}

func newFixture(t *testing.T, tune ...func(*config.WebAuthn)) *fixture {
	t.Helper()

	cfg := config.Default().WebAuthn
	cfg.RPID = testRPID
	cfg.Origins = []string{testOrigin}
	for _, fn := range tune {
		fn(&cfg)
	}

	st, err := sqlite.Open(sqlite.Options{
		DSN:    filepath.Join(t.TempDir(), "webauthn.db"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	if err = st.Migrate(ctx); err != nil {
		t.Fatalf("migrate store: %v", err)
	}

	// The library enforces its own ceremony timeout against the wall clock, so
	// the injected clock starts at the present. Starting it elsewhere would
	// leave the two notions of "now" disagreeing inside one ceremony.
	clock := &testClock{t: time.Now().UTC().Truncate(time.Second)}

	err = st.CreateTenant(ctx, &store.Tenant{
		ID: testTenant, Name: "test", Status: "active",
		CreatedAt: clock.now(), UpdatedAt: clock.now(),
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	svc, err := webauthn.New(cfg, st, clock.now)
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	return &fixture{t: t, ctx: ctx, store: st, clock: clock, cfg: cfg, svc: svc}
}

// subject seeds an active subject. ref stands for the identifier the
// integrating application supplied, stored only as the store would hold it.
func (f *fixture) subject(ref, displayName string) *store.Subject {
	f.t.Helper()
	sum := sha256.Sum256([]byte(ref))
	sub, err := f.store.UpsertSubject(f.ctx, &store.Subject{
		ID:          uuid.NewString(),
		TenantID:    testTenant,
		RefHMAC:     sum[:],
		RefSealed:   []byte("sealed:" + ref),
		DisplayName: displayName,
		Status:      store.SubjectActive,
		CreatedAt:   f.clock.now(),
	})
	if err != nil {
		f.t.Fatalf("seed subject: %v", err)
	}
	return sub
}

func (f *fixture) reload(sub *store.Subject) *store.Subject {
	f.t.Helper()
	out, err := f.store.GetSubject(f.ctx, sub.TenantID, sub.ID)
	if err != nil {
		f.t.Fatalf("reload subject: %v", err)
	}
	return out
}

func (f *fixture) authenticator(model uuid.UUID) *virtualAuthenticator {
	return newVirtualAuthenticator(testOrigin, [16]byte(model))
}

// authenticatorAt is the same device behind a page served from somewhere else,
// which is what a relying party with more than one origin has to reason about.
func (f *fixture) authenticatorAt(origin string, model uuid.UUID) *virtualAuthenticator {
	return newVirtualAuthenticator(origin, [16]byte(model))
}

// register runs a whole registration ceremony and returns its result.
func (f *fixture) register(sub *store.Subject, a *virtualAuthenticator) (*store.Credential, error) {
	f.t.Helper()
	begin, err := f.svc.BeginRegistration(f.ctx, sub, "")
	if err != nil {
		return nil, err
	}
	resp, err := a.create(begin.Options)
	if err != nil {
		f.t.Fatalf("authenticator create: %v", err)
	}
	return f.svc.CompleteRegistration(f.ctx, sub, begin.ChallengeID, resp, "")
}

func (f *fixture) mustRegister(sub *store.Subject, a *virtualAuthenticator) *store.Credential {
	f.t.Helper()
	cred, err := f.register(sub, a)
	if err != nil {
		f.t.Fatalf("a genuine registration was refused: %v", err)
	}
	return cred
}

// assert runs a whole assertion ceremony and returns its result.
func (f *fixture) assert(sub *store.Subject, a *virtualAuthenticator) (*webauthn.AssertionOutcome, error) {
	f.t.Helper()
	begin, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		return nil, err
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		f.t.Fatalf("authenticator get: %v", err)
	}
	return f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
}

func (f *fixture) mustAssert(sub *store.Subject, a *virtualAuthenticator) *webauthn.AssertionOutcome {
	f.t.Helper()
	out, err := f.assert(sub, a)
	if err != nil {
		f.t.Fatalf("a genuine assertion was refused: %v", err)
	}
	return out
}

func (f *fixture) storedCredential(id string) *store.Credential {
	f.t.Helper()
	c, err := f.store.GetCredential(f.ctx, testTenant, id)
	if err != nil {
		f.t.Fatalf("read credential back: %v", err)
	}
	return c
}

// optionsField digs one value out of the options as a browser would receive
// them.
func optionsField(t *testing.T, options any, path ...string) any {
	t.Helper()
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("read options: %v", err)
	}
	for _, key := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("options have no object at %q in %v", key, path)
		}
		doc = m[key]
	}
	return doc
}

func optionsString(t *testing.T, options any, path ...string) string {
	t.Helper()
	s, ok := optionsField(t, options, path...).(string)
	if !ok || s == "" {
		t.Fatalf("options carry no string at %v", path)
	}
	return s
}

func TestRegistrationThenAssertionSucceedsAndRecordsWhatTheAuthenticatorReported(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)

	cred := f.mustRegister(sub, a)

	stored := f.storedCredential(cred.ID)
	if !bytes.Equal(stored.CredentialID, a.last.id) {
		t.Errorf("stored credential id %x is not the one the authenticator created, %x",
			stored.CredentialID, a.last.id)
	}
	if !bytes.Equal(stored.AAGUID, modelA[:]) {
		t.Errorf("stored AAGUID %x, want %x: the model policy and the binding hash both depend on it",
			stored.AAGUID, modelA[:])
	}
	if !stored.UserVerified {
		t.Error("the authenticator verified the user at registration but the stored credential says it did not")
	}
	if stored.SubjectID != sub.ID || stored.RPID != testRPID {
		t.Errorf("credential stored for subject %q and rp %q, want %q and %q",
			stored.SubjectID, stored.RPID, sub.ID, testRPID)
	}

	// The stored key has to be the key the device holds, compared as
	// coordinates so the check does not depend on the two sides agreeing on a
	// CBOR byte layout.
	var cose map[int]any
	if err := cbor.Unmarshal(stored.PublicKey, &cose); err != nil {
		t.Fatalf("stored public key is not a COSE key: %v", err)
	}
	wantX, wantY, err := coordinates(&a.last.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gotX, _ := cose[-2].([]byte)
	gotY, _ := cose[-3].([]byte)
	if !bytes.Equal(gotX, wantX) || !bytes.Equal(gotY, wantY) {
		t.Error("stored public key is not the key the authenticator created: assertions would be verified against somebody else's key")
	}

	out := f.mustAssert(sub, a)
	if !out.UserVerified {
		t.Error("the assertion carried the UV flag but the outcome reports the user as unverified")
	}
	if out.CloneWarning {
		t.Error("a first assertion with an advancing counter raised a clone warning")
	}
	if out.Credential == nil || out.Credential.ID != cred.ID {
		t.Error("the outcome does not name the credential that signed")
	}
}

func TestUserHandleIsDerivedFromInternalIDAndLeaksNoApplicationData(t *testing.T) {
	f := newFixture(t)
	const ref = "alice@example.test"
	const display = "Alice Liddell"
	const label = "Alice's laptop"
	sub := f.subject(ref, display)

	begin, err := f.svc.BeginRegistration(f.ctx, sub, label)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(optionsString(t, begin.Options, "publicKey", "user", "id"))
	if err != nil {
		t.Fatalf("user.id is not base64url: %v", err)
	}

	want := uuid.MustParse(sub.ID)
	if !bytes.Equal(handle, want[:]) {
		t.Errorf("user handle %x is not the internal subject id %x", handle, want[:])
	}
	if len(handle) == 0 || len(handle) > 64 {
		t.Errorf("user handle is %d bytes, the specification allows 1 to 64", len(handle))
	}

	// The handle is written to the authenticator and a discoverable credential
	// discloses it, so anything personal in it is published.
	for name, secret := range map[string][]byte{
		"application reference":        []byte(ref),
		"reference local part":         []byte("alice"),
		"display name":                 []byte(display),
		"ceremony label":               []byte(label),
		"reference HMAC":               sub.RefHMAC,
		"sealed application reference": sub.RefSealed,
	} {
		if bytes.Contains(bytes.ToLower(handle), bytes.ToLower(secret)) {
			t.Errorf("user handle contains the %s: personal data would be stored on the authenticator", name)
		}
	}
}

func TestRegistrationChallengeIsSingleUse(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)

	begin, err := f.svc.BeginRegistration(f.ctx, sub, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.CompleteRegistration(f.ctx, sub, begin.ChallengeID, resp, ""); err != nil {
		t.Fatalf("first completion refused: %v", err)
	}

	_, err = f.svc.CompleteRegistration(f.ctx, sub, begin.ChallengeID, resp, "")
	if !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("replayed registration completion returned %v, want ErrChallengeNotFound: a challenge must be single use", err)
	}
}

func TestAssertionChallengeIsSingleUseSoAReplayedAssertionIsRefused(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	cred := f.mustRegister(sub, a)

	begin, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp); err != nil {
		t.Fatalf("first completion refused: %v", err)
	}
	before := f.storedCredential(cred.ID)

	// The identical signed bytes, as an eavesdropper would resend them.
	_, err = f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
	if !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("replayed assertion returned %v, want ErrChallengeNotFound: a captured assertion must not authenticate twice", err)
	}
	after := f.storedCredential(cred.ID)
	if after.SignCount != before.SignCount || after.CloneWarning != before.CloneWarning {
		t.Error("a refused replay changed the stored credential")
	}
}

func TestExpiredChallengeIsRefused(t *testing.T) {
	ttl := config.Default().WebAuthn.ChallengeTTL.Duration

	t.Run("registration", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)

		begin, err := f.svc.BeginRegistration(f.ctx, sub, "")
		if err != nil {
			t.Fatal(err)
		}
		if want := f.clock.now().Add(ttl); !begin.ExpiresAt.Equal(want) {
			t.Errorf("ExpiresAt is %v, want %v from the injected clock", begin.ExpiresAt, want)
		}
		resp, err := a.create(begin.Options)
		if err != nil {
			t.Fatal(err)
		}

		// The boundary itself: a challenge is dead at its expiry instant, not
		// one tick later.
		f.clock.add(ttl)
		_, err = f.svc.CompleteRegistration(f.ctx, sub, begin.ChallengeID, resp, "")
		if !errors.Is(err, webauthn.ErrChallengeNotFound) {
			t.Errorf("registration completed at the expiry instant returned %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("assertion", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		f.mustRegister(sub, a)

		begin, err := f.svc.BeginAssertion(f.ctx, sub)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.get(begin.Options)
		if err != nil {
			t.Fatal(err)
		}

		f.clock.add(ttl + time.Second)
		_, err = f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
		if !errors.Is(err, webauthn.ErrChallengeNotFound) {
			t.Errorf("assertion completed after expiry returned %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("an unexpired challenge still completes", func(t *testing.T) {
		// Without this, the two cases above would also pass against a service
		// that refuses everything once the clock has moved.
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		f.mustRegister(sub, a)

		begin, err := f.svc.BeginAssertion(f.ctx, sub)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.get(begin.Options)
		if err != nil {
			t.Fatal(err)
		}
		f.clock.add(ttl - time.Second)
		if _, err := f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp); err != nil {
			t.Errorf("assertion completed one second before expiry was refused: %v", err)
		}
	})
}

func TestChallengeCannotCrossCeremonies(t *testing.T) {
	t.Run("a registration challenge cannot complete an assertion", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		f.mustRegister(sub, a)

		begin, err := f.svc.BeginRegistration(f.ctx, sub, "")
		if err != nil {
			t.Fatal(err)
		}

		// The strongest form of the attempt: a genuine signature from the
		// subject's own key over the registration challenge, so the only
		// thing wrong with the request is the ceremony the challenge belongs
		// to.
		crafted := map[string]any{"publicKey": map[string]any{
			"challenge": optionsString(t, begin.Options, "publicKey", "challenge"),
			"rpId":      testRPID,
			"allowCredentials": []map[string]any{{
				"type": "public-key",
				"id":   base64.RawURLEncoding.EncodeToString(a.last.id),
			}},
		}}
		resp, err := a.get(crafted)
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
		if !errors.Is(err, webauthn.ErrChallengeNotFound) {
			t.Errorf("assertion over a registration challenge returned %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("an assertion challenge cannot complete a registration", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		f.mustRegister(sub, f.authenticator(modelA))

		begin, err := f.svc.BeginAssertion(f.ctx, sub)
		if err != nil {
			t.Fatal(err)
		}

		// Take the user handle from a genuine creation request so the forged
		// one differs from it in the challenge alone.
		genuine, err := f.svc.BeginRegistration(f.ctx, sub, "")
		if err != nil {
			t.Fatal(err)
		}
		crafted := map[string]any{"publicKey": map[string]any{
			"challenge": optionsString(t, begin.Options, "publicKey", "challenge"),
			"rp":        map[string]any{"id": testRPID},
			"user":      map[string]any{"id": optionsString(t, genuine.Options, "publicKey", "user", "id")},
		}}
		intruder := f.authenticator(modelA)
		resp, err := intruder.create(crafted)
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.svc.CompleteRegistration(f.ctx, sub, begin.ChallengeID, resp, "")
		if !errors.Is(err, webauthn.ErrChallengeNotFound) {
			t.Errorf("registration over an assertion challenge returned %v, want ErrChallengeNotFound: "+
				"it would enrol a new authenticator from a login prompt", err)
		}
		creds, err := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 1 {
			t.Errorf("subject has %d credentials after the refused registration, want 1", len(creds))
		}
	})
}

func TestChallengeIssuedForOneSubjectCannotBeCompletedForAnother(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		f := newFixture(t)
		alice := f.subject("alice@example.test", "Alice")
		bob := f.subject("bob@example.test", "Bob")
		a := f.authenticator(modelA)

		begin, err := f.svc.BeginRegistration(f.ctx, alice, "")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.create(begin.Options)
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.svc.CompleteRegistration(f.ctx, bob, begin.ChallengeID, resp, "")
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Errorf("completing Alice's registration as Bob returned %v, want ErrCeremonyFailed: "+
				"it would graft an authenticator onto an account that never started a ceremony", err)
		}
		for _, sub := range []*store.Subject{alice, bob} {
			creds, err := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(creds) != 0 {
				t.Errorf("subject %s holds %d credentials after the refused completion, want 0", sub.DisplayName, len(creds))
			}
		}
	})

	t.Run("assertion", func(t *testing.T) {
		f := newFixture(t)
		alice := f.subject("alice@example.test", "Alice")
		bob := f.subject("bob@example.test", "Bob")
		aliceKey := f.authenticator(modelA)
		f.mustRegister(alice, aliceKey)
		f.mustRegister(bob, f.authenticator(modelA))

		begin, err := f.svc.BeginAssertion(f.ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := aliceKey.get(begin.Options)
		if err != nil {
			t.Fatal(err)
		}

		_, err = f.svc.CompleteAssertion(f.ctx, bob, begin.ChallengeID, resp)
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Errorf("presenting Alice's assertion as Bob returned %v, want ErrCeremonyFailed: "+
				"one user's signature must not authenticate another", err)
		}
	})
}

func TestResponseNotBoundToThisRelyingPartyIsRefused(t *testing.T) {
	// Each case is a response that is genuine in every respect except the one
	// named, so a refusal can only come from the check under test.
	cases := []struct {
		name          string
		sabotage      func(*virtualAuthenticator)
		assertionOnly bool
		why           string
	}{
		{
			name:     "wrong origin",
			sabotage: func(a *virtualAuthenticator) { a.origin = "https://login.example.test.evil.example" },
			why:      "a response collected by a page on another origin is a phishing relay",
		},
		{
			name: "wrong rpId hash",
			sabotage: func(a *virtualAuthenticator) {
				sum := sha256.Sum256([]byte("evil.example"))
				a.rpIDHashOverride = sum[:]
			},
			why: "authenticator data scoped to another relying party proves nothing here",
		},
		{
			name:          "tampered signature",
			sabotage:      func(a *virtualAuthenticator) { a.tamperSignature = true },
			assertionOnly: true,
			why:           "the signature is the only proof of possession",
		},
		{
			name:     "user verification absent while required",
			sabotage: func(a *virtualAuthenticator) { a.userVerified = false },
			why:      "with user_verification = required a stolen key alone must not authenticate",
		},
		{
			name:     "user presence absent",
			sabotage: func(a *virtualAuthenticator) { a.userPresent = false; a.userVerified = false },
			why:      "a response produced without a user gesture may have been produced by malware",
		},
	}

	for _, tc := range cases {
		if !tc.assertionOnly {
			t.Run(tc.name+"/registration", func(t *testing.T) {
				f := newFixture(t)
				sub := f.subject("alice@example.test", "Alice")
				a := f.authenticator(modelA)
				tc.sabotage(a)

				_, err := f.register(sub, a)
				if !errors.Is(err, webauthn.ErrCeremonyFailed) {
					t.Errorf("registration returned %v, want ErrCeremonyFailed: %s", err, tc.why)
				}
				creds, lerr := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
				if lerr != nil {
					t.Fatal(lerr)
				}
				if len(creds) != 0 {
					t.Errorf("a refused registration still stored %d credential(s)", len(creds))
				}
			})
		}

		t.Run(tc.name+"/assertion", func(t *testing.T) {
			f := newFixture(t)
			sub := f.subject("alice@example.test", "Alice")
			a := f.authenticator(modelA)
			cred := f.mustRegister(sub, a)
			f.mustAssert(sub, a)
			before := f.storedCredential(cred.ID)

			tc.sabotage(a)
			_, err := f.assert(sub, a)
			if !errors.Is(err, webauthn.ErrCeremonyFailed) {
				t.Errorf("assertion returned %v, want ErrCeremonyFailed: %s", err, tc.why)
			}
			after := f.storedCredential(cred.ID)
			if after.SignCount != before.SignCount {
				t.Errorf("a refused assertion moved the stored counter from %d to %d", before.SignCount, after.SignCount)
			}
		})
	}
}

func TestOutcomeReportsUserVerificationOfThisAssertionNotOfAnEarlierOne(t *testing.T) {
	// With "preferred" an assertion without UV is accepted, and the caller
	// relies on the outcome to decide whether it counts as one factor or two.
	f := newFixture(t, func(c *config.WebAuthn) { c.UserVerification = "preferred" })
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	if out := f.mustAssert(sub, a); !out.UserVerified {
		t.Error("an assertion carrying the UV flag was reported as unverified")
	}

	a.userVerified = false
	out := f.mustAssert(sub, a)
	if out.UserVerified {
		t.Error("SUSPECTED SERVICE BUG: an assertion WITHOUT the UV flag was reported as UserVerified. " +
			"CompleteAssertion reads validated.Flags.UserVerified, which the library latches from the stored " +
			"credential record; a possession-only assertion is then presented to the caller as a verified one")
	}
}

func TestSignatureCounter(t *testing.T) {
	t.Run("an increasing counter advances the stored value without a warning", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)

		for want := uint32(1); want <= 3; want++ {
			out := f.mustAssert(sub, a)
			if out.CloneWarning {
				t.Errorf("assertion %d: an advancing counter raised a clone warning", want)
			}
			if out.PreviousSignCount != want-1 || out.NewSignCount != want {
				t.Errorf("assertion %d: outcome reports counter %d -> %d, want %d -> %d",
					want, out.PreviousSignCount, out.NewSignCount, want-1, want)
			}
			stored := f.storedCredential(cred.ID)
			if stored.SignCount != want {
				t.Errorf("assertion %d: stored counter is %d, want %d", want, stored.SignCount, want)
			}
			if stored.CloneWarning {
				t.Errorf("assertion %d: credential marked as cloned", want)
			}
			if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(f.clock.now()) {
				t.Errorf("assertion %d: LastUsedAt is %v, want %v from the injected clock",
					want, stored.LastUsedAt, f.clock.now())
			}
			f.clock.add(time.Minute)
		}

		a.forceCounter(1000)
		f.mustAssert(sub, a)
		if got := f.storedCredential(cred.ID).SignCount; got != 1000 {
			t.Errorf("stored counter is %d after a jump to 1000: a counter may advance by any positive amount", got)
		}
	})

	t.Run("a counter that does not advance warns and marks the credential but still succeeds", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)
		f.mustAssert(sub, a)
		f.mustAssert(sub, a)

		a.freezeCounter = true
		out, err := f.assert(sub, a)
		if err != nil {
			t.Fatalf("an assertion with a stuck counter was refused (%v): the signal has innocent causes "+
				"and is meant to alert, not to lock the user out", err)
		}
		if !out.CloneWarning {
			t.Error("a counter that failed to advance raised no CloneWarning: this is the only clone signal WebAuthn offers")
		}
		stored := f.storedCredential(cred.ID)
		if !stored.CloneWarning {
			t.Error("the credential was not marked after a stuck counter, so the warning is lost once the response is sent")
		}
		if stored.SignCount != 2 {
			t.Errorf("stored counter is %d, want 2: a stuck counter must not move it", stored.SignCount)
		}
	})

	t.Run("a counter that goes backwards warns and does not lower the stored value", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)
		a.forceCounter(50)
		f.mustAssert(sub, a)

		a.forceCounter(7)
		out, err := f.assert(sub, a)
		if err != nil {
			t.Fatalf("an assertion with a regressed counter was refused: %v", err)
		}
		if !out.CloneWarning {
			t.Error("a counter that went backwards raised no CloneWarning")
		}
		if got := f.storedCredential(cred.ID).SignCount; got != 50 {
			t.Errorf("stored counter is %d, want 50: lowering it would let the older clone go unnoticed afterwards", got)
		}
	})

	t.Run("an authenticator that always reports zero never warns", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		a.freezeCounter = true
		cred := f.mustRegister(sub, a)

		for i := 1; i <= 3; i++ {
			out := f.mustAssert(sub, a)
			if out.CloneWarning {
				t.Errorf("assertion %d: a counter-less authenticator raised a clone warning; "+
					"most passkeys report zero and would alert on every login", i)
			}
		}
		stored := f.storedCredential(cred.ID)
		if stored.CloneWarning || stored.SignCount != 0 {
			t.Errorf("counter-less credential stored as count=%d warning=%v, want 0 and false",
				stored.SignCount, stored.CloneWarning)
		}
	})
}

func TestUseOfACounterlessCredentialIsStillRecorded(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	a.freezeCounter = true
	cred := f.mustRegister(sub, a)

	f.clock.add(time.Minute)
	f.mustAssert(sub, a)

	stored := f.storedCredential(cred.ID)
	if stored.LastUsedAt == nil {
		t.Fatal("SUSPECTED SERVICE BUG: LastUsedAt is unset after a successful assertion from a counter-less " +
			"authenticator. CompleteAssertion calls AdvanceSignCount(prev=0, next=0), which the store refuses " +
			"with ErrStaleWrite before writing, and the service discards that error; dormant-credential " +
			"review then sees every passkey as never used")
	}
	if !stored.LastUsedAt.Equal(f.clock.now()) {
		t.Errorf("LastUsedAt is %v, want %v from the injected clock", stored.LastUsedAt, f.clock.now())
	}
}

func TestSameCounterFromTwoSeparateChallengesWarnsOnTheSecond(t *testing.T) {
	// Two copies of one private key, each answering its own challenge and each
	// reporting the counter it last saw. Single use of the challenge cannot
	// catch this; only the stored counter can.
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	cred := f.mustRegister(sub, a)

	first, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}

	a.forceCounter(5)
	respOriginal, err := a.get(first.Options)
	if err != nil {
		t.Fatal(err)
	}
	a.forceCounter(5)
	respClone, err := a.get(second.Options)
	if err != nil {
		t.Fatal(err)
	}

	out, err := f.svc.CompleteAssertion(f.ctx, sub, first.ChallengeID, respOriginal)
	if err != nil {
		t.Fatalf("first assertion refused: %v", err)
	}
	if out.CloneWarning {
		t.Error("the first use of counter 5 raised a clone warning")
	}

	out, err = f.svc.CompleteAssertion(f.ctx, sub, second.ChallengeID, respClone)
	if err != nil {
		t.Fatalf("second assertion refused (%v): the counter signal is meant to alert, not refuse", err)
	}
	if !out.CloneWarning {
		t.Error("a second assertion carrying the same counter value 5 raised no CloneWarning: " +
			"two devices holding one key would go unnoticed")
	}
	stored := f.storedCredential(cred.ID)
	if !stored.CloneWarning || stored.SignCount != 5 {
		t.Errorf("credential stored as count=%d warning=%v, want 5 and true", stored.SignCount, stored.CloneWarning)
	}
}

func TestAuthenticatorModelPolicy(t *testing.T) {
	t.Run("a model outside the allow list is refused", func(t *testing.T) {
		f := newFixture(t, func(c *config.WebAuthn) { c.AllowedAAGUIDs = []string{modelA.String()} })
		sub := f.subject("alice@example.test", "Alice")

		_, err := f.register(sub, f.authenticator(modelB))
		if !errors.Is(err, webauthn.ErrAuthenticatorModel) {
			t.Errorf("registering model B under an allow list naming only model A returned %v, want ErrAuthenticatorModel", err)
		}
		creds, lerr := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
		if lerr != nil {
			t.Fatal(lerr)
		}
		if len(creds) != 0 {
			t.Errorf("a refused model still left %d stored credential(s)", len(creds))
		}

		if _, err := f.register(sub, f.authenticator(modelA)); err != nil {
			t.Errorf("the allowed model was refused: %v", err)
		}
	})

	t.Run("the allow list is not case sensitive", func(t *testing.T) {
		upper := bytes.ToUpper([]byte(modelA.String()))
		f := newFixture(t, func(c *config.WebAuthn) { c.AllowedAAGUIDs = []string{string(upper)} })
		sub := f.subject("alice@example.test", "Alice")
		if _, err := f.register(sub, f.authenticator(modelA)); err != nil {
			t.Errorf("an allow list written in upper case refused its own model: %v", err)
		}
	})

	t.Run("a blocked model is refused and others are not", func(t *testing.T) {
		f := newFixture(t, func(c *config.WebAuthn) { c.BlockedAAGUIDs = []string{modelB.String()} })
		sub := f.subject("alice@example.test", "Alice")

		_, err := f.register(sub, f.authenticator(modelB))
		if !errors.Is(err, webauthn.ErrAuthenticatorModel) {
			t.Errorf("registering a blocked model returned %v, want ErrAuthenticatorModel: "+
				"the block list is how a flawed device is withdrawn", err)
		}
		if _, err := f.register(sub, f.authenticator(modelA)); err != nil {
			t.Errorf("a model that is not blocked was refused: %v", err)
		}
	})
}

func TestRequiredAttestationRefusesFormatNone(t *testing.T) {
	f := newFixture(t, func(c *config.WebAuthn) {
		c.RequireAttestation = true
		c.AttestationPreference = "direct"
		c.AllowedAAGUIDs = []string{modelA.String()}
	})
	sub := f.subject("alice@example.test", "Alice")

	// The AAGUID is on the allow list, so the attestation requirement is the
	// only thing that can refuse this. With fmt "none" the AAGUID is an
	// unauthenticated claim, which is exactly why it must not be enough.
	_, err := f.register(sub, f.authenticator(modelA))
	if !errors.Is(err, webauthn.ErrAuthenticatorModel) {
		t.Errorf("registration with fmt \"none\" under require_attestation returned %v, want ErrAuthenticatorModel: "+
			"otherwise any authenticator satisfies the setting by declining to attest", err)
	}
	creds, lerr := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(creds) != 0 {
		t.Errorf("an unattested credential was stored despite require_attestation (%d found)", len(creds))
	}
}

// TestAForgedAttestationWithABorrowedAAGUIDRegisters pins what the AAGUID allow
// list is, so that nobody mistakes it for what it is not.
//
// The device here is software. It mints an attestation certificate for itself,
// puts model A's AAGUID in the certificate and in the authenticator data, and
// signs a well-formed packed statement. The library reports attestation type
// "basic_full", because with no trust anchors the format's verification
// procedure has nothing to compare the certificate against, and the allow list
// sees a model it was told to accept. The registration succeeds, and it should:
// an allow list filters an inventory, it does not authenticate one.
//
// The control that would refuse this is a metadata BLOB, which the
// configuration validator now requires before require_attestation can be turned
// on. Without one, a deployment that wants assurance about which devices are in
// use has to get it from procurement rather than from this setting.
func TestAForgedAttestationWithABorrowedAAGUIDRegisters(t *testing.T) {
	f := newFixture(t, func(c *config.WebAuthn) {
		c.AttestationPreference = "direct"
		c.AllowedAAGUIDs = []string{modelA.String()}
	})
	sub := f.subject("alice@example.test", "Alice")

	a := f.authenticator(modelA)
	a.forgePackedAttestation = true

	cred, err := f.register(sub, a)
	if err != nil {
		t.Fatalf("the forged attestation was refused by %v. If a check was added that refuses "+
			"it without a metadata blob, this test is the one to rewrite: say what the new "+
			"check is rather than deleting the record of what the allow list does not do", err)
	}
	if cred.AttestationType != store.AttestationBasic {
		t.Errorf("stored attestation type = %q, want %q: the library reports a packed "+
			"statement with a certificate chain as full basic attestation, whatever signed it",
			cred.AttestationType, store.AttestationBasic)
	}
	if !bytes.Equal(cred.AAGUID, modelA[:]) {
		t.Errorf("stored AAGUID = %x, want the borrowed %x", cred.AAGUID, modelA[:])
	}
}

func TestCredentialLimitExcludeListAndCrossSubjectUniqueness(t *testing.T) {
	f := newFixture(t, func(c *config.WebAuthn) { c.MaxCredentialsPerSubject = 2 })
	alice := f.subject("alice@example.test", "Alice")
	first := f.authenticator(modelA)
	firstCred := f.mustRegister(alice, first)

	begin, err := f.svc.BeginRegistration(f.ctx, alice, "")
	if err != nil {
		t.Fatal(err)
	}
	excluded, _ := optionsField(t, begin.Options, "publicKey", "excludeCredentials").([]any)
	var found bool
	for _, e := range excluded {
		d, _ := e.(map[string]any)
		if d["id"] == base64.RawURLEncoding.EncodeToString(firstCred.CredentialID) {
			found = true
		}
	}
	if !found {
		t.Errorf("excludeCredentials %v does not name the credential already enrolled: "+
			"the same authenticator could be enrolled twice", excluded)
	}
	if _, err = first.create(begin.Options); !errors.Is(err, errCredentialExcluded) {
		t.Errorf("the enrolled authenticator answered a creation request that excludes it (err=%v)", err)
	}

	second := f.authenticator(modelA)
	resp, err := second.create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.CompleteRegistration(f.ctx, alice, begin.ChallengeID, resp, ""); err != nil {
		t.Fatalf("second credential, within the limit of 2, was refused: %v", err)
	}

	_, err = f.svc.BeginRegistration(f.ctx, alice, "")
	if !errors.Is(err, webauthn.ErrTooManyCredentials) {
		t.Errorf("a third registration under a limit of 2 returned %v, want ErrTooManyCredentials: "+
			"a compromised API key could otherwise add authenticators without bound", err)
	}

	// A hostile client replays Alice's credential id under its own account,
	// with its own key behind it.
	bob := f.subject("bob@example.test", "Bob")
	intruder := f.authenticator(modelA)
	intruder.nextCredentialID = firstCred.CredentialID
	_, err = f.register(bob, intruder)
	if !errors.Is(err, webauthn.ErrCredentialExists) {
		t.Errorf("registering Alice's credential id under Bob returned %v, want ErrCredentialExists: "+
			"a credential id must identify one subject per relying party", err)
	}
	creds, err := f.store.ListCredentials(f.ctx, testTenant, bob.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Errorf("Bob holds %d credential(s) after the refused registration, want 0", len(creds))
	}
	if stored := f.storedCredential(firstCred.ID); stored.SubjectID != alice.ID || !bytes.Equal(stored.PublicKey, firstCred.PublicKey) {
		t.Error("the refused registration altered Alice's credential")
	}
}

// TestCeremoniesBegunTogetherCannotAllStoreACredential covers the cap that
// BeginRegistration alone does not enforce.
//
// The count it reads is taken at the start of a ceremony the caller may hold
// open for as long as the challenge lives, so three ceremonies begun while the
// subject holds nothing are all allowed, and three completions would leave the
// subject holding three under a limit of two.
func TestCeremoniesBegunTogetherCannotAllStoreACredential(t *testing.T) {
	f := newFixture(t, func(c *config.WebAuthn) { c.MaxCredentialsPerSubject = 2 })
	sub := f.subject("alice@example.test", "Alice")

	type pending struct {
		challengeID string
		response    []byte
	}
	var open []pending
	for i := 0; i < 3; i++ {
		begin, err := f.svc.BeginRegistration(f.ctx, sub, "")
		if err != nil {
			t.Fatalf("ceremony %d was refused at begin: all three are begun while the subject "+
				"holds nothing, so all three pass the check there: %v", i, err)
		}
		resp, err := f.authenticator(modelA).create(begin.Options)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, pending{challengeID: begin.ChallengeID, response: resp})
	}

	for i, p := range open[:2] {
		if _, err := f.svc.CompleteRegistration(f.ctx, sub, p.challengeID, p.response, ""); err != nil {
			t.Fatalf("completion %d, within the limit of 2, was refused: %v", i, err)
		}
	}

	_, err := f.svc.CompleteRegistration(f.ctx, sub, open[2].challengeID, open[2].response, "")
	if !errors.Is(err, webauthn.ErrTooManyCredentials) {
		t.Errorf("the third completion returned %v, want ErrTooManyCredentials", err)
	}
	creds, err := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Errorf("the subject holds %d credentials under a limit of 2", len(creds))
	}
}

// TestSignCountRegressionIsRefusedOnlyUnderThePolicy covers the optional
// refusal and, as much as that, what it deliberately leaves alone.
func TestSignCountRegressionIsRefusedOnlyUnderThePolicy(t *testing.T) {
	t.Run("a counter that went backwards is refused", func(t *testing.T) {
		f := newFixture(t, func(c *config.WebAuthn) { c.RefuseSignCountRegression = true })
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)

		a.forceCounter(50)
		f.mustAssert(sub, a)

		a.forceCounter(7)
		if _, err := f.assert(sub, a); !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Fatalf("a counter that went from 50 to 7 returned %v, want ErrCeremonyFailed", err)
		}

		stored := f.storedCredential(cred.ID)
		if !stored.CloneWarning {
			t.Error("the refusal left no clone warning on the credential, so the only durable " +
				"record of what happened is gone once the response is sent")
		}
		if stored.SignCount != 50 {
			t.Errorf("stored counter is %d, want 50: a refused assertion must not move it", stored.SignCount)
		}
	})

	t.Run("a counter that merely stalled still succeeds", func(t *testing.T) {
		// This is what every counter-less passkey does on every assertion, and
		// what a policy that refused it would lock out.
		f := newFixture(t, func(c *config.WebAuthn) { c.RefuseSignCountRegression = true })
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		f.mustRegister(sub, a)

		a.forceCounter(50)
		f.mustAssert(sub, a)

		a.forceCounter(50)
		out, err := f.assert(sub, a)
		if err != nil {
			t.Fatalf("an assertion whose counter stalled at its stored value was refused: %v", err)
		}
		if !out.CloneWarning {
			t.Error("a stalled counter raised no clone warning")
		}
	})

	t.Run("the default is unchanged", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		f.mustRegister(sub, a)

		a.forceCounter(50)
		f.mustAssert(sub, a)

		a.forceCounter(7)
		if _, err := f.assert(sub, a); err != nil {
			t.Fatalf("a regressed counter was refused with the policy off (%v): turning the "+
				"policy on has to be what changes the behaviour", err)
		}
	})
}

func TestRevokedCredentialCannotAssert(t *testing.T) {
	t.Run("no ceremony can begin once the only credential is revoked", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)
		f.mustAssert(sub, a)

		if err := f.store.RevokeCredential(f.ctx, testTenant, cred.ID, "lost", f.clock.now()); err != nil {
			t.Fatal(err)
		}
		_, err := f.svc.BeginAssertion(f.ctx, sub)
		if !errors.Is(err, webauthn.ErrNoCredentials) {
			t.Errorf("BeginAssertion after revocation returned %v, want ErrNoCredentials", err)
		}
	})

	t.Run("a ceremony begun before the revocation cannot complete after it", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		a := f.authenticator(modelA)
		cred := f.mustRegister(sub, a)

		begin, err := f.svc.BeginAssertion(f.ctx, sub)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.get(begin.Options)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.store.RevokeCredential(f.ctx, testTenant, cred.ID, "lost", f.clock.now()); err != nil {
			t.Fatal(err)
		}

		out, err := f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
		if err == nil {
			t.Fatalf("an assertion from a revoked credential succeeded (outcome %+v): "+
				"revocation must take effect on ceremonies already in flight", out)
		}
		if !errors.Is(err, webauthn.ErrNoCredentials) && !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Errorf("revoked credential refused with %v, want ErrNoCredentials or ErrCeremonyFailed", err)
		}
	})

	t.Run("a revoked credential is refused while a sibling stays usable", func(t *testing.T) {
		f := newFixture(t)
		sub := f.subject("alice@example.test", "Alice")
		lost := f.authenticator(modelA)
		kept := f.authenticator(modelA)
		lostCred := f.mustRegister(sub, lost)
		f.mustRegister(sub, kept)

		if err := f.store.RevokeCredential(f.ctx, testTenant, lostCred.ID, "lost", f.clock.now()); err != nil {
			t.Fatal(err)
		}

		begin, err := f.svc.BeginAssertion(f.ctx, sub)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lost.get(begin.Options); !errors.Is(err, errNoMatchingCredential) {
			t.Errorf("the allow list still offers the revoked credential (err=%v)", err)
		}

		// The thief ignores the allow list and signs the challenge anyway.
		crafted := map[string]any{"publicKey": map[string]any{
			"challenge": optionsString(t, begin.Options, "publicKey", "challenge"),
			"rpId":      testRPID,
			"allowCredentials": []map[string]any{{
				"type": "public-key",
				"id":   base64.RawURLEncoding.EncodeToString(lost.last.id),
			}},
		}}
		resp, err := lost.get(crafted)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp)
		if !errors.Is(err, webauthn.ErrCeremonyFailed) {
			t.Errorf("a revoked credential signing a live challenge returned %v, want ErrCeremonyFailed", err)
		}

		if _, err := f.assert(sub, kept); err != nil {
			t.Errorf("the credential that was not revoked stopped working: %v", err)
		}
	})
}

func TestLockedSubjectCannotBeginOrCompleteEitherCeremony(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	// Both ceremonies are started while the subject is still active, so the
	// completions below are refused for the lock and for nothing else.
	reg, err := f.svc.BeginRegistration(f.ctx, sub, "")
	if err != nil {
		t.Fatal(err)
	}
	regResp, err := f.authenticator(modelA).create(reg.Options)
	if err != nil {
		t.Fatal(err)
	}
	login, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	loginResp, err := a.get(login.Options)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.store.SetSubjectStatus(f.ctx, testTenant, sub.ID, store.SubjectLocked); err != nil {
		t.Fatal(err)
	}
	locked := f.reload(sub)
	if locked.Active() {
		t.Fatal("the subject is still active after being locked")
	}

	if _, err = f.svc.BeginRegistration(f.ctx, locked, ""); !errors.Is(err, webauthn.ErrSubjectInactive) {
		t.Errorf("BeginRegistration for a locked subject returned %v, want ErrSubjectInactive", err)
	}
	if _, err = f.svc.BeginAssertion(f.ctx, locked); !errors.Is(err, webauthn.ErrSubjectInactive) {
		t.Errorf("BeginAssertion for a locked subject returned %v, want ErrSubjectInactive", err)
	}
	if _, err = f.svc.CompleteRegistration(f.ctx, locked, reg.ChallengeID, regResp, ""); !errors.Is(err, webauthn.ErrSubjectInactive) {
		t.Errorf("CompleteRegistration for a locked subject returned %v, want ErrSubjectInactive: "+
			"a lock must stop an attacker enrolling a key through a ceremony opened beforehand", err)
	}
	if _, err = f.svc.CompleteAssertion(f.ctx, locked, login.ChallengeID, loginResp); !errors.Is(err, webauthn.ErrSubjectInactive) {
		t.Errorf("CompleteAssertion for a locked subject returned %v, want ErrSubjectInactive: "+
			"a lock must stop a login through a ceremony opened beforehand", err)
	}

	creds, err := f.store.ListCredentials(f.ctx, testTenant, sub.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Errorf("locked subject holds %d credentials, want the 1 enrolled before the lock", len(creds))
	}
}

// discoverableAssert runs a whole usernameless ceremony and reports which
// subject came back.
func (f *fixture) discoverableAssert(a *virtualAuthenticator) (*store.Subject, *webauthn.AssertionOutcome, error) {
	f.t.Helper()
	begin, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		return nil, nil, err
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		f.t.Fatalf("authenticator get: %v", err)
	}
	return f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, begin.ChallengeID, resp)
}

func TestDiscoverableAssertionNamesTheSubjectItResolved(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	cred := f.mustRegister(sub, a)

	got, out, err := f.discoverableAssert(a)
	if err != nil {
		t.Fatalf("a genuine usernameless assertion was refused: %v", err)
	}
	if got.ID != sub.ID {
		t.Errorf("resolved subject = %q, want %q", got.ID, sub.ID)
	}
	if out.Credential.ID != cred.ID {
		t.Errorf("outcome credential = %q, want the one that was used, %q", out.Credential.ID, cred.ID)
	}
	if !out.UserVerified {
		t.Error("user verification was required, so the outcome must report it")
	}
}

func TestDiscoverableAssertionOffersNoAllowList(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	f.mustRegister(sub, f.authenticator(modelA))

	begin, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	// An allow list would defeat the point: the browser would learn which
	// credentials this subject holds before anyone proved anything, and the
	// caller would have had to name the subject to build it.
	if got := optionsField(t, begin.Options, "publicKey", "allowCredentials"); got != nil {
		t.Errorf("allowCredentials = %v, want absent", got)
	}
	if got := optionsField(t, begin.Options, "publicKey", "userVerification"); got != "required" {
		t.Errorf("userVerification = %v, want \"required\": a usernameless ceremony is "+
			"scoped to nothing, so possession alone must not sign anyone in", got)
	}
}

func TestDiscoverableAssertionRefusesAPossessionOnlyResponse(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	// A key whose PIN was never entered, which is what a found or stolen
	// authenticator produces.
	a.userVerified = false

	if _, _, err := f.discoverableAssert(a); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("possession-only usernameless assertion returned %v, want ErrCeremonyFailed", err)
	}
}

func TestDiscoverableAssertionRefusesARevokedCredential(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	cred := f.mustRegister(sub, a)

	if err := f.store.RevokeCredential(f.ctx, testTenant, cred.ID, "lost", f.clock.now()); err != nil {
		t.Fatal(err)
	}

	// The property, not the mechanism: a revoked passkey signs in to nothing,
	// even when nobody had to name its owner. It is refused twice over, by the
	// explicit check on the resolved credential and again by the store, whose
	// counter and last-used writes both require revoked_at to be null. This
	// test would still pass with the explicit check removed, which is why the
	// reason for keeping it is written where the check is rather than here.
	if _, _, err := f.discoverableAssert(a); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("revoked credential returned %v, want ErrCeremonyFailed", err)
	}
}

func TestDiscoverableAssertionRefusesAnInactiveSubject(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	if err := f.store.SetSubjectStatus(f.ctx, testTenant, sub.ID, store.SubjectLocked); err != nil {
		t.Fatal(err)
	}

	if _, _, err := f.discoverableAssert(a); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("locked subject returned %v, want ErrCeremonyFailed", err)
	}
}

func TestDiscoverableAssertionRefusesAMismatchedUserHandle(t *testing.T) {
	f := newFixture(t)
	alice := f.subject("alice@example.test", "Alice")
	bob := f.subject("bob@example.test", "Bob")
	a := f.authenticator(modelA)
	f.mustRegister(alice, a)
	bobAuth := f.authenticator(modelB)
	f.mustRegister(bob, bobAuth)

	begin, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}

	// Alice's own credential, presented with Bob's user handle. What this
	// pins is that the substitution gains nothing: the subject is resolved
	// from the credential, so no handle can make the service believe Alice is
	// Bob, and a response whose two halves disagree is refused outright rather
	// than half ignored. The library compares the handle as well, so this
	// passes with the service's own comparison removed; the comparison stays
	// because the property should not rest on one dependency.
	var body map[string]any
	if err = json.Unmarshal(resp, &body); err != nil {
		t.Fatal(err)
	}
	bobHandle := userHandleOf(t, bob.ID)
	inner, ok := body["response"].(map[string]any)
	if !ok {
		t.Fatalf("the authenticator's response has no object under \"response\": %T", body["response"])
	}
	inner["userHandle"] = base64.RawURLEncoding.EncodeToString(bobHandle)
	tampered, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, begin.ChallengeID, tampered); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("mismatched user handle returned %v, want ErrCeremonyFailed", err)
	}
}

func TestNamedAndDiscoverableChallengesAreNotInterchangeable(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	// A challenge issued for a named subject, completed through the
	// usernameless route. The two ceremonies differ in the allow list and in
	// the user-verification requirement, which is exactly the pair an
	// attacker would want to choose between.
	named, err := f.svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(named.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, named.ChallengeID, resp); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("named challenge through the usernameless route returned %v, want ErrCeremonyFailed", err)
	}

	// And the reverse.
	disc, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := a.get(disc.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CompleteAssertion(f.ctx, sub, disc.ChallengeID, resp2); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Errorf("usernameless challenge through the named route returned %v, want ErrCeremonyFailed", err)
	}
}

func TestDiscoverableAssertionChallengeIsSingleUse(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	begin, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, begin.ChallengeID, resp); err != nil {
		t.Fatalf("first completion refused: %v", err)
	}
	if _, _, err := f.svc.CompleteDiscoverableAssertion(f.ctx, testTenant, begin.ChallengeID, resp); !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("replayed usernameless completion returned %v, want ErrChallengeNotFound", err)
	}
}

func TestDiscoverableAssertionIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	begin, err := f.svc.BeginDiscoverableAssertion(f.ctx, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}

	// The credential lookup is the only thing that names the subject, so it
	// must not reach across tenants. A challenge belonging to one tenant is
	// not found under another, which refuses this before the lookup runs.
	if _, _, err := f.svc.CompleteDiscoverableAssertion(f.ctx, "other-tenant", begin.ChallengeID, resp); err == nil {
		t.Error("a usernameless completion succeeded under a different tenant")
	}
}

// userHandleOf derives the handle the service stores for a subject, so a test
// can present a handle belonging to somebody else.
func userHandleOf(t *testing.T, subjectID string) []byte {
	t.Helper()
	id, err := uuid.Parse(subjectID)
	if err != nil {
		t.Fatalf("subject identifier is not a uuid: %v", err)
	}
	return append([]byte(nil), id[:]...)
}

// revokingStore revokes a credential at the moment its clone warning is
// recorded, which is the instant between the listing an assertion starts with
// and the write it ends with.
type revokingStore struct {
	store.Store
	now func() time.Time
}

func (r *revokingStore) MarkCloneWarning(ctx context.Context, tenantID, id string) error {
	if err := r.Store.RevokeCredential(ctx, tenantID, id, "revoked mid-ceremony", r.now()); err != nil {
		return err
	}
	return r.Store.MarkCloneWarning(ctx, tenantID, id)
}

// TestACredentialRevokedDuringAStuckCounterAssertionDoesNotAssert closes the
// one branch that let a revocation go unnoticed.
//
// The counterless branch and the advancing branch both refuse a credential that
// was revoked while the ceremony ran. The branch for a counter that did not
// advance ignored it, and that is the branch a copied key lands in.
func TestACredentialRevokedDuringAStuckCounterAssertionDoesNotAssert(t *testing.T) {
	f := newFixture(t)
	sub := f.subject("alice@example.test", "Alice")
	a := f.authenticator(modelA)
	f.mustRegister(sub, a)

	// Establish a stored counter of 5, then answer a second challenge with the
	// same value, which is what a copy of the key does.
	a.forceCounter(5)
	f.mustAssert(sub, a)
	a.forceCounter(5)

	svc, err := webauthn.New(f.cfg, &revokingStore{Store: f.store, now: f.clock.now}, f.clock.now)
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	begin, err := svc.BeginAssertion(f.ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.get(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteAssertion(f.ctx, sub, begin.ChallengeID, resp); !errors.Is(err, webauthn.ErrCeremonyFailed) {
		t.Fatalf("assertion on a credential revoked mid-ceremony = %v, want ErrCeremonyFailed", err)
	}
}
