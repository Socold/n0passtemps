// Package perf holds the benchmarks for the operations on the authentication
// hot path.
//
// The specification set a latency target for verification without saying which
// operations it covered, so the point of this package is to make the cost of
// each one visible rather than to assert a number. A benchmark that fails a
// hard threshold on shared continuous-integration hardware fails for reasons
// that have nothing to do with the change under review, so the assertions here
// are confined to the two cases where a wrong order of magnitude is a real
// defect rather than a slow runner.
//
// Run them with:
//
//	go test -bench=. -benchmem ./test/perf/
package perf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/crypto/token"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/totp"
)

// BenchmarkEnvelopeSeal measures sealing a TOTP-sized secret.
//
// This runs once per TOTP enrolment, which is rare, so its cost is not on the
// authentication path. It is measured because it bounds the enrolment burst a
// deployment can absorb.
func BenchmarkEnvelopeSeal(b *testing.B) {
	sealer := newSealer(b)
	secret := make([]byte, 20)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := sealer.Seal(secret); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnvelopeUnseal measures unsealing.
//
// This one IS on the authentication path: every TOTP verification unseals the
// stored seed first.
func BenchmarkEnvelopeUnseal(b *testing.B) {
	sealer := newSealer(b)
	sealed, err := sealer.Seal(make([]byte, 20))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := sealer.Unseal(sealed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnvelopeRewrap measures moving a record to a new key version
// without decrypting its payload.
//
// It is the operation a keyring rotation performs per row, so its cost sets how
// long rotating a large deployment takes.
func BenchmarkEnvelopeRewrap(b *testing.B) {
	sealer := newSealer(b)
	sealed, err := sealer.Seal(make([]byte, 20))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := sealer.Rewrap(sealed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTokenVerify measures authenticating a bearer credential.
//
// This runs on EVERY request to either surface, so it is the most
// latency-sensitive operation in the service, and it is the reason these
// credentials are hashed with a single SHA-256 rather than with Argon2id. The
// assertion below is the one that matters: if a change ever puts a
// password-stretching function on this path, the cost jumps by four orders of
// magnitude and an unauthenticated caller gains a way to exhaust memory by
// presenting invalid credentials.
func BenchmarkTokenVerify(b *testing.B) {
	tok, err := token.Generate(token.KindAPIKey)
	if err != nil {
		b.Fatal(err)
	}
	parsed, err := token.Parse(tok.Display)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	start := time.Now()
	var n int
	for b.Loop() {
		ok, err := parsed.Verify(tok.Hash)
		if err != nil || !ok {
			b.Fatalf("verify = %v, %v", ok, err)
		}
		n++
	}
	if n > 0 {
		per := time.Since(start) / time.Duration(n)
		// Ten microseconds is three orders of magnitude above what a single
		// SHA-256 over a short input costs, so this only trips if the
		// construction has been replaced, not if the runner is loaded.
		if per > 10*time.Microsecond {
			b.Errorf("bearer credential verification took %v per call, which is far above "+
				"the cost of one SHA-256; has a password-stretching function been put on "+
				"the request path?", per)
		}
	}
}

// BenchmarkRecoveryVerify measures redeeming a recovery code.
//
// This one is deliberately expensive: it is an Argon2id evaluation at the OWASP
// baseline. It is acceptable here because redeeming a recovery code is rare and
// rate limited, and the contrast with BenchmarkTokenVerify is the point of
// having both.
func BenchmarkRecoveryVerify(b *testing.B) {
	codes, err := recovery.Generate(1)
	if err != nil {
		b.Fatal(err)
	}
	_, verifier, err := recovery.Split(codes[0].Display)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		ok, err := recovery.Verify(verifier, codes[0].Hash)
		if err != nil || !ok {
			b.Fatalf("verify = %v, %v", ok, err)
		}
	}
}

// BenchmarkRecoveryGenerate measures issuing a batch.
//
// A batch is sixteen Argon2id evaluations, so this is the slowest single
// request the service serves. It is measured so that the batch size stays a
// deliberate choice.
func BenchmarkRecoveryGenerate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := recovery.Generate(16); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTOTPVerify measures checking a code.
//
// The implementation evaluates every step in the skew window unconditionally
// rather than stopping at the first match, so that a replayed code costs the
// same as a wrong one. This measures that constant cost.
func BenchmarkTOTPVerify(b *testing.B) {
	secret, err := totp.GenerateSecret(20)
	if err != nil {
		b.Fatal(err)
	}
	params := totp.Params{Algorithm: totp.SHA1, Digits: 6, Period: 30 * time.Second, Skew: 1}
	now := time.Now()
	code, err := totp.Code(secret, params, now)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, ok := totp.Verify(secret, params, code, now, 0); !ok {
			b.Fatal("a freshly generated code did not verify")
		}
	}
}

// BenchmarkAuditComputeHash measures the chain hash of one entry.
//
// Every audited event pays this, and an authenticated request produces at least
// one, so it sits on the hot path.
func BenchmarkAuditComputeHash(b *testing.B) {
	entry := &store.AuditEntry{
		Seq: 1000, TenantID: "default", OccurredAt: time.Now(),
		EventType: "webauthn.assertion.completed", ActorType: store.ActorAPIKey,
		ActorID:   "11111111-1111-1111-1111-111111111111",
		SubjectID: "22222222-2222-2222-2222-222222222222",
		Outcome:   store.OutcomeSuccess, SourceIP: "192.0.2.10",
		Detail:  json.RawMessage(`{"user_verified":true,"sign_count":42}`),
		PIISalt: make([]byte, audit.SaltSize),
	}
	entry.PIIDigest = audit.PIIDigest(entry)
	prev := audit.Genesis()

	b.ReportAllocs()
	for b.Loop() {
		_ = audit.ComputeHash(entry, prev)
	}
}

// BenchmarkAuditAppend measures one audited event including the database write.
//
// The append reads the chain head, computes the hashes and inserts inside one
// transaction, so this is the real cost of the audit guarantee rather than the
// cost of the hash alone.
func BenchmarkAuditAppend(b *testing.B) {
	st := newStore(b)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		_, err := st.Append(ctx, &store.AuditEntry{
			TenantID: "default", EventType: "webauthn.assertion.completed",
			ActorType: store.ActorAPIKey, Outcome: store.OutcomeSuccess,
			SubjectID: "22222222-2222-2222-2222-222222222222",
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditVerifyChain measures walking a chain of ten thousand entries.
//
// Verification is linear, which is why it is off by default at startup. This
// puts a number on what turning it on costs.
func BenchmarkAuditVerifyChain(b *testing.B) {
	st := newStore(b)
	ctx := context.Background()

	const entries = 10000
	for i := 0; i < entries; i++ {
		if _, err := st.Append(ctx, &store.AuditEntry{
			TenantID: "default", EventType: "webauthn.assertion.completed",
			ActorType: store.ActorAPIKey, Outcome: store.OutcomeSuccess,
		}); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		checked, broken, err := st.VerifyChain(ctx, 1)
		if err != nil {
			b.Fatal(err)
		}
		if broken != 0 || checked != entries {
			b.Fatalf("checked %d, broken at %d", checked, broken)
		}
	}
}

// BenchmarkConsumeTOTPStep measures the anti-replay compare-and-swap.
//
// It is one conditional UPDATE inside a transaction on the single write
// connection, which is the serialisation point of the whole service under
// SQLite. This is therefore the ceiling on concurrent TOTP verifications.
func BenchmarkConsumeTOTPStep(b *testing.B) {
	st := newStore(b)
	ctx := context.Background()

	// totp_secrets carries a foreign key to subjects, so the subject has to
	// exist before the seed can be inserted.
	subject, err := st.UpsertSubject(ctx, &store.Subject{
		ID:        "22222222-2222-2222-2222-222222222222",
		TenantID:  "default",
		RefHMAC:   []byte("bench-subject-lookup-key-32-byte"),
		Status:    store.SubjectActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		b.Fatal(err)
	}

	seed := &store.TOTPSecret{
		ID: "11111111-1111-1111-1111-111111111111", TenantID: "default",
		SubjectID:    subject.ID,
		SecretSealed: []byte("sealed"), Algorithm: "SHA1", Digits: 6,
		PeriodSeconds: 30, CreatedAt: time.Now(),
	}
	if err := st.CreateTOTPSecret(ctx, seed); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	var step int64
	for b.Loop() {
		res, err := st.ConsumeTOTPStep(ctx, "default", seed.ID, step, step+1)
		if err != nil {
			b.Fatal(err)
		}
		if !res.Accepted {
			b.Fatalf("step %d was refused", step+1)
		}
		step++
	}
}

// newSealer builds an envelope sealer over a throwaway keyring.
func newSealer(tb testing.TB) *envelope.Sealer {
	tb.Helper()

	dir := tb.TempDir()
	path := filepath.Join(dir, "kek.json")

	key := make([]byte, kek.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	doc := map[string]any{
		"current": 2,
		"keys": map[string]string{
			"1": base64.StdEncoding.EncodeToString(key),
			"2": base64.StdEncoding.EncodeToString(key),
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		tb.Fatal(err)
	}

	// The keyring must not sit inside a data directory, so none is declared
	// here and the check has nothing to refuse.
	provider, err := kek.LoadFileProvider(path)
	if err != nil {
		tb.Fatal(err)
	}
	return envelope.NewSealer(provider)
}

// newStore opens a migrated database in a temporary directory.
func newStore(tb testing.TB) store.Store {
	tb.Helper()

	st, err := sqlite.Open(sqlite.Options{
		DSN:    filepath.Join(tb.TempDir(), "bench.db"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		tb.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.CreateTenant(ctx, &store.Tenant{
		ID: "default", Name: "bench", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		tb.Fatal(err)
	}
	return st
}
