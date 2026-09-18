package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/store"
	sqlitestore "github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/subject"
)

// pepperEnvForTests is deliberately not the production variable name, so a
// test run cannot pick up an operator's real pepper from the shell it was
// started in.
const pepperEnvForTests = "N0PASSTEMPS_TEST_SUBJECT_PEPPER"

// testTenant is the tenant every fixture writes its rows under.
const testTenant = "default"

// trio is a generated deployment: the three artefacts an operator backs up
// separately, plus the plaintexts the fixture used, so a test can assert that
// none of them reaches the output.
type trio struct {
	dbPath      string
	keyringPath string
	pepper      string // base64, as an operator's environment holds it
	ref         string
	totpSecret  string
	keyMaterial []string // base64 of every key in the keyring
}

// trioOptions vary the fixture.
type trioOptions struct {
	// sealReference stores the encrypted copy of the subject reference, which
	// is what the pepper is recomputed against.
	sealReference bool
	// keyVersions is how many key versions the keyring holds. The highest is
	// current, so the records are sealed under it.
	keyVersions int
	// withRecords creates a subject and a TOTP enrolment, so there is
	// something encrypted to open.
	withRecords bool
}

func defaultTrioOptions() trioOptions {
	return trioOptions{sealReference: true, keyVersions: 1, withRecords: true}
}

// buildTrio writes a migrated database, the keyring its records are sealed
// under and the pepper their lookup values derive from.
//
// The records are created through the real subject service and the real
// sealer, not by writing bytes into the tables: a fixture that sealed records
// its own way could pass a verification the service's own records would fail.
func buildTrio(t *testing.T, opts trioOptions) trio {
	t.Helper()

	dir := t.TempDir()
	tr := trio{
		dbPath:      filepath.Join(dir, "data", "n0passtemps.db"),
		keyringPath: filepath.Join(dir, "kek", "keyring.json"),
		ref:         "user-4711@example.com",
		totpSecret:  "JBSWY3DPEHPK3PXP",
	}
	tr.keyMaterial = writeKeyring(t, tr.keyringPath, opts.keyVersions, 0o600)

	pepper := make([]byte, subject.MinPepperBytes)
	if _, err := rand.Read(pepper); err != nil {
		t.Fatalf("generate pepper: %v", err)
	}
	tr.pepper = base64.StdEncoding.EncodeToString(pepper)

	provider, err := kek.LoadFileProvider(tr.keyringPath)
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	defer func() { _ = provider.Close() }()
	sealer := envelope.NewSealer(provider)

	st, err := sqlitestore.Open(sqlitestore.Options{
		DSN:    tr.dbPath,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Now().UTC()
	if err := st.CreateTenant(ctx, &store.Tenant{
		ID: testTenant, Name: "Verify fixture", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	if opts.withRecords {
		cfg := config.Default().Subject
		cfg.SealReference = opts.sealReference
		cfg.PepperEnv = pepperEnvForTests
		t.Setenv(pepperEnvForTests, tr.pepper)

		svc, err := subject.New(cfg, st, sealer, nil)
		if err != nil {
			t.Fatalf("build subject service: %v", err)
		}
		defer svc.Close()

		sub, err := svc.Resolve(ctx, testTenant, tr.ref, "Verify fixture")
		if err != nil {
			t.Fatalf("resolve subject: %v", err)
		}

		sealed, err := sealer.Seal([]byte(tr.totpSecret))
		if err != nil {
			t.Fatalf("seal totp secret: %v", err)
		}
		if err := st.CreateTOTPSecret(ctx, &store.TOTPSecret{
			ID: uuid.NewString(), TenantID: testTenant, SubjectID: sub.ID,
			SecretSealed: sealed, Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
			CreatedAt: now,
		}); err != nil {
			t.Fatalf("create totp secret: %v", err)
		}
	}

	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return tr
}

// writeKeyring writes a keyring holding versions 1..n, the highest current,
// and returns the base64 of every key in it.
func writeKeyring(t *testing.T, path string, versions int, mode os.FileMode) []string {
	t.Helper()

	doc := keyringFile{Current: uint32(versions), Keys: map[string]string{}}
	material := make([]string, 0, versions)
	for v := 1; v <= versions; v++ {
		key := make([]byte, kek.KeySize)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("generate key: %v", err)
		}
		encoded := base64.StdEncoding.EncodeToString(key)
		doc.Keys[strconv.Itoa(v)] = encoded
		material = append(material, encoded)
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode keyring: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create keyring directory: %v", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), mode); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	// WriteFile applies the umask, and one of the fixtures needs a mode that a
	// umask would have taken bits off.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod keyring: %v", err)
	}
	return material
}

// runVerifyCapturing runs the command with a pepper in the environment and
// returns everything it printed, so a test can assert on the report as well as
// on the verdict.
func runVerifyCapturing(t *testing.T, pepper string, args ...string) (string, error) {
	t.Helper()
	t.Setenv(pepperEnvForTests, pepper)

	previous := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	verr := runVerify(append([]string{"-pepper-env", pepperEnvForTests}, args...))

	_ = w.Close()
	os.Stdout = previous
	out := <-collected
	_ = r.Close()
	return out, verr
}

func TestVerifyAGoodTrioOpens(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	if err != nil {
		t.Fatalf("a good trio was refused: %v\n%s", err, out)
	}
	if exit := exitCodeFor(err); err != nil && exit != 0 {
		t.Fatalf("exit code %d for a good trio", exit)
	}

	for _, want := range []string{
		"The trio opens.",
		"subjects.ref_sealed",
		"totp_secrets.secret_sealed",
		"Unsealed 2 records",
		"Proved:",
		"Not proved:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q\n%s", want, out)
		}
	}
}

// TestVerifyPrintsNoSecret is the check on the command's own output. Counts,
// versions, identifiers and verdicts are printable; key material, the pepper,
// a decrypted TOTP secret and a subject reference are not.
func TestVerifyPrintsNoSecret(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath, "-all")
	if err != nil {
		t.Fatalf("a good trio was refused: %v", err)
	}

	forbidden := map[string]string{
		"the pepper":            tr.pepper,
		"the subject reference": tr.ref,
		"the TOTP secret":       tr.totpSecret,
	}
	for name, value := range forbidden {
		if strings.Contains(out, value) {
			t.Errorf("the report printed %s", name)
		}
	}
	for i, key := range tr.keyMaterial {
		if strings.Contains(out, key) {
			t.Errorf("the report printed key version %d", i+1)
		}
	}
}

// TestVerifyDoesNotWriteTheDatabase is the read-only guarantee, checked on the
// artefact rather than trusted.
func TestVerifyDoesNotWriteTheDatabase(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())
	before := digest(t, tr.dbPath)

	if _, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath,
		"-keyring", tr.keyringPath, "-all"); err != nil {
		t.Fatalf("a good trio was refused: %v", err)
	}

	if after := digest(t, tr.dbPath); after != before {
		t.Fatalf("the database changed: %s before, %s after", before, after)
	}
}

// TestReadOnlyHandleRefusesEveryWrite checks that the refusal comes from
// SQLite and not from this package's restraint. Every statement below is
// rejected by the engine on the handle the command uses.
func TestReadOnlyHandleRefusesEveryWrite(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	db, err := openReadOnly(tr.dbPath)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, stmt := range []string{
		`INSERT INTO tenants (id, name, status, created_at, updated_at) VALUES ('t', 't', 'active', '', '')`,
		`UPDATE subjects SET display_name = 'changed'`,
		`DELETE FROM totp_secrets`,
		`CREATE TABLE scratch (a INTEGER)`,
		`DROP TABLE totp_secrets`,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (99, 'x', 'x', 'x')`,
	} {
		if _, err := db.Exec(stmt); err == nil {
			t.Errorf("the read-only handle accepted: %s", stmt)
		}
	}
}

func TestVerifyRefusesAWrongKeyring(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	// Same shape, same version numbering, different key material. This is the
	// case that parsing a keyring cannot catch and unsealing a record can.
	other := filepath.Join(t.TempDir(), "keyring.json")
	writeKeyring(t, other, 1, 0o600)

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", other)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	if !strings.Contains(err.Error(), "did not open it") {
		t.Errorf("the verdict does not say the key failed to open a record: %v\n%s", err, out)
	}
}

func TestVerifyRefusesAWrongPepper(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	wrong := make([]byte, subject.MinPepperBytes)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatalf("generate pepper: %v", err)
	}

	_, err := runVerifyCapturing(t, base64.StdEncoding.EncodeToString(wrong),
		"-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	if !strings.Contains(err.Error(), "does not derive the stored lookup value") {
		t.Errorf("the verdict does not name the pepper: %v", err)
	}
}

func TestVerifyRefusesAPepperOfTheWrongLength(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	short := make([]byte, 16)
	if _, err := rand.Read(short); err != nil {
		t.Fatalf("generate pepper: %v", err)
	}

	// The encoding is named, so the value is not rejected for being ambiguous
	// and the length check is what fires.
	_, err := runVerifyCapturing(t, "base64:"+base64.StdEncoding.EncodeToString(short),
		"-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	if !strings.Contains(err.Error(), "holds 16 bytes") {
		t.Errorf("the verdict does not give the length: %v", err)
	}
}

func TestVerifyRefusesAnUndecodablePepper(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	_, err := runVerifyCapturing(t, "not a pepper at all",
		"-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
}

func TestVerifyRefusesATruncatedDatabase(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	raw, err := os.ReadFile(tr.dbPath)
	if err != nil {
		t.Fatalf("read database: %v", err)
	}
	if err = os.WriteFile(tr.dbPath, raw[:len(raw)/3], 0o600); err != nil {
		t.Fatalf("truncate database: %v", err)
	}

	_, err = runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
}

func TestVerifyRefusesAFileThatIsNotADatabase(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())
	if err := os.WriteFile(tr.dbPath, []byte("this is not a database"), 0o600); err != nil {
		t.Fatalf("overwrite database: %v", err)
	}

	_, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
}

func TestVerifyRefusesAKeyringReadableByGroupOrOther(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())
	if err := os.Chmod(tr.keyringPath, 0o644); err != nil {
		t.Fatalf("chmod keyring: %v", err)
	}

	_, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("the verdict does not say how to fix the mode: %v", err)
	}
}

// TestVerifyNamesTheMissingKeyVersion is the diagnosis the roadmap entry asks
// for: which version is absent, and how many records need it.
func TestVerifyNamesTheMissingKeyVersion(t *testing.T) {
	opts := defaultTrioOptions()
	opts.keyVersions = 2
	tr := buildTrio(t, opts)

	// Every record is sealed under version 2, because it was current. Hand
	// over a keyring that has only version 1, which is the shape of a backup
	// taken before a rotation.
	writeKeyring(t, tr.keyringPath, 1, 0o600)

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	for _, want := range []string{"no key version 2", "in totp_secrets.secret_sealed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the verdict does not mention %q: %v", want, err)
		}
	}
	if !strings.Contains(out, "KEY MISSING") {
		t.Errorf("the census does not flag the missing key\n%s", out)
	}
}

// TestVerifyReportsAnUntestedKeyVersion covers a keyring holding a version
// nothing in the database is sealed under, which is the normal state after a
// rotation and a rewrap. It passes, and the report says which version it could
// not exercise.
func TestVerifyReportsAnUntestedKeyVersion(t *testing.T) {
	opts := defaultTrioOptions()
	opts.keyVersions = 2
	tr := buildTrio(t, opts)

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	if err != nil {
		t.Fatalf("a good trio was refused: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Key version 1 is in the keyring") {
		t.Errorf("the report does not name the untested key version\n%s", out)
	}
}

func TestVerifyCannotRunWithoutAPepper(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	_, err := runVerifyCapturing(t, "", "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errCannotVerify, 2)
}

func TestVerifyCannotRunWithoutPaths(t *testing.T) {
	_, err := runVerifyCapturing(t, "unused")
	requireVerdict(t, err, errCannotVerify, 2)
}

func TestVerifyCannotRunOnAMissingFile(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())
	absent := filepath.Join(filepath.Dir(tr.dbPath), "not-here.db")

	_, err := runVerifyCapturing(t, tr.pepper, "-db", absent, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errCannotVerify, 2)

	_, err = runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", absent)
	requireVerdict(t, err, errCannotVerify, 2)
}

// TestVerifyCannotRunOnANewerSchema covers a backup written by a later build.
// The tables this command reads may still be there, but a binary that does not
// know what changed cannot claim it covered everything.
func TestVerifyCannotRunOnANewerSchema(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	db, err := sql.Open("sqlite", "file:"+tr.dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	if _, err = db.Exec(
		`INSERT INTO schema_migrations (version, name, checksum, applied_at)
		 VALUES (9999, 'from_the_future', 'deadbeef', '2026-09-18T00:00:00.000000000Z')`); err != nil {
		t.Fatalf("insert migration row: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	_, err = runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errCannotVerify, 2)
	if !strings.Contains(err.Error(), "newer version") {
		t.Errorf("the verdict does not say the database is newer: %v", err)
	}
}

// TestVerifyCannotRunOnAnEmptyDatabase refuses to call a trio verified when
// the database holds nothing sealed. A migrated but empty database proves
// nothing about a keyring.
func TestVerifyCannotRunOnAnEmptyDatabase(t *testing.T) {
	opts := defaultTrioOptions()
	opts.withRecords = false
	tr := buildTrio(t, opts)

	_, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errCannotVerify, 2)
	if !strings.Contains(err.Error(), "nothing in this database is sealed") {
		t.Errorf("the verdict does not say why: %v", err)
	}
}

// TestVerifyWithoutASealedReference covers subject.seal_reference = false.
// There is then nothing to recompute the pepper against, so the command says
// so rather than reporting a trio it only half checked, and -ref makes it
// runnable again.
func TestVerifyWithoutASealedReference(t *testing.T) {
	opts := defaultTrioOptions()
	opts.sealReference = false
	tr := buildTrio(t, opts)

	_, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errCannotVerify, 2)
	if !strings.Contains(err.Error(), "-ref") {
		t.Errorf("the verdict does not point at -ref: %v", err)
	}

	out, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath,
		"-keyring", tr.keyringPath, "-ref", tr.ref)
	if err != nil {
		t.Fatalf("the trio was refused with -ref supplied: %v\n%s", err, out)
	}
	if !strings.Contains(out, "The trio opens.") {
		t.Errorf("the report does not reach a verdict\n%s", out)
	}
}

func TestVerifyRefusesAReferenceThatDoesNotMatch(t *testing.T) {
	opts := defaultTrioOptions()
	opts.sealReference = false
	tr := buildTrio(t, opts)

	_, err := runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath,
		"-keyring", tr.keyringPath, "-ref", "nobody@example.com")
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
}

// TestVerifyDamagedEnvelopeHeader covers a sealed column that has been
// corrupted in place rather than one sealed under a key that is missing.
func TestVerifyDamagedEnvelopeHeader(t *testing.T) {
	tr := buildTrio(t, defaultTrioOptions())

	db, err := sql.Open("sqlite", "file:"+tr.dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	if _, err = db.Exec(`UPDATE totp_secrets SET secret_sealed = X'00'`); err != nil {
		t.Fatalf("damage the column: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	_, err = runVerifyCapturing(t, tr.pepper, "-db", tr.dbPath, "-keyring", tr.keyringPath)
	requireVerdict(t, err, errTrioDoesNotOpen, 1)
	if !strings.Contains(err.Error(), "envelope header") {
		t.Errorf("the verdict does not name the damage: %v", err)
	}
}

func TestReadOnlyDSNEscapesThePath(t *testing.T) {
	got := readOnlyDSN("/var/lib/n0 passtemps/db?x.db")
	for _, want := range []string{"%20", "%3F", "mode=ro", "query_only"} {
		if !strings.Contains(got, want) {
			t.Errorf("the dsn %q does not contain %q", got, want)
		}
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"a bad trio", errTrioDoesNotOpen, 1},
		{"a wrapped bad trio", errors.New("x"), 1},
		{"could not run", errCannotVerify, 2},
		{"a wrapped could not run", errors.Join(errCannotVerify, errors.New("x")), 2},
	}
	for _, c := range cases {
		if got := exitCodeFor(c.err); got != c.want {
			t.Errorf("%s: exit code %d, want %d", c.name, got, c.want)
		}
	}
}

// requireVerdict asserts both halves of the interface: the sentinel the command
// reports, and the exit status an operator's cron job reads.
func requireVerdict(t *testing.T, err error, want error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %v, got no error", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
	if got := exitCodeFor(err); got != code {
		t.Fatalf("exit code %d, want %d, for %v", got, code, err)
	}
}

func digest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
