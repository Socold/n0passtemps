package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// TestOpenNarrowsThePermissionsItFinds covers a data directory that already
// exists with a wider mode, which is what a Docker volume, a system package and
// an operator running mkdir all produce.
//
// MkdirAll only sets a mode on a directory it creates, so nothing used to
// happen in this case at all: the directory stayed readable by every local
// account, and the database file and its write-ahead log were created at 0644
// less the umask on top of that. The database holds the sealed secrets, the
// reference HMACs, the Argon2id hashes of the recovery codes and the personal
// fields of the audit log.
func TestOpenNarrowsThePermissionsItFinds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create the data directory: %v", err)
	}

	path := filepath.Join(dir, "store.db")
	s, err := Open(Options{DSN: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if mode := modeOf(t, dir); mode&^dataDirMode != 0 {
		t.Errorf("the data directory is mode %04o, wider than %04o", mode, dataDirMode)
	}

	// The two companions are part of the check and not an afterthought: the
	// write-ahead log holds the most recent transactions, in the clear, in the
	// same form as the database itself.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		file := path + suffix
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("stat %s: %v", file, err)
		}
		if mode := modeOf(t, file); mode&^dataFileMode != 0 {
			t.Errorf("%s is mode %04o, wider than %04o", file, mode, dataFileMode)
		}
	}
}

// TestTheWritePoolCommitsWithFullSynchronous states the durability the store
// claims.
//
// Under WAL, synchronous NORMAL cannot corrupt the database but can lose the
// tail of the most recent transactions after a power loss, and every record
// this schema spends exactly once becomes unspent again with it: a recovery
// code, a TOTP timestep, a consumed enrolment ticket. An audit entry already
// sent to an external witness would come back with a different sequence number,
// and the witness would disagree with the log for ever.
func TestTheWritePoolCommitsWithFullSynchronous(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	var got string
	if err := s.write.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&got); err != nil {
		t.Fatalf("read the pragma on the write pool: %v", err)
	}
	// 2 is FULL. The pragma answers with the level as a number.
	if got != "2" {
		t.Errorf("the write pool is at synchronous %q, want \"2\" (FULL): a power loss could "+
			"un-spend a recovery code, a TOTP step or an enrolment ticket already reported as consumed", got)
	}
}

// TestOnePendingTOTPSecretPerSubject covers the guard migration 0008 declares.
//
// The guard exists for the other engine, where two concurrent enrolments for
// one subject do not see each other's rows and both end up pending, only one of
// which the user holds. It is declared for both, because the two schemas are
// kept identical and a constraint that exists on one engine only is one nobody
// can rely on. Here it is also a check on CreateTOTPSecret: the revocation it
// performs is what keeps the ordinary path clear of the index.
func TestOnePendingTOTPSecretPerSubject(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "tenant-a")
	seedSubject(t, s, "tenant-a", "subject-1", "ref-1")

	secret := func(id string) *store.TOTPSecret {
		return &store.TOTPSecret{
			ID: id, TenantID: "tenant-a", SubjectID: "subject-1",
			SecretSealed: []byte("sealed-" + id), Algorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		}
	}

	// Two enrolments in a row, which is a user who started again. The second
	// revokes the first, so the index sees one pending secret throughout.
	if err := s.CreateTOTPSecret(ctx, secret("totp-1")); err != nil {
		t.Fatalf("first enrolment: %v", err)
	}
	if err := s.CreateTOTPSecret(ctx, secret("totp-2")); err != nil {
		t.Fatalf("second enrolment: %v", err)
	}

	// A pending secret inserted without that revocation, which is what a
	// concurrent enrolment amounts to on an engine that admits two writers.
	_, err := s.write.ExecContext(ctx, `
		INSERT INTO totp_secrets (id, tenant_id, subject_id, secret_sealed, algorithm,
			digits, period_seconds, last_timestep, created_at)
		VALUES (?, ?, ?, ?, 'SHA1', 6, 30, 0, ?)`,
		"totp-3", "tenant-a", "subject-1", []byte("sealed-3"), formatTime(time.Now()))
	if err == nil {
		t.Fatal("a second pending secret was accepted: the subject now has two, and holds one")
	}
	if !errors.Is(mapError(err), store.ErrConflict) {
		t.Errorf("the refusal was %v, want a conflict", err)
	}

	pending, err := s.GetPendingTOTPSecret(ctx, "tenant-a", "subject-1")
	if err != nil {
		t.Fatalf("read the pending secret: %v", err)
	}
	if pending.ID != "totp-2" {
		t.Errorf("the pending secret is %q, want the most recent enrolment", pending.ID)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
