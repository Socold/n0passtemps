// Package sqlite implements store.Store on SQLite.
//
// # Two pools
//
// SQLite in WAL mode allows many concurrent readers and exactly one writer. A
// single database/sql pool of several connections therefore produces
// SQLITE_BUSY under write contention, which surfaces as intermittent failures
// that are hard to reproduce. This implementation opens two pools instead: a
// read pool with several connections, and a write pool limited to one. Writes
// queue in Go rather than colliding in SQLite, so a busy error becomes a short
// wait instead of an error the caller has to retry.
//
// # Write transactions
//
// Every write transaction is opened with BEGIN IMMEDIATE. SQLite's default
// deferred transaction takes its write lock at the first write statement, so a
// read-then-write sequence can have its premise invalidated between the two
// halves and fails at commit time with SQLITE_BUSY_SNAPSHOT. Taking the lock up
// front makes the compare-and-swap operations this schema relies on, the TOTP
// replay counter and the audit chain head, actually atomic.
//
// # Timestamps
//
// SQLite has no date type, so instants are stored as fixed-width RFC 3339 in
// UTC with nine fractional digits. The width matters: time.RFC3339Nano removes
// trailing zeros, which breaks the lexicographic ordering that every ORDER BY
// and every range index on these columns depends on.
//
// # Durability
//
// The write pool commits with synchronous FULL, so a transaction that has
// returned has been fsynced to the write-ahead log. NORMAL, the usual advice
// under WAL, cannot corrupt the database but can lose the tail of the most
// recent transactions after a power loss, and every single-use record this
// schema holds is a record whose loss un-spends it: a recovery code becomes
// unused again, a TOTP timestep can be replayed, a consumed enrolment ticket
// can be redeemed a second time. Audit entries are worse still, because an
// entry already sent to an external witness would come back with a different
// sequence number and the witness would disagree with the log for ever. The
// cost is one fsync per commit on a path that already computes an Argon2id
// hash or verifies a signature, which is not where the time goes.
//
// # File permissions
//
// The database holds sealed secrets, the reference HMACs, the Argon2id hashes
// of the recovery codes and the personal fields of the audit log, so nothing in
// it is readable by another local account if this package can help it. Open
// narrows the data directory to 0700 and the database file and its -wal and
// -shm companions to 0600 whenever it finds them wider, says so in the log, and
// refuses to start only when the narrowing itself fails, which means the paths
// belong to another account and the operator has to act. The argument is at
// ensureParentDir and at tightenFileModes.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/migrations"
)

// timeLayout is fixed width so that string comparison orders instants
// correctly. See the package comment.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// The widest permissions the database is allowed to sit behind. See the package
// comment on what is in it.
const (
	dataDirMode  os.FileMode = 0o700
	dataFileMode os.FileMode = 0o600
)

// Store is the SQLite implementation of store.Store.
type Store struct {
	read  *sql.DB
	write *sql.DB
	log   *slog.Logger
	path  string
}

// Options configure Open.
type Options struct {
	// DSN is the database file path, optionally with a query string. An
	// in-memory database is supported for tests as ":memory:".
	DSN string

	// MaxReadConns bounds the read pool. The write pool is always one.
	MaxReadConns int

	// BusyTimeout is how long SQLite waits for a lock before returning
	// SQLITE_BUSY. With the two-pool arrangement this should rarely be
	// reached, but a checkpoint can still hold the lock briefly.
	BusyTimeout time.Duration

	ConnMaxLifetime time.Duration

	Logger *slog.Logger
}

// Open connects to the database and configures both pools.
//
// It does not apply migrations. Call Migrate for that, so an operator who
// prefers to review schema changes separately can skip it.
func Open(opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, errors.New("sqlite: dsn is required")
	}
	if opts.MaxReadConns <= 0 {
		opts.MaxReadConns = 4
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	memory := isMemoryDSN(opts.DSN)
	if !memory {
		if err := ensureParentDir(opts.DSN, opts.Logger); err != nil {
			return nil, err
		}
	}

	readDSN := buildDSN(opts.DSN, opts.BusyTimeout, false)
	writeDSN := buildDSN(opts.DSN, opts.BusyTimeout, true)

	read, err := sql.Open("sqlite", readDSN)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open read pool: %w", err)
	}
	write, err := sql.Open("sqlite", writeDSN)
	if err != nil {
		_ = read.Close()
		return nil, fmt.Errorf("sqlite: open write pool: %w", err)
	}

	// An in-memory database is private to its connection unless it is shared
	// by name, and two pools would otherwise see two different databases. The
	// shared-cache DSN built below handles the naming; the read pool is still
	// capped at one connection because shared-cache locking is per table and
	// concurrent readers there behave less predictably than on a file.
	readConns := opts.MaxReadConns
	if memory {
		readConns = 1
	}

	read.SetMaxOpenConns(readConns)
	read.SetMaxIdleConns(readConns)
	read.SetConnMaxLifetime(opts.ConnMaxLifetime)

	// The single write connection is the serialisation point. Keeping it idle
	// rather than letting it expire avoids re-running the pragmas on every
	// write burst.
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(0)

	s := &Store{read: read, write: write, log: opts.Logger, path: opts.DSN}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.verifyPragmas(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}

	// After the pragmas, because reading journal_mode on both pools is what
	// makes SQLite create the -wal and -shm files, and they are two thirds of
	// what has to be narrowed.
	if !memory {
		if err := s.tightenFileModes(ctx); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// buildDSN adds the pragmas this schema requires.
//
// They are set through the DSN rather than with an Exec after connecting,
// because database/sql may open a new connection at any time and a pragma set
// on one connection does not apply to the others.
func buildDSN(dsn string, busy time.Duration, writer bool) string {
	base, existing := splitDSN(dsn)

	q := url.Values{}
	for k, vs := range existing {
		for _, v := range vs {
			q.Add(k, v)
		}
	}

	add := func(pragma string) {
		q.Add("_pragma", pragma)
	}

	// Foreign keys are off by default in SQLite, which would make every
	// ON DELETE CASCADE in the schema silently inert.
	add("foreign_keys(1)")

	// WAL lets readers proceed during a write. It is persistent once set, but
	// setting it on every connection is harmless and covers a fresh file.
	add("journal_mode(WAL)")

	// FULL on the connection that commits, NORMAL on the ones that only read.
	// Under WAL, NORMAL cannot corrupt the database but can lose the tail of
	// the most recent transactions after a power loss, and losing a commit here
	// un-spends a single-use record: see the package comment on durability.
	// Nothing on the read pool commits, so the setting there costs nothing
	// either way and is left at the value the engine would choose.
	if writer {
		add("synchronous(FULL)")
	} else {
		add("synchronous(NORMAL)")
	}

	add(fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()))

	// Keep temporary tables and indexes in memory rather than in a file whose
	// permissions this process does not control.
	add("temp_store(MEMORY)")

	// Enforce the CHECK constraints and the STRICT tables the schema declares.
	add("trusted_schema(0)")

	if writer {
		// A deferred transaction upgrades to a write lock at its first write,
		// which is exactly the window the compare-and-swap operations must not
		// have. See the package comment.
		q.Set("_txlock", "immediate")
	}

	if isMemoryDSN(base) {
		// Give the in-memory database a name so both pools attach to the same
		// one instead of each getting a private database.
		base = "file:n0passtemps-memory"
		q.Set("mode", "memory")
		q.Set("cache", "shared")
	} else if !strings.HasPrefix(base, "file:") {
		base = "file:" + base
	}

	return base + "?" + q.Encode()
}

func splitDSN(dsn string) (string, url.Values) {
	i := strings.IndexByte(dsn, '?')
	if i < 0 {
		return dsn, url.Values{}
	}
	v, err := url.ParseQuery(dsn[i+1:])
	if err != nil {
		return dsn[:i], url.Values{}
	}
	return dsn[:i], v
}

func isMemoryDSN(dsn string) bool {
	base, _ := splitDSN(dsn)
	return base == ":memory:" || base == "file::memory:" || strings.Contains(dsn, "mode=memory")
}

// ensureParentDir creates the directory holding the database file, narrows it
// to 0700 if it is wider, and refuses to go on if it cannot.
//
// MkdirAll sets the mode only on a directory it creates. A data directory that
// is already there keeps whatever mode it was given, and 0755 is what a Docker
// volume, a system package and an operator running mkdir all produce, so the
// mode passed below decides nothing at all in the case that matters. The Stat
// afterwards is the check that does.
//
// Narrowing rather than refusing outright, because a wide data directory is a
// condition this process can end, and a service that refuses to start leaves
// the database exactly as exposed as it found it while also being down. What is
// refused is the case that cannot be ended: a directory owned by another
// account, which is where the operator has to act, and the error names the
// command. Neither outcome is silent, which is the property that matters: the
// repair is logged with the mode that was found.
func ensureParentDir(dsn string, log *slog.Logger) error {
	base, _ := splitDSN(dsn)
	base = strings.TrimPrefix(base, "file:")
	dir := filepath.Dir(base)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, dataDirMode); err != nil {
		return fmt.Errorf("sqlite: create %q: %w", dir, err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("sqlite: read the mode of %q: %w", dir, err)
	}
	mode := info.Mode().Perm()
	if mode&^dataDirMode == 0 {
		return nil
	}
	if err := os.Chmod(dir, dataDirMode); err != nil {
		return fmt.Errorf(
			"sqlite: the data directory %q is mode %04o and could not be narrowed to %04o, so "+
				"other local accounts can read the database: it holds sealed secrets, the "+
				"reference HMACs and the personal fields of the audit log. Run: chmod %04o %s: %w",
			dir, mode, dataDirMode, dataDirMode, dir, err)
	}
	log.Warn("data directory permissions narrowed",
		slog.String("path", dir),
		slog.String("was", fmt.Sprintf("%04o", mode)),
		slog.String("now", fmt.Sprintf("%04o", dataDirMode)))
	return nil
}

// tightenFileModes narrows the database file and the two files WAL keeps beside
// it to 0600.
//
// Unlike the directory, these are ours. SQLite creates them at 0644 less the
// umask and offers no setting for it, so refusing a wide mode would refuse
// every first start under the default umask of a distribution, on a deployment
// that has done nothing wrong. Narrowing them is therefore the correct answer
// here, and it is not silent: each one that had to be changed is logged with
// the mode it had.
//
// The -wal and -shm files may not exist yet on a database that has never been
// written, and they are recreated by the engine after a checkpoint. SQLite
// gives a recreated one the mode of the database file, so narrowing that one is
// what keeps the other two narrow afterwards.
func (s *Store) tightenFileModes(ctx context.Context) error {
	base, _ := splitDSN(s.path)
	base = strings.TrimPrefix(base, "file:")

	for _, path := range []string{base, base + "-wal", base + "-shm"} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("sqlite: read the mode of %q: %w", path, err)
		}
		mode := info.Mode().Perm()
		if mode&^dataFileMode == 0 {
			continue
		}
		if err := os.Chmod(path, dataFileMode); err != nil {
			return fmt.Errorf(
				"sqlite: %q is mode %04o and could not be narrowed to %04o, so another local "+
					"account can read it: %w",
				path, mode, dataFileMode, err)
		}
		s.log.InfoContext(ctx, "database file permissions narrowed",
			slog.String("path", path),
			slog.String("was", fmt.Sprintf("%04o", mode)),
			slog.String("now", fmt.Sprintf("%04o", dataFileMode)))
	}
	return nil
}

// verifyPragmas confirms the settings actually took effect.
//
// A pragma supplied in a DSN that the driver does not recognise is ignored
// silently. Checking afterwards turns a typo in the DSN builder into a startup
// failure rather than into foreign keys being off in production.
func (s *Store) verifyPragmas(ctx context.Context) error {
	checks := []struct {
		pragma string
		want   string
		why    string
	}{
		{"foreign_keys", "1", "ON DELETE CASCADE in the schema would not fire"},
		{"journal_mode", "wal", "readers would block behind every write"},
	}
	for _, pool := range []*sql.DB{s.read, s.write} {
		for _, c := range checks {
			var got string
			if err := pool.QueryRowContext(ctx, "PRAGMA "+c.pragma).Scan(&got); err != nil {
				return fmt.Errorf("sqlite: read pragma %s: %w", c.pragma, err)
			}
			if !strings.EqualFold(got, c.want) {
				return fmt.Errorf("sqlite: pragma %s is %q, expected %q: %s",
					c.pragma, got, c.want, c.why)
			}
		}
	}

	// synchronous is checked on the write pool alone, because that is the pool
	// whose value decides anything: it is the only one that commits. PRAGMA
	// synchronous answers with the numeric level, and 2 is FULL.
	var sync string
	if err := s.write.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil {
		return fmt.Errorf("sqlite: read pragma synchronous: %w", err)
	}
	if sync != "2" {
		return fmt.Errorf(
			"sqlite: pragma synchronous is %q on the write pool, expected \"2\" (FULL): "+
				"a power loss could then un-spend a recovery code, a TOTP timestep or an "+
				"enrolment ticket that has already been reported as consumed",
			sync)
	}
	return nil
}

// Engine implements store.Store.
func (s *Store) Engine() string { return "sqlite" }

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.read.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: ping read pool: %w", err)
	}
	if err := s.write.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: ping write pool: %w", err)
	}
	return nil
}

// Close implements store.Store.
func (s *Store) Close() error {
	var errs []error
	if err := s.write.Close(); err != nil {
		errs = append(errs, fmt.Errorf("sqlite: close write pool: %w", err))
	}
	if err := s.read.Close(); err != nil {
		errs = append(errs, fmt.Errorf("sqlite: close read pool: %w", err))
	}
	return errors.Join(errs...)
}

// Migrate implements store.Store.
//
// Each migration runs in its own transaction, so a failure leaves the database
// at the last complete version rather than half way through one. SQLite
// supports transactional DDL, which makes this genuinely atomic.
func (s *Store) Migrate(ctx context.Context) error {
	set, err := migrations.Load("sqlite")
	if err != nil {
		return err
	}

	if err = s.ensureMigrationTable(ctx); err != nil {
		return err
	}

	applied, err := s.appliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, m := range set {
		if prev, ok := applied[m.Version]; ok {
			if prev != m.Checksum {
				return fmt.Errorf(
					"sqlite: migration %04d_%s was applied with checksum %s but the "+
						"embedded file now hashes to %s; the database and this binary "+
						"disagree about the schema",
					m.Version, m.Name, prev, m.Checksum)
			}
			continue
		}

		if err := s.inTx(ctx, func(tx *sql.Tx) error {
			for i, stmt := range m.Statements {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("statement %d: %w\n%s", i+1, err, truncate(stmt, 400))
				}
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
				m.Version, m.Name, m.Checksum, formatTime(time.Now()))
			return err
		}); err != nil {
			return fmt.Errorf("sqlite: apply migration %04d_%s: %w", m.Version, m.Name, err)
		}

		s.log.InfoContext(ctx, "migration applied",
			slog.Int("version", m.Version), slog.String("name", m.Name))
	}
	return nil
}

// ensureMigrationTable creates the bookkeeping table if the database is new.
// It is written by hand rather than being migration zero, because a migration
// runner cannot record its own first step.
func (s *Store) ensureMigrationTable(ctx context.Context) error {
	_, err := s.write.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER NOT NULL PRIMARY KEY,
			name        TEXT    NOT NULL,
			checksum    TEXT    NOT NULL,
			applied_at  TEXT    NOT NULL
		) STRICT`)
	if err != nil {
		return fmt.Errorf("sqlite: create schema_migrations: %w", err)
	}
	return nil
}

func (s *Store) appliedMigrations(ctx context.Context) (map[int]string, error) {
	rows, err := s.read.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, fmt.Errorf("sqlite: scan schema_migrations: %w", err)
		}
		out[v] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate schema_migrations: %w", err)
	}
	return out, nil
}

// inTx runs fn inside a transaction on the write pool and commits, or rolls
// back if fn returns an error.
//
// The write pool is limited to one connection, so this also serialises writers.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback after a successful commit returns ErrTxDone, which is not a
		// problem and is deliberately ignored.
		_ = tx.Rollback()
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mapError translates a driver error into the sentinel errors declared by the
// store package, so handlers can decide on a status code without importing a
// driver.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed"),
		strings.Contains(msg, "constraint failed: UNIQUE"):
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	case strings.Contains(msg, "append-only"),
		strings.Contains(msg, "permits no update"),
		strings.Contains(msg, "may only be removed"):
		return fmt.Errorf("%w: %v", store.ErrAppendOnly, err)
	case strings.Contains(msg, "FOREIGN KEY constraint failed"):
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	}
	return err
}

// formatTime renders an instant for storage. See the package comment on why
// the layout is fixed width.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// formatTimePtr renders an optional instant, mapping nil to a SQL NULL.
func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// parseTime reads an instant back.
//
// Several layouts are accepted on read even though only one is written, so a
// database touched by an operator with the sqlite3 shell, or migrated from an
// earlier build, still loads.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{timeLayout, time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("sqlite: cannot parse timestamp %q", s)
}

// parseTimePtr reads an optional instant.
func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// nullString wraps a value that is stored as NULL when empty, so that a unique
// partial index treats absent values as distinct rather than colliding on the
// empty string.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func stringOrEmpty(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// clampLimit bounds a caller-supplied page size. A zero or negative limit means
// the caller did not choose, and gets the default rather than everything.
func clampLimit(limit, def, maxLimit int) int {
	if limit <= 0 {
		return def
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}
