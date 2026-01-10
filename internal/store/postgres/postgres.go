// Package postgres implements store.Store on PostgreSQL.
//
// It is the twin of the sqlite package and answers the same contract. Where the
// two differ, the difference is an engine property rather than a choice, and
// each one is noted at the place it applies.
//
// # One pool
//
// The SQLite implementation opens two pools, a read pool of several connections
// and a write pool limited to one. That arrangement exists because SQLite in
// WAL mode admits exactly one writer, so concurrent writers collide in the
// engine and surface as SQLITE_BUSY; funnelling them through a single Go
// connection turns the collision into a queue.
//
// PostgreSQL has real multi-version concurrency control. Writers to different
// rows do not block each other, and writers to the same row take a row lock for
// the duration of the statement rather than locking the database. Serialising
// every write through one connection would therefore throw away the engine's
// concurrency without buying any safety, so this implementation uses one
// *pgxpool.Pool for reads and writes alike.
//
// # Timestamps
//
// Instants are native TIMESTAMPTZ values, passed and scanned as time.Time.
// There is no format helper and no parser: the fixed-width RFC 3339 layout the
// SQLite implementation needs exists only because SQLite compares those columns
// as text, and lexicographic order has to agree with chronological order. That
// reasoning does not apply here.
//
// Every instant is normalised to UTC when it is read, because a TIMESTAMPTZ
// carries an absolute instant and no zone, and the driver renders it in the
// process's local zone. Normalising keeps both backends returning the same
// time.Time for the same stored value.
//
// PostgreSQL stores a TIMESTAMPTZ as a count of microseconds, so a value
// written with nanosecond precision is read back truncated. That matters in
// exactly one place, the audit chain, which commits to the timestamp as a
// nanosecond count; see prepareAppend in audit.go.
//
// # Isolation and the compare-and-swap operations
//
// The SQLite implementation opens every write transaction with BEGIN IMMEDIATE,
// because a deferred transaction takes its write lock at the first write
// statement and a read-then-write sequence can have its premise invalidated in
// between.
//
// PostgreSQL needs no counterpart for the compare-and-swap operations. A single
// conditional UPDATE ... WHERE <expected value> locks the row it matches for the
// rest of the statement, and a concurrent UPDATE of the same row waits and then
// re-evaluates its own WHERE clause against the committed result. Under READ
// COMMITTED that is already exactly-once: the second writer finds the expected
// value gone and matches nothing. So ConsumeTOTPStep, AdvanceSignCount,
// ConsumeRecoveryCode, ConsumeChallenge and DecideApproval each stay one
// statement and run without a surrounding transaction.
//
// The audit chain append is the one operation that genuinely needs more. It
// reads the chain head and then inserts an entry committing to it, and two
// concurrent appends under READ COMMITTED can both read the same head. That is
// resolved with an advisory lock; see audit.go for why an advisory lock rather
// than LOCK TABLE, and why not SERIALIZABLE with a retry.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/migrations"
)

// Store is the PostgreSQL implementation of store.Store.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	dsn  string
}

// Options configure Open.
type Options struct {
	// DSN is a libpq connection string or a postgres:// URL.
	DSN string

	// MaxConns bounds the pool. Unlike the SQLite implementation there is no
	// separate write limit, for the reason given in the package comment.
	MaxConns int32

	// ConnMaxLifetime recycles a connection after this long. It is worth
	// setting in front of a connection proxy, which may move the backend under
	// a long-lived connection.
	ConnMaxLifetime time.Duration

	Logger *slog.Logger
}

// Open connects to the cluster and configures the pool.
//
// It does not apply migrations. Call Migrate for that, so an operator who
// prefers to review schema changes separately can skip it.
func Open(opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, errors.New("postgres: dsn is required")
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 8
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	cfg.MaxConns = opts.MaxConns
	cfg.MaxConnLifetime = opts.ConnMaxLifetime

	// The pool is created without connecting, then probed below, so that an
	// unreachable cluster is reported by Open rather than by the first query
	// that needs it.
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}

	s := &Store{pool: pool, log: opts.Logger, dsn: opts.DSN}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	return s, nil
}

// Engine implements store.Store.
func (s *Store) Engine() string { return "postgres" }

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}
	return nil
}

// Close implements store.Store.
//
// pgxpool.Close waits for the connections to be returned and reports nothing,
// so unlike the two SQLite pools there is no error to join.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Migrate implements store.Store.
//
// Each migration runs in its own transaction, so a failure leaves the database
// at the last complete version rather than half way through one. PostgreSQL
// supports transactional DDL, which makes this genuinely atomic, including for
// the CREATE FUNCTION and CREATE TRIGGER statements the audit guards need.
func (s *Store) Migrate(ctx context.Context) error {
	set, err := migrations.Load("postgres")
	if err != nil {
		return err
	}

	if err := s.ensureMigrationTable(ctx); err != nil {
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
					"postgres: migration %04d_%s was applied with checksum %s but the "+
						"embedded file now hashes to %s; the database and this binary "+
						"disagree about the schema",
					m.Version, m.Name, prev, m.Checksum)
			}
			continue
		}

		if err := s.inTx(ctx, func(tx pgx.Tx) error {
			for i, stmt := range m.Statements {
				if _, err := tx.Exec(ctx, stmt); err != nil {
					return fmt.Errorf("statement %d: %w\n%s", i+1, err, truncate(stmt, 400))
				}
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES ($1, $2, $3, $4)`,
				m.Version, m.Name, m.Checksum, time.Now().UTC())
			return err
		}); err != nil {
			return fmt.Errorf("postgres: apply migration %04d_%s: %w", m.Version, m.Name, err)
		}

		s.log.InfoContext(ctx, "migration applied",
			slog.Int("version", m.Version), slog.String("name", m.Name))
	}
	return nil
}

// ensureMigrationTable creates the bookkeeping table if the database is new.
// It is written by hand rather than being migration zero, because a migration
// runner cannot record its own first step. The embedded migration files do not
// declare it for the same reason.
func (s *Store) ensureMigrationTable(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER     NOT NULL PRIMARY KEY,
			name        TEXT        NOT NULL,
			checksum    TEXT        NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}
	return nil
}

func (s *Store) appliedMigrations(ctx context.Context) (map[int]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, fmt.Errorf("postgres: scan schema_migrations: %w", err)
		}
		out[v] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate schema_migrations: %w", err)
	}
	return out, nil
}

// inTx runs fn inside a transaction and commits, or rolls back if fn returns an
// error.
//
// The default isolation level is used throughout. READ COMMITTED is enough for
// every transaction here, because the operations that need more than statement
// atomicity take an explicit lock instead; see the package comment.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback after a successful commit returns pgx.ErrTxClosed, which is
		// not a problem and is deliberately ignored.
		_ = tx.Rollback(ctx)
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// SQLSTATE codes this implementation recognises. They are compared as codes
// rather than as message text because the text is localised by the server's
// lc_messages setting and has been reworded between major versions, so a
// mapping built on it breaks silently on a server configured in another
// language. The codes are part of the SQL standard and of PostgreSQL's
// documented interface, and do not move.
const (
	sqlStateUniqueViolation     = "23505"
	sqlStateForeignKeyViolation = "23503"
	sqlStateCheckViolation      = "23514"
	sqlStateRaiseException      = "P0001"
)

// mapError translates a driver error into the sentinel errors declared by the
// store package, so handlers can decide on a status code without importing a
// driver.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	switch pgErr.Code {
	case sqlStateUniqueViolation, sqlStateForeignKeyViolation, sqlStateCheckViolation:
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	case sqlStateRaiseException:
		// The append-only guards in the schema are plpgsql functions that
		// RAISE EXCEPTION with a plain message, which arrives as
		// raise_exception. That code is not specific to them, so the relation
		// the message names is what separates a refused write to the audit
		// tables from any other hand-written exception.
		if namesAuditRelation(pgErr.Message) {
			return fmt.Errorf("%w: %v", store.ErrAppendOnly, err)
		}
	}
	return err
}

// namesAuditRelation reports whether a raise_exception message came from one of
// the append-only guards on the audit tables.
func namesAuditRelation(msg string) bool {
	return strings.Contains(msg, "audit_log") || strings.Contains(msg, "audit_checkpoints")
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// argset accumulates bind arguments and hands out the placeholder that names
// each one.
//
// PostgreSQL numbers its placeholders, so a query assembled from optional
// clauses cannot append a bare "?" the way the SQLite implementation does: the
// number has to stay in step with the argument list, and keeping the two
// together is what stops them drifting apart as clauses are added.
type argset struct {
	args []any
}

func (a *argset) add(v any) string {
	a.args = append(a.args, v)
	return "$" + strconv.Itoa(len(a.args))
}

// utc normalises an instant read from the database.
//
// pgx renders a TIMESTAMPTZ in the process's local zone. The stored value is an
// absolute instant either way, but a caller comparing two time.Time values, or
// formatting one, would otherwise see a different answer from the two backends.
func utc(t time.Time) time.Time { return t.UTC() }

// utcPtr normalises an optional instant, leaving an absent one absent.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
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

// text reads a nullable TEXT column back, mapping NULL to the empty string.
func text(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// The helpers below carry the JSONB columns. PostgreSQL validates the document
// on write, so an invalid one is refused by the column rather than by the
// application, but the empty cases still have to be handled here: pgx encodes a
// nil or empty []byte as SQL NULL or as an empty document, and the schema
// declares these columns NOT NULL.

// jsonArray renders a string slice for a JSONB column declared NOT NULL
// DEFAULT '[]'. A nil or empty slice becomes the empty array rather than a SQL
// NULL, which keeps the column readable without a null check on every scan.
func jsonArray(values []string) ([]byte, error) {
	if len(values) == 0 {
		return []byte("[]"), nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode json array: %w", err)
	}
	return b, nil
}

// decodeJSONArray reads a JSONB array column back.
//
// A NULL column, an empty value and a JSON null all yield an empty slice, so
// the caller iterates the result without a nil check and a row written by an
// operator with psql cannot turn into a nil dereference.
func decodeJSONArray(raw []byte) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("postgres: decode json array %q: %w", truncate(string(raw), 120), err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// jsonObject renders a document for a JSONB column declared NOT NULL DEFAULT
// '{}'. The value is validated before storage even though the column would
// refuse an invalid one, so that the error names the field rather than a
// constraint.
func jsonObject(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	if !json.Valid(raw) {
		return nil, errors.New("postgres: value is not valid json")
	}
	return raw, nil
}

// decodeJSONObject reads a JSONB document column back through encoding/json, so
// a malformed value is reported rather than handed on to a caller that will
// unmarshal it later and blame the wrong layer.
//
// An absent value yields the empty document rather than nil, for the same
// reason as decodeJSONArray.
func decodeJSONObject(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("{}"), nil
	}
	var out json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("postgres: decode json document %q: %w", truncate(string(raw), 120), err)
	}
	if len(out) == 0 {
		out = json.RawMessage("{}")
	}
	return out, nil
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
func clampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}

// escapeLike neutralises the wildcards in a value interpolated into a LIKE
// pattern, so a caller cannot widen the match by including a percent sign.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
