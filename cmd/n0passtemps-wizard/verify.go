package main

import (
	"crypto/hmac"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/crypto/zeroize"
	"github.com/Socold/n0passtemps/internal/store/migrations"
	"github.com/Socold/n0passtemps/internal/subject"
)

// The two outcomes verify distinguishes, and the exit statuses they map to.
//
// An operator puts this in a cron job, so the exit status is the interface and
// a negative verdict has to be told apart from an inability to reach one. A
// keyring that does not open the records is a finding about the backup and
// worth waking someone for; a path typed wrongly is not, and reporting both as
// the same failure would train the operator to ignore the alert.
//
//	0  the trio opens
//	1  the trio does not open: errTrioDoesNotOpen
//	2  verification could not run: errCannotVerify
//
// A missing file is deliberately in the second class, because a file that is
// not there cannot be told apart from a path typed wrongly. A file that is
// there and wrong is in the first.
var (
	errTrioDoesNotOpen = errors.New("the trio does not open")
	errCannotVerify    = errors.New("verification could not run")
)

// sealedColumn is one column holding envelope-encrypted records.
type sealedColumn struct {
	table  string
	column string

	// query lists every sealed value with the identifier of its row, the
	// tenant that owns it, and the subject it belongs to where that is not the
	// row itself. Those three are what the binding context is built from, so
	// the query has to carry them: a record opens only under the context it was
	// sealed with. It is a literal rather than assembled from table and column,
	// for the reason sealedStatementsFor in internal/store/sqlite gives: a
	// statement built from a struct field becomes an injection point the day
	// something sets that field from an argument.
	query string

	// bind builds the context a record of this column is sealed under.
	bind func(rec sealedRecord) envelope.Context
}

func (c sealedColumn) String() string { return c.table + "." + c.column }

// sealedColumns are every column the key encryption keyring protects. Nothing
// else in the schema is sealed under it: recovery codes are Argon2id hashes,
// WebAuthn public keys are stored in clear, and caller credentials are SHA-256
// digests. TROUBLESHOOT.md tabulates that in full.
//
// The filters match the rewrap walk's, so the two agree on which records are
// live. Including a revoked TOTP secret would be worse than useless: a rewrap
// deliberately leaves those on the key version they were sealed under, so the
// day an operator prunes that version this command would report a missing key
// for records nothing will ever read again.
var sealedColumns = []sealedColumn{
	{
		table:  "subjects",
		column: "ref_sealed",
		query: `SELECT id, tenant_id, '', ref_sealed FROM subjects
			WHERE ref_sealed IS NOT NULL AND length(ref_sealed) > 0
			ORDER BY id`,
		bind: func(rec sealedRecord) envelope.Context {
			return envelope.SubjectRef(rec.tenantID, rec.id)
		},
	},
	{
		table:  "totp_secrets",
		column: "secret_sealed",
		query: `SELECT id, tenant_id, subject_id, secret_sealed FROM totp_secrets
			WHERE secret_sealed IS NOT NULL AND length(secret_sealed) > 0
			AND revoked_at IS NULL
			ORDER BY id`,
		bind: func(rec sealedRecord) envelope.Context {
			return envelope.TOTPSecret(rec.tenantID, rec.subjectID, rec.id)
		},
	},
}

// runVerify checks that a database, a keyring and a pepper belong together.
//
// It exists because the three artefacts are backed up separately, on purpose,
// and nothing until now confirmed that a given trio still opens. An operator
// found that out during a restore, which is the worst moment available.
//
// The command is read-only on every artefact, and deliberately diagnostic: it
// says which key version is missing and how many records need it. That is the
// opposite of the API surface, where a precise refusal is an oracle and the
// envelope package returns errors coarse enough to be useless to an attacker.
// The difference is the audience. This runs on the operator's own host, against
// their own backup, for someone who already holds all three secrets and needs
// to know which one is wrong. Do not "harden" these messages: a verification
// tool that will not say what is wrong has no reason to exist.
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite database file to check, a backup copy or the live file")
	keyringPath := fs.String("keyring", "", "keyring file the records are expected to be sealed under")
	pepperEnv := fs.String("pepper-env", config.Default().Subject.PepperEnv,
		"environment variable holding the subject pepper")
	ref := fs.String("ref", "", "a subject reference known to exist, used to check the pepper "+
		"when no subject in the database has a sealed reference")
	all := fs.Bool("all", false, "unseal every sealed record rather than one per key version")
	fs.Usage = func() { verifyUsage(fs) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" || *keyringPath == "" {
		return fmt.Errorf("%w: -db and -keyring are both required, and the pepper is read "+
			"from %s; run with -h for the whole story", errCannotVerify, *pepperEnv)
	}

	pepper, err := loadPepper(*pepperEnv)
	if err != nil {
		return err
	}
	defer zeroize.Bytes(pepper)

	keyring, mode, err := openKeyring(*keyringPath)
	if err != nil {
		return err
	}
	defer func() { _ = keyring.Close() }()

	db, err := openReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	versions := keyring.Versions()
	current, currentKey, err := keyring.Current()
	if err != nil {
		return fmt.Errorf("%w: %v", errTrioDoesNotOpen, err)
	}
	zeroize.Bytes(currentKey)

	fmt.Printf("Database:  %s\n", *dbPath)
	fmt.Printf("Keyring:   %s (mode %#o, current version %d, retained %v)\n",
		*keyringPath, mode, current, versions)
	fmt.Printf("Pepper:    %s (%d bytes)\n\n", *pepperEnv, len(pepper))
	fmt.Print("The database is open read-only, so verifying it cannot change it. " +
		"Nothing\nbelow writes, migrates or upgrades anything.\n\n")

	if placed := keyringBesideDatabase(*keyringPath, *dbPath); placed != "" {
		fmt.Print("The keyring sits in the same directory as the database. That is fine for a\n" +
			"drill on copies, and the server would refuse it in production: a key stored\n" +
			"beside the ciphertext it protects gives no confidentiality if the volume is\n" +
			"copied.\n\n")
		fmt.Printf("  both in    %s\n\n", placed)
	}

	if err = checkIntegrity(db, *dbPath); err != nil {
		return err
	}
	if err = reportSchema(db, *dbPath); err != nil {
		return err
	}

	sealer := envelope.NewSealer(keyring)

	censuses, err := takeCensus(db, *all)
	if err != nil {
		return err
	}
	if err = reportCensus(censuses, versions); err != nil {
		return err
	}
	unsealed, err := unsealSample(sealer, censuses)
	if err != nil {
		return err
	}
	pepperProof, err := checkPepper(db, sealer, pepper, *ref)
	if err != nil {
		return err
	}

	fmt.Print("\nThe trio opens.\n\n")
	reportScope(unsealed, censuses, versions, pepperProof)
	return nil
}

// verifyUsage prints the command's own help.
//
// The PostgreSQL scoping is stated here rather than only in the documentation,
// because the operator who needs it is the one running the command against a
// pg_dump file and wondering why there is no -dsn flag.
func verifyUsage(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, "n0passtemps-wizard verify checks that a database, a keyring and a pepper\n"+
		"belong together, before a disaster rather than during one.\n\n"+
		"Usage:\n  n0passtemps-wizard verify -db <file> -keyring <file> [flags]\n\n"+
		"It unseals real records under the keyring and recomputes a subject lookup\n"+
		"value under the pepper, so it reports whether the keyring actually opens what\n"+
		"this database holds rather than whether three files parse.\n\n"+
		"The database is opened through SQLite's read-only mode. A write, including a\n"+
		"migration, is refused by SQLite itself and not merely avoided by this code.\n\n"+
		"SQLite only. A PostgreSQL backup is a pg_dump archive, which cannot be read\n"+
		"without restoring it into a server first, so \"here are my three artefacts\"\n"+
		"has no meaning for it; and once restored, the guarantee that verification\n"+
		"cannot write comes from the role's privileges rather than from how a file was\n"+
		"opened. Restore into a scratch database and check there instead: DEPLOYMENT.md\n"+
		"gives the sequence.\n\n"+
		"Exit status:\n"+
		"  0  the trio opens\n"+
		"  1  the trio does not open\n"+
		"  2  verification could not run, so no verdict was reached\n\n"+
		"Flags:\n")
	fs.PrintDefaults()
}

// loadPepper reads the pepper from the environment, as the server does.
//
// It is taken from a variable and never from a flag: an argument is visible in
// ps and in the shell history of every operator who runs a drill.
func loadPepper(envVar string) ([]byte, error) {
	raw, ok := os.LookupEnv(envVar)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: %s is not set. Export the pepper from your backup, "+
			"or name the variable holding it with -pepper-env", errCannotVerify, envVar)
	}

	pepper, err := subject.DecodePepper(raw)
	if err != nil {
		// The variable is set and holds something, so this is a finding about
		// the artefact rather than a failure to invoke the command.
		return nil, fmt.Errorf("%w: %s does not decode as a pepper: %v", errTrioDoesNotOpen, envVar, err)
	}
	if len(pepper) < subject.MinPepperBytes {
		zeroize.Bytes(pepper)
		return nil, fmt.Errorf("%w: %s holds %d bytes and at least %d are required. The "+
			"server would refuse to start with it", errTrioDoesNotOpen, envVar, len(pepper),
			subject.MinPepperBytes)
	}
	return pepper, nil
}

// openKeyring loads the keyring and reports the mode it was found with.
//
// No data directories are passed to the provider, so the keyring is not judged
// on where it sits. The server refuses a keyring inside its own data directory
// and is right to, but a restore drill routinely unpacks all three artefacts
// into one scratch directory, and failing that arrangement would answer a
// question nobody asked. The placement is reported instead, by the caller.
func openKeyring(path string) (*kek.FileProvider, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: cannot read %s: %v", errCannotVerify, path, err)
	}

	provider, err := kek.LoadFileProvider(path)
	if err != nil {
		// Mode, key length, key version numbering and a current version naming
		// an absent key all arrive here, already phrased for an operator by the
		// kek package. A keyring the server would refuse is a trio that does
		// not open, whatever else is right about it.
		return nil, info.Mode().Perm(), fmt.Errorf("%w: %v", errTrioDoesNotOpen, err)
	}
	return provider, info.Mode().Perm(), nil
}

// openReadOnly opens the database in a way that makes writing impossible rather
// than merely unintended.
//
// How the guarantee is made, in three parts.
//
// First, mode=ro in the URI. SQLite opens the file with O_RDONLY and refuses
// every write against the handle with SQLITE_READONLY, so a write is rejected
// by the engine and not by a convention in this file. query_only(1) is set as
// well; it is redundant against mode=ro and costs nothing, and it means a later
// change that loses the URI parameter still fails closed.
//
// Second, this file does not use internal/store. It opens database/sql itself,
// so Migrate is not reachable from here: there is no object in scope that has
// the method. A verification tool that could migrate the artefact it is
// verifying would be worse than none, and the strongest way to promise it does
// not is to not hold the means.
//
// Third, what is not guaranteed, stated plainly. Reading a database in WAL mode
// makes SQLite build a write-ahead log index, which it keeps in a sibling
// "-shm" file; that file may be created next to the backup. The backup's own
// bytes, database and log alike, are not touched. A directory that must stay
// untouched therefore wants a copy, and the documentation says so.
//
// immutable=1 would avoid the sibling file and was rejected: it tells SQLite the
// file cannot change, which makes it skip the write-ahead log entirely. A
// database copied together with its log then reads as though the log's
// transactions were never committed, and the verification would pass against a
// stale view of the data. Silence about the most recent records is the one
// failure this command must not have.
func openReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", errCannotVerify, path, err)
	}

	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", errCannotVerify, path, err)
	}

	var queryOnly string
	if err := db.QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil {
		_ = db.Close()
		// A database file this damaged cannot answer a pragma. It is still a
		// finding about the backup: the file is there and it is not readable.
		return nil, fmt.Errorf("%w: %s cannot be read as a SQLite database: %v",
			errTrioDoesNotOpen, path, err)
	}
	if queryOnly != "1" {
		_ = db.Close()
		return nil, fmt.Errorf("%w: the read-only handle on %s reports query_only=%q; "+
			"refusing to continue rather than risk writing to the artefact being verified",
			errCannotVerify, path, queryOnly)
	}
	return db, nil
}

// readOnlyDSN builds the read-only connection string.
//
// The path is escaped, because SQLite reads it out of a URI and an operator's
// path may hold a character that a URI gives a meaning to. The pragmas that
// internal/store sets are deliberately absent: journal_mode(WAL) writes to the
// database header, which a read-only handle refuses, and none of the others
// affects reading a sealed blob.
func readOnlyDSN(path string) string {
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// keyringBesideDatabase reports the directory both artefacts share, if they do.
func keyringBesideDatabase(keyringPath, dbPath string) string {
	kekDir, err := filepath.Abs(filepath.Dir(keyringPath))
	if err != nil {
		return ""
	}
	dbDir, err := filepath.Abs(filepath.Dir(dbPath))
	if err != nil {
		return ""
	}
	if kekDir != dbDir {
		return ""
	}
	return kekDir
}

// checkIntegrity runs SQLite's own structural check.
//
// quick_check rather than integrity_check: it skips index content verification,
// which halves the work and does not matter here, because nothing this command
// reads comes from an index. It is what turns a truncated backup into one clear
// line instead of a puzzling failure several steps later.
func checkIntegrity(db *sql.DB, path string) error {
	var result string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("%w: %s does not read as a SQLite database, so nothing in it "+
			"can be verified: %v", errTrioDoesNotOpen, path, err)
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("%w: SQLite reports %s as damaged: %s", errTrioDoesNotOpen, path, result)
	}
	fmt.Printf("Integrity:  SQLite reports the file structure as ok\n")
	return nil
}

// reportSchema compares the schema the database carries with the one this
// binary knows.
//
// A database from a newer build is refused rather than read. The tables this
// command walks may well still be there, but a binary that does not know what
// changed cannot say that what it read is all there was, and a verification
// that quietly covered less than it claimed is the failure mode this command
// exists to remove.
func reportSchema(db *sql.DB, path string) error {
	known, err := migrations.Load("sqlite")
	if err != nil {
		return fmt.Errorf("%w: %v", errCannotVerify, err)
	}
	knownByVersion := make(map[int]migrations.Migration, len(known))
	highestKnown := 0
	for _, m := range known {
		knownByVersion[m.Version] = m
		if m.Version > highestKnown {
			highestKnown = m.Version
		}
	}

	rows, err := db.Query(`SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("%w: %s has no schema_migrations table, so it is not a database "+
			"this service wrote: %v", errTrioDoesNotOpen, path, err)
	}
	defer func() { _ = rows.Close() }()

	var (
		applied    int
		highest    int
		lastName   string
		unknown    []int
		mismatched []string
	)
	for rows.Next() {
		var (
			version  int
			name     string
			checksum string
		)
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			return fmt.Errorf("%w: reading schema_migrations: %v", errTrioDoesNotOpen, err)
		}
		applied++
		if version > highest {
			highest = version
			lastName = name
		}
		m, ok := knownByVersion[version]
		if !ok {
			unknown = append(unknown, version)
			continue
		}
		if m.Checksum != checksum {
			mismatched = append(mismatched, fmt.Sprintf("%04d_%s", version, name))
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: reading schema_migrations: %v", errTrioDoesNotOpen, err)
	}
	if applied == 0 {
		return fmt.Errorf("%w: schema_migrations is empty, so this database has never been "+
			"migrated and holds nothing to verify", errTrioDoesNotOpen)
	}

	if len(unknown) > 0 {
		return fmt.Errorf("%w: the database has migration %v applied and this binary only "+
			"carries %d. It was written by a newer version; verify it with that version's "+
			"binary", errCannotVerify, unknown, highestKnown)
	}
	if len(mismatched) > 0 {
		return fmt.Errorf("%w: %s was applied with a different checksum from the one this "+
			"binary embeds, so the database and this binary disagree about the schema",
			errCannotVerify, strings.Join(mismatched, ", "))
	}

	fmt.Printf("Schema:     %d %s applied, through %04d_%s\n",
		applied, plural(applied, "migration", "migrations"), highest, lastName)
	if highest < highestKnown {
		// Stated as a fact, not reassured about. Which sealed columns exist is
		// reported below from what the database actually holds, so an older
		// schema narrows the report rather than invalidating it.
		fmt.Printf("            this binary carries %d, so the database is behind it\n", highestKnown)
	}
	return nil
}

// sealedRecord is one envelope-encrypted value and the row it came from.
type sealedRecord struct {
	id        string
	tenantID  string
	subjectID string
	sealed    []byte
}

// columnCensus is what one sealed column holds, grouped by key version.
type columnCensus struct {
	column    sealedColumn
	total     int
	counts    map[uint32]int
	toUnseal  map[uint32][]sealedRecord
	malformed []string
}

// versions returns the key versions present, in ascending order.
func (c *columnCensus) versions() []uint32 {
	out := make([]uint32, 0, len(c.counts))
	for v := range c.counts {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// takeCensus reads the key version out of every sealed record's header.
//
// The walk spans every tenant, because one keyring serves all of them, which is
// the same reason the rewrap walk in internal/store is not tenant-scoped.
//
// Reading the version needs no key: it is bytes 2 to 5 of the record. That is
// what lets this command report "no key version 2, which 143 records need"
// rather than only "something did not decrypt".
func takeCensus(db *sql.DB, all bool) ([]*columnCensus, error) {
	out := make([]*columnCensus, 0, len(sealedColumns))
	for _, col := range sealedColumns {
		c := &columnCensus{
			column:   col,
			counts:   map[uint32]int{},
			toUnseal: map[uint32][]sealedRecord{},
		}

		rows, err := db.Query(col.query)
		if err != nil {
			return nil, fmt.Errorf("%w: reading %s: %v", errTrioDoesNotOpen, col, err)
		}

		for rows.Next() {
			var rec sealedRecord
			if err := rows.Scan(&rec.id, &rec.tenantID, &rec.subjectID, &rec.sealed); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("%w: reading %s: %v", errTrioDoesNotOpen, col, err)
			}
			c.total++

			version, err := envelope.KEKVersion(rec.sealed)
			if err != nil {
				c.malformed = append(c.malformed, rec.id)
				continue
			}
			c.counts[version]++
			// One record per version is enough to prove the key opens that
			// version. -all trades the time for covering every row, which is
			// the integrity sweep rather than the key check.
			if all || len(c.toUnseal[version]) == 0 {
				c.toUnseal[version] = append(c.toUnseal[version], rec)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("%w: reading %s: %v", errTrioDoesNotOpen, col, err)
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("%w: reading %s: %v", errTrioDoesNotOpen, col, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// reportCensus prints the record counts and refuses a keyring that is missing a
// version the data needs.
func reportCensus(censuses []*columnCensus, held []uint32) error {
	heldSet := make(map[uint32]bool, len(held))
	for _, v := range held {
		heldSet[v] = true
	}

	total := 0
	for _, c := range censuses {
		total += c.total
	}
	if total == 0 {
		empty := make([]string, 0, len(censuses))
		for _, c := range censuses {
			empty = append(empty, c.column.String())
		}
		return fmt.Errorf("%w: nothing in this database is sealed, so it cannot show that "+
			"this keyring opens anything. %s hold no records. Verify a database that has at "+
			"least one subject or one TOTP enrolment in it",
			errCannotVerify, strings.Join(empty, " and "))
	}

	fmt.Print("\nSealed records, across every tenant, by the key version they were sealed\nunder:\n\n")
	var missing []string
	for _, c := range censuses {
		if c.total == 0 {
			fmt.Printf("  %-28s no records\n", c.column)
			continue
		}
		for _, v := range c.versions() {
			state := "key present"
			if !heldSet[v] {
				state = "KEY MISSING"
				missing = append(missing, fmt.Sprintf("version %d, which %d %s in %s %s "+
					"sealed under", v, c.counts[v],
					plural(c.counts[v], "record", "records"), c.column,
					plural(c.counts[v], "is", "are")))
			}
			fmt.Printf("  %-28s version %-4d %5d %-8s %s\n", c.column, v, c.counts[v],
				plural(c.counts[v], "record", "records"), state)
		}
		if len(c.malformed) > 0 {
			fmt.Printf("  %-28s %d %s with no envelope header\n", c.column, len(c.malformed),
				plural(len(c.malformed), "record", "records"))
		}
	}

	for _, c := range censuses {
		if len(c.malformed) > 0 {
			return fmt.Errorf("%w: %d %s in %s do not begin with an envelope header, so the "+
				"column has been damaged or written by something other than this service. "+
				"First: %s", errTrioDoesNotOpen, len(c.malformed),
				plural(len(c.malformed), "record", "records"), c.column, c.malformed[0])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the keyring has no key %s. Find the keyring that holds %s, "+
			"or accept that those records are unreadable; TROUBLESHOOT.md says exactly what "+
			"that costs", errTrioDoesNotOpen, strings.Join(missing, "; and no key "),
			plural(len(missing), "it", "them"))
	}
	return nil
}

// unsealSample decrypts real records, which is the point of the command.
//
// Parsing the keyring proves that it is a keyring. Opening a record proves that
// it is this database's keyring, because the payload is authenticated: AES-GCM
// rejects a wrong key rather than returning plausible plaintext.
func unsealSample(sealer *envelope.Sealer, censuses []*columnCensus) (int, error) {
	unsealed := 0
	for _, c := range censuses {
		for _, v := range c.versions() {
			for _, rec := range c.toUnseal[v] {
				plain, err := sealer.Unseal(rec.sealed, c.column.bind(rec))
				if err != nil {
					// The envelope package will not say which of the two it is,
					// and cannot: an authenticated cipher that distinguished a
					// wrong key from a damaged record would be an oracle. So
					// both are named, because the operator's next step differs.
					return unsealed, fmt.Errorf("%w: record %s in %s is sealed under key "+
						"version %d and that key did not open it. Either the keyring holds a "+
						"different key under that version, or the record is damaged; the "+
						"cipher cannot tell those apart, so both are possible",
						errTrioDoesNotOpen, rec.id, c.column, v)
				}
				// The plaintext is a TOTP secret or a subject reference. It is
				// zeroized and never printed, here or anywhere below.
				zeroize.Bytes(plain)
				unsealed++
			}
		}
	}

	fmt.Printf("\nUnsealed %d %s and every one authenticated.\n", unsealed,
		plural(unsealed, "record", "records"))
	return unsealed, nil
}

// pepperProof records how the pepper was checked, for the closing summary.
type pepperProof struct {
	method    string // how the lookup value was recovered, for the summary
	subjectID string
}

// checkPepper recomputes a stored lookup value and matches it against the row.
//
// The strong form needs both the keyring and the pepper: unseal a subject's
// reference, recompute the HMAC of the plaintext under the pepper, and compare
// it with the ref_hmac the row was found by. A pepper that produces the stored
// value is the pepper this database was written with, and nothing short of
// deriving it demonstrates that.
//
// When no subject has a sealed reference, because subject.seal_reference was
// off, there is nothing to recompute from and the operator has to supply a
// reference they know exists. That path is weaker and says so: a miss means
// either a wrong pepper or a reference that was never enrolled here.
func checkPepper(db *sql.DB, sealer *envelope.Sealer, pepper []byte, ref string) (pepperProof, error) {
	var (
		id       string
		tenantID string
		refHMAC  []byte
		sealed   []byte
	)
	err := db.QueryRow(`SELECT id, tenant_id, ref_hmac, ref_sealed FROM subjects
		WHERE ref_sealed IS NOT NULL AND length(ref_sealed) > 0
		ORDER BY id LIMIT 1`).Scan(&id, &tenantID, &refHMAC, &sealed)

	switch {
	case err == nil:
		plain, uerr := sealer.Unseal(sealed, envelope.SubjectRef(tenantID, id))
		if uerr != nil {
			return pepperProof{}, fmt.Errorf("%w: the sealed reference of subject %s did not "+
				"open, so the pepper cannot be checked against it", errTrioDoesNotOpen, id)
		}
		defer zeroize.Bytes(plain)

		if !hmac.Equal(refHMAC, subject.RefHMAC(pepper, string(plain))) {
			return pepperProof{}, fmt.Errorf("%w: the pepper does not derive the stored lookup "+
				"value of subject %s. The keyring is right and this pepper is not the one this "+
				"database was written with; with it, no existing subject can be found at all",
				errTrioDoesNotOpen, id)
		}
		fmt.Print("Recomputed a subject's lookup value from its sealed reference under the\n" +
			"pepper, and it matches the value stored on the row.\n")
		fmt.Printf("  subject    %s\n", id)
		return pepperProof{method: "sealed reference", subjectID: id}, nil

	case !errors.Is(err, sql.ErrNoRows):
		return pepperProof{}, fmt.Errorf("%w: reading subjects: %v", errTrioDoesNotOpen, err)
	}

	// No sealed reference anywhere. Fall back to a reference the operator names.
	if ref == "" {
		return pepperProof{}, fmt.Errorf("%w: no subject in this database has a sealed "+
			"reference, so there is nothing to recompute the pepper against. Either "+
			"subject.seal_reference was off when these subjects were created, or there are no "+
			"subjects. Pass -ref with a reference you know is enrolled and the pepper will be "+
			"checked against its stored lookup value. The keyring and the database were "+
			"verified; the pepper was not", errCannotVerify)
	}

	// The reference is the application's own user identifier, so it is matched
	// and never echoed: the outcome is printed as a subject identifier.
	err = db.QueryRow(`SELECT id FROM subjects WHERE ref_hmac = ? LIMIT 1`,
		subject.RefHMAC(pepper, ref)).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return pepperProof{}, fmt.Errorf("%w: no subject matches the lookup value this pepper "+
			"derives for the reference given. Either the pepper is not this database's, or "+
			"that reference was never enrolled here. Those two cannot be told apart from "+
			"outside, so confirm the reference before replacing the pepper", errTrioDoesNotOpen)
	case err != nil:
		return pepperProof{}, fmt.Errorf("%w: looking the reference up: %v", errTrioDoesNotOpen, err)
	}
	fmt.Print("The reference supplied derives the lookup value stored on a subject row, so\n" +
		"the pepper belongs to this database.\n")
	fmt.Printf("  subject    %s\n", id)
	return pepperProof{method: "reference supplied with -ref", subjectID: id}, nil
}

// reportScope states what the run proved and what it left alone.
//
// The second half is the part that earns the command its trust. A verification
// that reports only successes invites the belief that everything was covered,
// and an operator acting on that belief is worse off than one who read a
// caveat.
func reportScope(unsealed int, censuses []*columnCensus, held []uint32, proof pepperProof) {
	covered := map[uint32]bool{}
	sealedTotal := 0
	for _, c := range censuses {
		sealedTotal += c.total
		for _, v := range c.versions() {
			covered[v] = true
		}
	}

	fmt.Print("Proved:\n")
	fmt.Printf("  This keyring opens the envelope-encrypted records in this database. %d\n"+
		"  %s decrypted and authenticated, not merely parsed.\n", unsealed,
		plural(unsealed, "record was", "records were"))
	fmt.Printf("  This pepper derives a stored lookup value in this database, recomputed\n"+
		"  from the %s of subject %s.\n", proof.method, proof.subjectID)

	fmt.Print("\nNot proved:\n")
	if unsealed < sealedTotal {
		fmt.Printf("  The other %d sealed %s were not decrypted; one per key version per\n"+
			"  column was. Pass -all for the whole sweep.\n", sealedTotal-unsealed,
			plural(sealedTotal-unsealed, "record", "records"))
	}
	var idle []string
	for _, v := range held {
		if !covered[v] {
			idle = append(idle, fmt.Sprintf("%d", v))
		}
	}
	if len(idle) > 0 {
		fmt.Printf("  Key %s %s %s in the keyring and nothing in this database is sealed\n"+
			"  under %s, so %s untested. That is the normal state after a rotation\n"+
			"  and a rewrap.\n",
			plural(len(idle), "version", "versions"), strings.Join(idle, ", "),
			plural(len(idle), "is", "are"),
			plural(len(idle), "it", "them"), plural(len(idle), "it is", "they are"))
	}
	fmt.Print("  The other subjects' references were not each recomputed, only the one\n" +
		"  named above. One match is enough: a pepper that derives one stored value\n" +
		"  derives all of them.\n")
	fmt.Print("  The Ed25519 key that signs assertions is not part of this trio and was\n" +
		"  not read. Check it with \"assertion-key inspect\".\n")
	fmt.Print("  Recovery codes, WebAuthn credentials and caller credentials are not\n" +
		"  sealed under the keyring, so they neither pass nor fail here. They survive\n" +
		"  its loss entirely; TROUBLESHOOT.md tabulates that.\n")
	fmt.Print("  The audit hash chain was not verified. It needs no key and is checked\n" +
		"  through the running service, with GET /admin/v1/audit/verify.\n")
}

// plural picks a word for a count, so a report does not say "1 records".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
