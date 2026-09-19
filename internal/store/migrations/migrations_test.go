package migrations

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "plain statements",
			sql:  "CREATE TABLE a (id INT);\nCREATE TABLE b (id INT);",
			want: []string{"CREATE TABLE a (id INT)", "CREATE TABLE b (id INT)"},
		},
		{
			name: "final statement without a semicolon",
			sql:  "SELECT 1;\nSELECT 2",
			want: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name: "empty statements are dropped",
			sql:  ";;\n SELECT 1 ;; \n;",
			want: []string{"SELECT 1"},
		},
		{
			name: "empty input",
			sql:  "  \n\t ",
			want: nil,
		},
		{
			name: "semicolon inside a string literal",
			sql:  "INSERT INTO t VALUES ('a;b');SELECT 2;",
			want: []string{"INSERT INTO t VALUES ('a;b')", "SELECT 2"},
		},
		{
			// The doubled quote must not end the literal, or the semicolon
			// after it would be read as a separator.
			name: "escaped quote before a semicolon inside a string literal",
			sql:  "INSERT INTO t VALUES ('it''s;here');SELECT 2;",
			want: []string{"INSERT INTO t VALUES ('it''s;here')", "SELECT 2"},
		},
		{
			name: "string literal ending in an escaped quote",
			sql:  "SELECT 'a;''';SELECT 2;",
			want: []string{"SELECT 'a;'''", "SELECT 2"},
		},
		{
			name: "semicolon inside a double-quoted identifier",
			sql:  `CREATE TABLE "odd;name" (id INT);SELECT 2;`,
			want: []string{`CREATE TABLE "odd;name" (id INT)`, "SELECT 2"},
		},
		{
			name: "doubled quote inside a double-quoted identifier",
			sql:  `CREATE TABLE "odd"";name" (id INT);SELECT 2;`,
			want: []string{`CREATE TABLE "odd"";name" (id INT)`, "SELECT 2"},
		},
		{
			name: "semicolon inside a backtick identifier",
			sql:  "CREATE TABLE `odd;name` (id INT);SELECT 2;",
			want: []string{"CREATE TABLE `odd;name` (id INT)", "SELECT 2"},
		},
		{
			name: "semicolon inside a line comment",
			sql:  "SELECT 1 -- not; a separator\n, 2;SELECT 3;",
			want: []string{"SELECT 1 \n, 2", "SELECT 3"},
		},
		{
			// A quote inside a comment must not open a literal, or the rest
			// of the file would be swallowed into one statement.
			name: "apostrophe inside a line comment",
			sql:  "-- the operator's note\nSELECT 1;SELECT 2;",
			want: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name: "comment marker inside a string literal is data",
			sql:  "SELECT '--not a comment';SELECT 2;",
			want: []string{"SELECT '--not a comment'", "SELECT 2"},
		},
		{
			name: "semicolon inside a block comment",
			sql:  "SELECT 1 /* not; a\nseparator; */ , 2;SELECT 3;",
			want: []string{"SELECT 1   , 2", "SELECT 3"},
		},
		{
			name: "file containing only comments",
			sql:  "-- nothing here;\n/* nor; here */\n",
			want: nil,
		},
		{
			name: "sqlite trigger body stays one statement",
			sql: "CREATE TRIGGER guard BEFORE UPDATE ON t\n" +
				"BEGIN\n" +
				"    SELECT RAISE(ABORT, 'no; updates');\n" +
				"    DELETE FROM u;\n" +
				"END;\n" +
				"CREATE TABLE after_it (id INT);",
			want: []string{
				"CREATE TRIGGER guard BEFORE UPDATE ON t\n" +
					"BEGIN\n" +
					"    SELECT RAISE(ABORT, 'no; updates');\n" +
					"    DELETE FROM u;\n" +
					"END",
				"CREATE TABLE after_it (id INT)",
			},
		},
		{
			name: "begin and end are matched case-insensitively",
			sql:  "CREATE TRIGGER g BEFORE DELETE ON t begin SELECT 1; SELECT 2; End;SELECT 3;",
			want: []string{"CREATE TRIGGER g BEFORE DELETE ON t begin SELECT 1; SELECT 2; End", "SELECT 3"},
		},
		{
			// Substrings of longer words must not move the nesting depth. If
			// BEGINNING counted as BEGIN the rest of the file would become one
			// statement; if ENDPOINT counted as END a trigger would be cut in
			// the middle and its guard silently not installed.
			name: "BEGINNING and ENDPOINT are ordinary words",
			sql:  "CREATE TABLE beginning (endpoint TEXT, the_end TEXT, begin_at TEXT);SELECT 2;",
			want: []string{"CREATE TABLE beginning (endpoint TEXT, the_end TEXT, begin_at TEXT)", "SELECT 2"},
		},
		{
			name: "ENDPOINT inside a trigger body does not close it",
			sql:  "CREATE TRIGGER g BEFORE UPDATE ON t BEGIN UPDATE u SET endpoint = 1; SELECT 2; END;SELECT 3;",
			want: []string{"CREATE TRIGGER g BEFORE UPDATE ON t BEGIN UPDATE u SET endpoint = 1; SELECT 2; END", "SELECT 3"},
		},
		{
			name: "BEGIN inside a string literal is data",
			sql:  "SELECT 'BEGIN';SELECT 2;",
			want: []string{"SELECT 'BEGIN'", "SELECT 2"},
		},
		{
			name: "END outside any body is ignored",
			sql:  "SELECT 1 AS \"end\", 2 AS END;SELECT 3;",
			want: []string{"SELECT 1 AS \"end\", 2 AS END", "SELECT 3"},
		},
		{
			name: "postgres dollar-quoted body stays one statement",
			sql: "CREATE FUNCTION f() RETURNS TRIGGER AS $$\n" +
				"BEGIN\n" +
				"    RAISE EXCEPTION 'no; updates';\n" +
				"    RETURN NULL;\n" +
				"END;\n" +
				"$$ LANGUAGE plpgsql;\n" +
				"SELECT 2;",
			want: []string{
				"CREATE FUNCTION f() RETURNS TRIGGER AS $$\n" +
					"BEGIN\n" +
					"    RAISE EXCEPTION 'no; updates';\n" +
					"    RETURN NULL;\n" +
					"END;\n" +
					"$$ LANGUAGE plpgsql",
				"SELECT 2",
			},
		},
		{
			name: "tagged dollar-quoted body stays one statement",
			sql:  "CREATE FUNCTION f() RETURNS INT AS $body$ SELECT 1; SELECT 2; $body$ LANGUAGE sql;SELECT 3;",
			want: []string{"CREATE FUNCTION f() RETURNS INT AS $body$ SELECT 1; SELECT 2; $body$ LANGUAGE sql", "SELECT 3"},
		},
		{
			name: "a different tag inside a tagged body does not close it",
			sql:  "CREATE FUNCTION f() RETURNS INT AS $tag$ SELECT $other$a;b$other$; SELECT 2; $tag$ LANGUAGE sql;SELECT 3;",
			want: []string{"CREATE FUNCTION f() RETURNS INT AS $tag$ SELECT $other$a;b$other$; SELECT 2; $tag$ LANGUAGE sql", "SELECT 3"},
		},
		{
			name: "anonymous dollars inside a tagged body do not close it",
			sql:  "CREATE FUNCTION f() RETURNS INT AS $tag$ SELECT $$a;b$$; $tag$ LANGUAGE sql;SELECT 3;",
			want: []string{"CREATE FUNCTION f() RETURNS INT AS $tag$ SELECT $$a;b$$; $tag$ LANGUAGE sql", "SELECT 3"},
		},
		{
			// Inside a dollar quote BEGIN and END are text. An unmatched BEGIN
			// there must not leave the depth raised for the rest of the file.
			name: "unmatched BEGIN inside a dollar quote is text",
			sql:  "SELECT $$ BEGIN $$;SELECT 2;",
			want: []string{"SELECT $$ BEGIN $$", "SELECT 2"},
		},
		{
			// $1 is a positional parameter, not the opening of a quote: a tag
			// may not start with a digit.
			name: "positional parameters are not dollar quotes",
			sql:  "SELECT $1, $2;SELECT 3;",
			want: []string{"SELECT $1, $2", "SELECT 3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Split(tc.sql)
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("a wrongly cut statement installs half a guard or none\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestSplitErrors(t *testing.T) {
	// Each of these is a file the scanner cannot cut reliably. Refusing it is
	// the safe outcome: the alternative is applying a schema whose statement
	// boundaries were guessed.
	tests := []struct {
		name    string
		sql     string
		wantErr string
	}{
		{"unterminated block comment", "SELECT 1; /* never closed", "unterminated block comment"},
		{"unterminated dollar quote", "CREATE FUNCTION f() AS $$ SELECT 1;", "unterminated dollar quote"},
		{"dollar quote closed by the wrong tag", "CREATE FUNCTION f() AS $a$ SELECT 1; $b$;", "unterminated dollar quote $a$"},
		{"unbalanced BEGIN", "CREATE TRIGGER g BEFORE UPDATE ON t BEGIN SELECT 1;", "unbalanced BEGIN"},
		{"nested BEGIN closed once", "CREATE TRIGGER g BEFORE UPDATE ON t BEGIN BEGIN SELECT 1; END;", "unbalanced BEGIN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Split(tc.sql)
			if err == nil {
				t.Fatalf("malformed SQL was accepted and cut into %q", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

var engines = []string{"sqlite", "postgres"}

func mustLoad(t *testing.T, engine string) []Migration {
	t.Helper()
	ms, err := Load(engine)
	if err != nil {
		t.Fatalf("Load(%q): %v", engine, err)
	}
	if len(ms) == 0 {
		t.Fatalf("Load(%q) returned no migrations", engine)
	}
	return ms
}

func TestLoad(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)

	for _, engine := range engines {
		t.Run(engine, func(t *testing.T) {
			ms := mustLoad(t, engine)

			seenSums := map[string]int{}
			for i, m := range ms {
				// The runner applies in this order and records each version.
				// A gap or a start other than 1 means a file is missing from
				// the build, and the schema it would have created with it.
				if want := i + 1; m.Version != want {
					t.Errorf("migration %d has version %d, want %d: versions must ascend from 1 with no gaps", i, m.Version, want)
				}
				if m.Name == "" {
					t.Errorf("version %d has no name", m.Version)
				}
				if !hex64.MatchString(m.Checksum) {
					t.Errorf("version %d checksum %q is not 64 lowercase hex characters: an edited migration could not be told from the applied one", m.Version, m.Checksum)
				}
				if prev, dup := seenSums[m.Checksum]; dup {
					t.Errorf("versions %d and %d share a checksum", prev, m.Version)
				}
				seenSums[m.Checksum] = m.Version

				if len(m.Statements) == 0 {
					t.Errorf("version %d has no statements", m.Version)
				}
				for _, s := range m.Statements {
					if strings.TrimSpace(s) == "" {
						t.Errorf("version %d contains an empty statement", m.Version)
					}
					if strings.HasSuffix(s, ";") {
						t.Errorf("version %d statement keeps its separator: %q", m.Version, tail(s))
					}
				}
			}
		})
	}

	t.Run("checksums are stable between loads", func(t *testing.T) {
		a, b := mustLoad(t, "sqlite"), mustLoad(t, "sqlite")
		for i := range a {
			if a[i].Checksum != b[i].Checksum {
				t.Errorf("version %d checksum changed between two loads of the same binary", a[i].Version)
			}
		}
	})

	t.Run("unknown engine", func(t *testing.T) {
		// The engine name is joined into an embedded path, so anything outside
		// the two known values must be refused before it is used.
		for _, engine := range []string{"", "mysql", "SQLite", "../sqlite", "sqlite/"} {
			if ms, err := Load(engine); err == nil {
				t.Errorf("Load(%q) returned %d migrations, want an error", engine, len(ms))
			}
		}
	})
}

func TestLoadEnginesAgreeOnVersions(t *testing.T) {
	sqlite, postgres := mustLoad(t, "sqlite"), mustLoad(t, "postgres")

	if len(sqlite) != len(postgres) {
		t.Fatalf("sqlite has %d migrations and postgres has %d: one engine is missing a schema change", len(sqlite), len(postgres))
	}
	for i := range sqlite {
		if sqlite[i].Version != postgres[i].Version || sqlite[i].Name != postgres[i].Name {
			t.Errorf("position %d: sqlite is %04d_%s, postgres is %04d_%s: the same version must mean the same change on both engines",
				i, sqlite[i].Version, sqlite[i].Name, postgres[i].Version, postgres[i].Name)
		}
	}
}

func TestLoadKeepsGuardBodiesWhole(t *testing.T) {
	// The append-only guards on the audit log are the statements most exposed
	// to a splitting mistake, because they are the ones with bodies. A guard
	// cut at an inner semicolon either fails to apply or, worse, applies as a
	// fragment and leaves the audit table writable.
	tests := []struct {
		engine string
		prefix string
		suffix string
		want   []string
	}{
		{
			engine: "sqlite",
			prefix: "CREATE TRIGGER",
			suffix: "END",
			want: []string{
				"audit_checkpoints_boundary_guard",
				"audit_checkpoints_marker_guard",
				"audit_checkpoints_no_change",
				"audit_checkpoints_no_delete",
				"audit_log_delete_guard",
				"audit_log_update_guard",
			},
		},
		{
			engine: "postgres",
			prefix: "CREATE FUNCTION",
			suffix: "LANGUAGE plpgsql",
			want: []string{
				"audit_checkpoints_insert_guard",
				"audit_checkpoints_reject_write",
				"audit_log_delete_guard",
				"audit_log_update_guard",
			},
		},
	}

	nameRE := regexp.MustCompile(`(?i)^CREATE\s+(?:TRIGGER|FUNCTION)\s+([a-z_][a-z0-9_]*)`)

	for _, tc := range tests {
		t.Run(tc.engine, func(t *testing.T) {
			var got []string
			for _, m := range mustLoad(t, tc.engine) {
				for _, s := range m.Statements {
					if !strings.HasPrefix(strings.ToUpper(s), tc.prefix) {
						continue
					}
					match := nameRE.FindStringSubmatch(s)
					if match == nil {
						t.Errorf("cannot read a name out of %q", head(s))
						continue
					}
					got = append(got, match[1])
					if !strings.HasSuffix(s, tc.suffix) {
						t.Errorf("%s does not end in %q, so its body was cut short: ...%q", match[1], tc.suffix, tail(s))
					}
				}
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("guards found = %v, want %v: a missing guard leaves an append-only table writable", got, tc.want)
			}
		})
	}
}

var (
	createTableRE = regexp.MustCompile(`(?i)^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["` + "`" + `]?([a-z_][a-z0-9_]*)`)
	createIndexRE = regexp.MustCompile(`(?i)^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?["` + "`" + `]?([a-z_][a-z0-9_]*)`)
	uniqueIndexRE = regexp.MustCompile(`(?i)^CREATE\s+UNIQUE\s+INDEX`)
)

type schemaNames struct {
	tables  []string
	indexes []string
	// unique records which indexes enforce uniqueness. An index that is
	// unique on one engine and plain on the other is a constraint that only
	// half the deployments have.
	unique []string
}

func collectSchema(t *testing.T, engine string) schemaNames {
	t.Helper()
	var out schemaNames
	for _, m := range mustLoad(t, engine) {
		for _, s := range m.Statements {
			if match := createTableRE.FindStringSubmatch(s); match != nil {
				out.tables = append(out.tables, strings.ToLower(match[1]))
				continue
			}
			if match := createIndexRE.FindStringSubmatch(s); match != nil {
				name := strings.ToLower(match[1])
				out.indexes = append(out.indexes, name)
				if uniqueIndexRE.MatchString(s) {
					out.unique = append(out.unique, name)
				}
			}
		}
	}
	sort.Strings(out.tables)
	sort.Strings(out.indexes)
	sort.Strings(out.unique)
	return out
}

func TestSchemaParity(t *testing.T) {
	sqlite := collectSchema(t, "sqlite")
	postgres := collectSchema(t, "postgres")

	// A parser that finds nothing would make the two sets trivially equal.
	if len(sqlite.tables) < 10 || len(sqlite.indexes) < 10 {
		t.Fatalf("found only %d tables and %d indexes in the sqlite schema: the name extraction is not working, so parity would pass vacuously",
			len(sqlite.tables), len(sqlite.indexes))
	}
	for _, must := range []string{"audit_log", "audit_checkpoints", "subjects", "webauthn_credentials", "erasure_requests"} {
		if !contains(sqlite.tables, must) {
			t.Errorf("table %s was not found in the sqlite schema", must)
		}
	}

	tests := []struct {
		kind             string
		sqlite, postgres []string
	}{
		{"tables", sqlite.tables, postgres.tables},
		{"indexes", sqlite.indexes, postgres.indexes},
		{"unique indexes", sqlite.unique, postgres.unique},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			if dup := duplicates(tc.sqlite); len(dup) > 0 {
				t.Errorf("sqlite declares %s more than once: %v", tc.kind, dup)
			}
			if dup := duplicates(tc.postgres); len(dup) > 0 {
				t.Errorf("postgres declares %s more than once: %v", tc.kind, dup)
			}
			onlySQLite, onlyPostgres := difference(tc.sqlite, tc.postgres), difference(tc.postgres, tc.sqlite)
			if len(onlySQLite) > 0 || len(onlyPostgres) > 0 {
				t.Errorf("%s differ between engines, so a control present on one is absent on the other\n only in sqlite:   %v\n only in postgres: %v",
					tc.kind, onlySQLite, onlyPostgres)
			}
		})
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func difference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func duplicates(sorted []string) []string {
	var out []string
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			out = append(out, sorted[i])
		}
	}
	return out
}

func head(s string) string {
	if len(s) > 60 {
		return s[:60]
	}
	return s
}

func tail(s string) string {
	if len(s) > 60 {
		return s[len(s)-60:]
	}
	return s
}

// TestSplitRegressions pins three defects found by testing the splitter
// against inputs the shipped migrations did not happen to contain.
func TestSplitRegressions(t *testing.T) {
	t.Run("an unterminated quote is an error, not one giant statement", func(t *testing.T) {
		for _, in := range []string{
			"SELECT 'never closed; SELECT 2;",
			`SELECT "never closed; SELECT 2;`,
			"SELECT `never closed; SELECT 2;",
		} {
			if got, err := Split(in); err == nil {
				t.Errorf("Split(%q) = %q with no error; the rest of the file was absorbed", in, got)
			}
		}
	})

	t.Run("a CASE expression does not close a trigger body", func(t *testing.T) {
		in := `CREATE TRIGGER g BEFORE UPDATE ON u BEGIN
			UPDATE u SET a = CASE WHEN 1 THEN 2 ELSE 3 END;
			DELETE FROM v;
		END;
		SELECT 3;`
		got, err := Split(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d statements, want 2 (the whole trigger, then the select): %q", len(got), got)
		}
	})

	t.Run("quotes and comment markers inside a dollar body are literal", func(t *testing.T) {
		in := "CREATE FUNCTION f() RETURNS text AS $$ BEGIN RETURN 'it''s -- not a comment; /* nor this'; END; $$ LANGUAGE plpgsql; SELECT 1;"
		got, err := Split(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d statements, want 2: %q", len(got), got)
		}
		lone := "CREATE FUNCTION g() RETURNS text AS $$ BEGIN RETURN 'unbalanced \" inside'; END; $$ LANGUAGE plpgsql;"
		if _, err := Split(lone); err != nil {
			t.Errorf("a lone double quote inside a dollar body broke the split: %v", err)
		}
	})
}
