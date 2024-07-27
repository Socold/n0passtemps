// Package migrations embeds the schema files and splits them into statements.
//
// The files are embedded rather than read from disk so that a single binary
// carries its own schema. An operator cannot end up running a build against a
// migration set from a different version, which is a failure mode that is
// tedious to diagnose and easy to cause.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed sqlite/*.sql postgres/*.sql
var files embed.FS

// Migration is one numbered schema file.
type Migration struct {
	Version int
	Name    string
	// Checksum is the SHA-256 of the file contents, recorded when the
	// migration is applied. A later run that finds a different checksum for an
	// already applied version reports it rather than proceeding: an edited
	// migration means the database and the code disagree about the schema, and
	// continuing would hide that.
	Checksum string
	// Statements are the individual statements, in order.
	Statements []string
}

// Load returns the migrations for an engine, ordered by version.
//
// engine is "sqlite" or "postgres".
func Load(engine string) ([]Migration, error) {
	switch engine {
	case "sqlite", "postgres":
	default:
		return nil, fmt.Errorf("migrations: unknown engine %q", engine)
	}

	entries, err := fs.ReadDir(files, engine)
	if err != nil {
		return nil, fmt.Errorf("migrations: read %s: %w", engine, err)
	}

	out := make([]Migration, 0, len(entries))
	seen := make(map[int]string, len(entries))

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, err := parseName(e.Name())
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations: version %d is claimed by both %q and %q",
				version, prev, e.Name())
		}
		seen[version] = e.Name()

		raw, err := fs.ReadFile(files, path.Join(engine, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrations: read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(raw)

		stmts, err := Split(string(raw))
		if err != nil {
			return nil, fmt.Errorf("migrations: %s: %w", e.Name(), err)
		}
		if len(stmts) == 0 {
			return nil, fmt.Errorf("migrations: %s contains no statements", e.Name())
		}

		out = append(out, Migration{
			Version:    version,
			Name:       name,
			Checksum:   hex.EncodeToString(sum[:]),
			Statements: stmts,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// parseName splits "0002_governance.sql" into 2 and "governance".
func parseName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, "", fmt.Errorf("migrations: %q must be named NNNN_name.sql", filename)
	}
	version, err := strconv.Atoi(base[:idx])
	if err != nil {
		return 0, "", fmt.Errorf("migrations: %q does not start with a version number: %w", filename, err)
	}
	if version <= 0 {
		return 0, "", fmt.Errorf("migrations: %q has a non-positive version", filename)
	}
	return version, base[idx+1:], nil
}

// Split separates a SQL file into statements.
//
// Splitting naively on every semicolon is wrong for this schema. A semicolon
// inside a string literal, inside a quoted identifier, inside a SQLite trigger
// body between BEGIN and END, or inside a PostgreSQL dollar-quoted function
// body is part of the statement, not a separator. Each of those appears in the
// migrations here, so the scanner below tracks the context it is in.
//
// The states recognised are:
//
//	line comment      -- to end of line
//	block comment     /* to */, not nested, as the SQL standard specifies
//	dollar quote      $tag$ ... $tag$ with a matching tag, checked first
//	string literal    '...', with '' as an escaped quote
//	quoted identifier "..." and `...`, with doubling as the escape
//	END-closed block  BEGIN ... END and CASE ... END, for SQLite trigger bodies
func Split(sql string) ([]string, error) {
	var (
		out       []string
		cur       strings.Builder
		i         int
		n         = len(sql)
		depth     int // BEGIN nesting inside a trigger or function body
		dollarTag string
	)

	flush := func() {
		s := strings.TrimSpace(cur.String())
		if s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}

	for i < n {
		c := sql[i]

		// Inside a dollar quote nothing is special except the closing tag. This
		// is checked before every other construct, because a function body is
		// free to contain an apostrophe or a comment marker, and treating
		// either as SQL syntax would swallow the closing tag.
		if dollarTag != "" {
			if c == '$' && strings.HasPrefix(sql[i:], dollarTag) {
				cur.WriteString(dollarTag)
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			cur.WriteByte(c)
			i++
			continue
		}

		switch {
		// Line comment.
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
			// The newline is kept so statements stay readable in an error.
			if i < n {
				cur.WriteByte('\n')
				i++
			}
			continue

		// Block comment.
		case c == '/' && i+1 < n && sql[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated block comment at offset %d", i)
			}
			i += 2 + end + 2
			cur.WriteByte(' ')
			continue

		// String literal, and quoted identifier. Both escape their delimiter
		// by doubling it. An unterminated one is an error: left alone it would
		// absorb the rest of the file into a single statement, and the
		// migration would fail somewhere far from the actual mistake.
		case c == '\'' || c == '"' || c == '`':
			q := c
			start := i
			closed := false
			i++
			for i < n {
				if sql[i] == q {
					if i+1 < n && sql[i+1] == q {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated %c quote starting at offset %d", q, start)
			}
			cur.WriteString(sql[start:i])
			continue

		// Dollar quote, PostgreSQL. The tag between the dollars must match
		// exactly for the quote to close, so $$ and $body$ do not terminate
		// each other.
		case c == '$':
			if tag, ok := dollarTagAt(sql, i); ok {
				dollarTag = tag
				cur.WriteString(tag)
				i += len(tag)
				continue
			}
			cur.WriteByte(c)
			i++
			continue
		}

		// Track the constructs that END closes, so a SQLite trigger body is not
		// cut at the semicolons inside it. CASE is counted as well as BEGIN:
		// both are closed by END, and counting only BEGIN meant a CASE
		// expression inside a trigger body closed the body early and split the
		// trigger in two. Only a word boundary counts, so "BEGINNING" is not a
		// BEGIN.
		if word, ok := wordAt(sql, i); ok {
			switch strings.ToUpper(word) {
			case "BEGIN", "CASE":
				depth++
			case "END":
				if depth > 0 {
					depth--
				}
			}
			cur.WriteString(word)
			i += len(word)
			continue
		}

		if c == ';' && depth == 0 {
			flush()
			i++
			continue
		}

		cur.WriteByte(c)
		i++
	}

	if dollarTag != "" {
		return nil, fmt.Errorf("unterminated dollar quote %s", dollarTag)
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced BEGIN and END, depth %d at end of file", depth)
	}
	flush()
	return out, nil
}

// dollarTagAt reports whether a dollar-quote tag starts at i, and returns it
// including both dollar signs.
func dollarTagAt(s string, i int) (string, bool) {
	if i >= len(s) || s[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(s) {
		c := s[j]
		if c == '$' {
			return s[i : j+1], true
		}
		isTagChar := c == '_' ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9' && j > i+1)
		if !isTagChar {
			return "", false
		}
		j++
	}
	return "", false
}

// wordAt returns the identifier starting at i, if i is at a word boundary.
func wordAt(s string, i int) (string, bool) {
	if !isWordStart(s[i]) {
		return "", false
	}
	if i > 0 && isWordChar(s[i-1]) {
		return "", false
	}
	j := i
	for j < len(s) && isWordChar(s[j]) {
		j++
	}
	return s[i:j], true
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isWordChar(c byte) bool {
	return isWordStart(c) || (c >= '0' && c <= '9')
}
