package config

import "testing"

// TestPostgresDSNTransportPolicy pins what the validator accepts.
//
// An earlier version looked for the substring "host=localhost", which a URL
// never contains, so every loopback URL was refused while the documentation
// said it was accepted, and the shipped compose deployment could not start.
func TestPostgresDSNTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		dsn            string
		allowPlaintext bool
		wantOK         bool
	}{
		{"url, verify-full", "postgres://u:p@db.internal:5432/n0p?sslmode=verify-full", false, true},
		{"url, require", "postgresql://u:p@db.internal/n0p?sslmode=require", false, true},
		{"keyword, verify-ca", "host=db.internal user=u dbname=n0p sslmode=verify-ca", false, true},

		{"no sslmode at all", "postgres://u:p@db.internal/n0p", false, false},
		{"prefer falls back silently", "postgres://u:p@db.internal/n0p?sslmode=prefer", false, false},
		{"allow falls back silently", "host=db.internal sslmode=allow", false, false},

		{"disable to loopback name, url form", "postgres://u:p@localhost:5432/n0p?sslmode=disable", false, true},
		{"disable to loopback v4, url form", "postgres://u:p@127.0.0.1/n0p?sslmode=disable", false, true},
		{"disable to loopback v6, url form", "postgres://u:p@[::1]:5432/n0p?sslmode=disable", false, true},
		{"disable to a socket directory, url form", "postgres:///n0p?host=/var/run/postgresql&sslmode=disable", false, true},
		{"disable to a socket directory, keyword form", "host=/var/run/postgresql dbname=n0p sslmode=disable", false, true},
		{"disable with no host, keyword form", "dbname=n0p sslmode=disable", false, true},

		{"disable to another machine is refused", "postgres://u:p@db:5432/n0p?sslmode=disable", false, false},
		{"disable to another machine, acknowledged", "postgres://u:p@db:5432/n0p?sslmode=disable", true, true},
		// The acknowledgement covers "disable" only. It must not make the
		// silently-downgrading modes acceptable.
		{"acknowledgement does not cover prefer", "postgres://u:p@db/n0p?sslmode=prefer", true, false},
		// A host that merely contains the word must not pass as loopback.
		{"localhost as a subdomain label", "postgres://u:p@localhost.evil.example/n0p?sslmode=disable", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePostgresDSN(tc.dsn, tc.allowPlaintext)
			if tc.wantOK && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("accepted a DSN that does not guarantee an encrypted transport")
			}
		})
	}
}
