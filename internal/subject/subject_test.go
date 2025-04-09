package subject

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

const testPepperEnv = "N0PASSTEMPS_TEST_SUBJECT_PEPPER"

// key32 is a fixed 32-byte value whose bytes are all distinct, so a decoding
// that reorders, truncates or re-encodes it cannot go unnoticed.
func key32(offset byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = offset + byte(i)*7
	}
	return b
}

func TestDecodePepper(t *testing.T) {
	key := key32(0xa0)
	passphrase := "correct horse battery staple, forty ch!!" // 40 bytes, neither hex nor base64

	if len(passphrase) != 40 {
		t.Fatalf("test passphrase is %d bytes, want 40", len(passphrase))
	}

	tests := []struct {
		name string
		raw  string
		want []byte
	}{
		{"64-char hex", hex.EncodeToString(key), key},
		{"64-char upper-case hex", strings.ToUpper(hex.EncodeToString(key)), key},
		{"std base64", base64.StdEncoding.EncodeToString(key), key},
		{"raw std base64", base64.RawStdEncoding.EncodeToString(key), key},
		{"url base64", base64.URLEncoding.EncodeToString(key), key},
		{"raw url base64", base64.RawURLEncoding.EncodeToString(key), key},
		// A passphrase is accepted only when the operator says that is what it
		// is. Guessing was the defect: see TestDecodePepperNeverGuesses.
		{"passphrase marked raw", "raw:" + passphrase, []byte(passphrase)},
		{"hex marked explicitly", "hex:" + hex.EncodeToString(key), key},
		{"base64 marked explicitly", "base64:" + base64.StdEncoding.EncodeToString(key), key},
		// A value pasted from a terminal commonly carries a trailing newline.
		{"surrounding whitespace is ignored", "  " + hex.EncodeToString(key) + "\n", key},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodePepper(tc.raw)
			if err != nil {
				t.Fatalf("decodePepper: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("decoded %d bytes that differ from the key the operator created: the HMAC key would carry less entropy than they believe", len(got))
			}
		})
	}

	t.Run("hex takes precedence over base64", func(t *testing.T) {
		// Every hex string is also valid base64. Read as base64, 64 hex
		// characters give 48 bytes drawn from a 16-symbol alphabet, which is
		// not the key the operator created.
		raw := hex.EncodeToString(key)
		got, err := decodePepper(raw)
		if err != nil {
			t.Fatalf("decodePepper: %v", err)
		}
		if len(got) != 32 {
			t.Errorf("a hex pepper decoded to %d bytes, want 32: it was misread as another encoding", len(got))
		}
	})
}

func TestDecodePepperRefusals(t *testing.T) {
	short := key32(0x10)[:16]

	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", ErrPepperMissing},
		{"whitespace only", " \t\n", ErrPepperMissing},
		{"short std base64", base64.StdEncoding.EncodeToString(short), ErrPepperShort},
		{"short raw std base64", base64.RawStdEncoding.EncodeToString(short), ErrPepperShort},
		{"short url base64", base64.URLEncoding.EncodeToString(short), ErrPepperShort},
		{"short raw url base64", base64.RawURLEncoding.EncodeToString(short), ErrPepperShort},
		{"short passphrase", "hunter2 hunter2", ErrPepperShort},
		{"31-byte passphrase", strings.Repeat("p", 30) + "!", ErrPepperShort},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodePepper(tc.raw)
			if err == nil {
				t.Fatalf("a %d-byte pepper was accepted: an attacker holding the database confirms guesses against a weak key", len(got))
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func newTestService(t *testing.T, pepper []byte, maxRef int) *Service {
	t.Helper()
	t.Setenv(testPepperEnv, hex.EncodeToString(pepper))
	// No method under test here touches the store or the sealer.
	s, err := New(config.Subject{PepperEnv: testPepperEnv, MaxRefLength: maxRef}, nil, nil,
		func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestNew(t *testing.T) {
	t.Run("unsets the environment variable once read", func(t *testing.T) {
		newTestService(t, key32(1), 256)
		if v, ok := os.LookupEnv(testPepperEnv); ok {
			t.Errorf("the pepper is still in the environment (%d bytes): child processes and /proc/self/environ can read it", len(v))
		}
	})

	t.Run("accepts exactly the minimum length", func(t *testing.T) {
		s := newTestService(t, key32(1), 256)
		if len(s.pepper) != MinPepperBytes {
			t.Errorf("pepper is %d bytes, want %d", len(s.pepper), MinPepperBytes)
		}
	})

	refusals := []struct {
		name  string
		set   bool
		value string
		want  error
	}{
		{"variable not set", false, "", ErrPepperMissing},
		{"variable empty", true, "", ErrPepperMissing},
		{"variable blank", true, "   ", ErrPepperMissing},
		// Short in each encoding: the length floor in New is the only thing
		// standing between a 16-byte hex value and an accepted key, because
		// decodePepper returns hex of any length.
		{"short hex", true, hex.EncodeToString(key32(1)[:16]), ErrPepperShort},
		{"31-byte hex", true, hex.EncodeToString(key32(1)[:31]), ErrPepperShort},
		{"short base64", true, base64.StdEncoding.EncodeToString(key32(1)[:16]), ErrPepperShort},
		{"short passphrase", true, "hunter2", ErrPepperShort},
	}
	for _, tc := range refusals {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			// Setenv first in both cases so the variable is restored after
			// the test, then remove it for the unset case.
			t.Setenv(testPepperEnv, tc.value)
			if !tc.set {
				if err := os.Unsetenv(testPepperEnv); err != nil {
					t.Fatal(err)
				}
			}

			s, err := New(config.Subject{PepperEnv: testPepperEnv, MaxRefLength: 256}, nil, nil, nil)
			if err == nil {
				t.Fatalf("New accepted a pepper of %d bytes: subject references would be keyed by a guessable value", len(s.pepper))
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), tc.value) && strings.TrimSpace(tc.value) != "" {
				t.Errorf("the error message repeats the pepper value: %q", err)
			}
		})
	}

	t.Run("a refused short pepper is still removed from the environment", func(t *testing.T) {
		t.Setenv(testPepperEnv, "hunter2")
		if _, err := New(config.Subject{PepperEnv: testPepperEnv, MaxRefLength: 256}, nil, nil, nil); err == nil {
			t.Fatal("short pepper accepted")
		}
		if _, ok := os.LookupEnv(testPepperEnv); ok {
			t.Error("a rejected pepper stayed in the environment")
		}
	})

	t.Run("Close wipes the pepper", func(t *testing.T) {
		s := newTestService(t, key32(1), 256)
		held := s.pepper
		s.Close()
		if !bytes.Equal(held, make([]byte, len(held))) {
			t.Error("the pepper bytes survive Close and remain readable in memory")
		}
		if s.pepper != nil {
			t.Error("the service still references the pepper after Close")
		}
	})
}

func TestValidateRef(t *testing.T) {
	const limit = 64
	s := newTestService(t, key32(1), limit)

	tests := []struct {
		name string
		ref  string
		want error
	}{
		{"normal email", "alice@example.org", nil},
		{"opaque identifier", "usr_01HZX3K9Q", nil},
		{"unicode letters", "zoë.müller@exämple.org", nil},
		{"non-latin script", "山田太郎", nil},
		{"interior space", "alice smith", nil},
		{"exactly at the limit", strings.Repeat("a", limit), nil},

		{"empty", "", ErrRefEmpty},
		{"whitespace only", " \t \n", ErrRefEmpty},
		// The limit is in bytes, so it also bounds what reaches the sealer
		// and the log line, whatever the script.
		{"one byte over the limit", strings.Repeat("a", limit+1), ErrRefTooLong},
		{"multi-byte runes over the byte limit", strings.Repeat("é", limit/2+1), ErrRefTooLong},

		// A newline lets a reference forge a second log entry.
		{"newline", "alice\nlevel=ERROR msg=forged", ErrRefMalformed},
		{"carriage return", "alice\rforged", ErrRefMalformed},
		{"tab", "alice\tbob", ErrRefMalformed},
		// ESC opens a terminal escape sequence, which can rewrite what an
		// operator tailing the log sees.
		{"escape byte", "alice\x1b[2Jbob", ErrRefMalformed},
		// NUL truncates the string in anything that hands it to C.
		{"nul", "alice\x00bob", ErrRefMalformed},
		{"delete", "alice\x7fbob", ErrRefMalformed},
		// C1 controls: U+009B is a single-rune CSI on some terminals.
		{"c1 control", "alice2Jbob", ErrRefMalformed},
		// Two byte strings that both render as U+FFFD would otherwise be
		// distinct subjects that look identical everywhere they are shown.
		{"invalid utf-8", "alice\xff\xfebob", ErrRefMalformed},
		{"truncated utf-8 sequence", "alice\xc3", ErrRefMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.ValidateRef(tc.ref)
			switch {
			case tc.want == nil && err != nil:
				t.Errorf("a legitimate reference was refused: %v", err)
			case tc.want != nil && err == nil:
				t.Errorf("reference %q was accepted, want %v: it reaches log lines and the admin interface unescaped", tc.ref, tc.want)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Errorf("error = %v, want %v", err, tc.want)
			}
			if err != nil && tc.ref != "" && strings.Contains(err.Error(), tc.ref) {
				t.Errorf("the error repeats the refused reference, which then reaches the log it was refused to protect: %q", err)
			}
		})
	}
}

func TestRefHMAC(t *testing.T) {
	s := newTestService(t, key32(1), 256)

	t.Run("is deterministic and 32 bytes", func(t *testing.T) {
		a, b := s.RefHMAC("alice@example.org"), s.RefHMAC("alice@example.org")
		if len(a) != sha256.Size {
			t.Errorf("lookup key is %d bytes, want %d", len(a), sha256.Size)
		}
		if !bytes.Equal(a, b) {
			t.Error("the same reference produced two lookup keys: a returning user would be registered as a new subject on every login")
		}
	})

	t.Run("differs per reference", func(t *testing.T) {
		pairs := [][2]string{
			{"alice@example.org", "bob@example.org"},
			// No normalisation is promised, so these are different subjects.
			{"alice@example.org", "Alice@example.org"},
			{"alice", "alice "},
		}
		for _, p := range pairs {
			if bytes.Equal(s.RefHMAC(p[0]), s.RefHMAC(p[1])) {
				t.Errorf("%q and %q share a lookup key: one user would authenticate as the other", p[0], p[1])
			}
		}
	})

	t.Run("differs per pepper", func(t *testing.T) {
		other := newTestService(t, key32(2), 256)
		if bytes.Equal(s.RefHMAC("alice@example.org"), other.RefHMAC("alice@example.org")) {
			t.Error("two peppers give the same lookup key: the pepper is not keying the digest, so the database alone confirms who has an account")
		}
	})

	t.Run("is not an unkeyed digest of the reference", func(t *testing.T) {
		ref := "alice@example.org"
		got := s.RefHMAC(ref)

		plain := sha256.Sum256([]byte(ref))
		if bytes.Equal(got, plain[:]) {
			t.Error("the lookup key is the plain SHA-256 of the reference: anyone holding the database can enumerate email addresses against it")
		}
		domained := sha256.Sum256([]byte("n0passtemps/subject-ref/v1\x00" + ref))
		if bytes.Equal(got, domained[:]) {
			t.Error("the lookup key is an unkeyed digest: the pepper plays no part in it")
		}
	})
}

func TestMatches(t *testing.T) {
	s := newTestService(t, key32(1), 256)
	sub := &store.Subject{ID: "s1", RefHMAC: s.RefHMAC("alice@example.org")}

	tests := []struct {
		name string
		sub  *store.Subject
		ref  string
		want bool
	}{
		{"same reference", sub, "alice@example.org", true},
		{"different reference", sub, "bob@example.org", false},
		{"empty reference", sub, "", false},
		{"subject with no stored key", &store.Subject{ID: "s2"}, "alice@example.org", false},
		{"subject with a truncated key", &store.Subject{ID: "s3", RefHMAC: sub.RefHMAC[:16]}, "alice@example.org", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Matches(tc.sub, tc.ref); got != tc.want {
				t.Errorf("Matches = %v, want %v: a wrong answer binds an operation to the wrong person", got, tc.want)
			}
		})
	}

	t.Run("a key derived under another pepper does not match", func(t *testing.T) {
		other := newTestService(t, key32(2), 256)
		if other.Matches(sub, "alice@example.org") {
			t.Error("a subject created under one pepper matched under another")
		}
	})
}

// TestDecodePepperNeverGuesses is the regression test for a decoder that fell
// back to using the text itself as the key.
//
// The base64 of a 24-byte secret is 32 characters long. The old fallback saw
// "too few bytes once decoded", then "long enough as raw text", and used the 32
// characters of base64 as the key: it worked, with a key whose entropy was a
// quarter less than its length implied, and nothing told the operator. A value
// that is neither unambiguous nor labelled is now refused.
func TestDecodePepperNeverGuesses(t *testing.T) {
	short := make([]byte, 24)
	for i := range short {
		short[i] = byte(i + 1)
	}
	for name, raw := range map[string]string{
		"base64 of too few bytes":  base64.StdEncoding.EncodeToString(short),
		"an unlabelled passphrase": "correct horse battery staple, forty chars",
		"marked hex but is not":    "hex:zz",
		"marked base64 but is not": "base64:!!!!",
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := decodePepper(raw); err == nil {
				t.Fatalf("%q was accepted as a %d byte key; an ambiguous value must be "+
					"refused rather than interpreted", raw, len(b))
			}
		})
	}
}
