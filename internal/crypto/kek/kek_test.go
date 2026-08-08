package kek

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const testEnvVar = "N0PASSTEMPS_TEST_KEK_KEYRING"

// testKey returns a deterministic 32 byte key. Distinct seeds give distinct
// keys, which lets a test tell which version it was handed.
func testKey(seed byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func keyringJSON(t *testing.T, current uint32, keys map[uint32][]byte) []byte {
	t.Helper()
	f := fileFormat{Current: current, Keys: map[string]string{}}
	for v, k := range keys {
		f.Keys[strconv.FormatUint(uint64(v), 10)] = base64.StdEncoding.EncodeToString(k)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("encode keyring: %v", err)
	}
	return raw
}

// writeFile sets the mode with an explicit chmod, because the mode passed to
// os.WriteFile is filtered by the umask of whoever runs the tests.
func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func validKeyring(t *testing.T) []byte {
	t.Helper()
	return keyringJSON(t, 2, map[uint32][]byte{1: testKey(0x10), 2: testKey(0x20), 5: testKey(0x50)})
}

func TestFileProviderLoadsValidKeyring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	writeFile(t, path, validKeyring(t), 0o600)

	p, err := LoadFileProvider(path)
	if err != nil {
		t.Fatalf("a well-formed, owner-only keyring must load: %v", err)
	}
	defer p.Close()

	if p.Path() != path {
		t.Errorf("Path() = %q, want %q", p.Path(), path)
	}

	v, key, err := p.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v != 2 || !bytes.Equal(key, testKey(0x20)) {
		t.Errorf("Current returned version %d with the wrong key material; new secrets would be sealed under the wrong KEK", v)
	}

	for version, want := range map[uint32][]byte{1: testKey(0x10), 2: testKey(0x20), 5: testKey(0x50)} {
		got, err := p.ByVersion(version)
		if err != nil {
			t.Errorf("ByVersion(%d): %v", version, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ByVersion(%d) returned the key of another version", version)
		}
	}

	if key, err := p.ByVersion(3); !errors.Is(err, ErrUnknownVersion) || key != nil {
		t.Errorf("ByVersion of an absent version: got (%v, %v), want (nil, ErrUnknownVersion)", key, err)
	}

	if got, want := p.Versions(), []uint32{1, 2, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("Versions() = %v, want %v in ascending order", got, want)
	}
}

// The envelope sealer zeroizes every key it is handed. If the provider
// returned its own backing array, the first Seal would wipe the keyring and
// every later record would be sealed under 32 zero bytes.
func TestReturnedKeysAreCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	writeFile(t, path, validKeyring(t), 0o600)
	p, err := LoadFileProvider(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()

	cases := []struct {
		name string
		get  func() ([]byte, error)
		want []byte
	}{
		{"Current", func() ([]byte, error) { _, k, err := p.Current(); return k, err }, testKey(0x20)},
		{"ByVersion", func() ([]byte, error) { return p.ByVersion(1) }, testKey(0x10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.get()
			if err != nil {
				t.Fatalf("first call: %v", err)
			}
			for i := range first {
				first[i] = 0
			}
			second, err := tc.get()
			if err != nil {
				t.Fatalf("second call: %v", err)
			}
			if !bytes.Equal(second, tc.want) {
				t.Fatal("zeroizing a returned key altered the keyring: the provider hands out its own storage instead of a copy")
			}
		})
	}
}

func TestFileProviderPermissions(t *testing.T) {
	cases := []struct {
		name   string
		mode   os.FileMode
		wantOK bool
	}{
		// The usual mistake: a file created under a default umask.
		{"0644 world readable is refused", 0o644, false},
		// Group read exposes the key to every account sharing the group,
		// which on many hosts includes the backup or web server user.
		{"0640 group readable is refused", 0o640, false},
		// Readable by other but not by group: a check that only looked at the
		// group bits would let this through.
		{"0604 other readable is refused", 0o604, false},
		{"0600 owner only is accepted", 0o600, true},
		// Read-only for the owner is the stricter setting some operators
		// choose; refusing it would push them towards a looser mode.
		{"0400 owner read-only is accepted", 0o400, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kek.json")
			writeFile(t, path, validKeyring(t), tc.mode)

			p, err := LoadFileProvider(path)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("mode %#o grants nothing to group or other and must be accepted: %v", tc.mode, err)
				}
				p.Close()
				return
			}
			if err == nil {
				p.Close()
				t.Fatalf("keyring with mode %#o loaded: a KEK readable beyond the service user must be refused", tc.mode)
			}
			// Guard against passing for an unrelated reason.
			if !strings.Contains(err.Error(), "must not be readable by group or other") {
				t.Fatalf("mode %#o refused, but not for its permissions: %v", tc.mode, err)
			}
		})
	}
}

// A KEK stored on the same volume as the ciphertext it protects is copied
// along with it by any backup, snapshot or stolen disk. These cases pin down
// what "inside the data directory" means.
func TestFileProviderDataDirPlacement(t *testing.T) {
	type layout struct {
		kekPath  string
		dataDirs []string
	}
	cases := []struct {
		name        string
		build       func(t *testing.T, base string) layout
		wantRefused bool
	}{
		{
			name: "keyring directly inside the data dir is refused",
			build: func(t *testing.T, base string) layout {
				data := filepath.Join(base, "data")
				kek := filepath.Join(data, "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				return layout{kek, []string{data}}
			},
			wantRefused: true,
		},
		{
			name: "keyring in a subdirectory of the data dir is refused",
			build: func(t *testing.T, base string) layout {
				data := filepath.Join(base, "data")
				kek := filepath.Join(data, "secrets", "deep", "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				return layout{kek, []string{data}}
			},
			wantRefused: true,
		},
		{
			name: "keyring inside the second of two data dirs is refused",
			build: func(t *testing.T, base string) layout {
				kek := filepath.Join(base, "backups", "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				return layout{kek, []string{filepath.Join(base, "data"), filepath.Join(base, "backups")}}
			},
			wantRefused: true,
		},
		{
			// Regression guard. The configured path looks safe as text, yet
			// the bytes live in the data dir. A textual comparison passes
			// this; only resolving the link catches it.
			name: "symlinked file pointing inside the data dir is refused",
			build: func(t *testing.T, base string) layout {
				data := filepath.Join(base, "data")
				target := filepath.Join(data, "kek.json")
				writeFile(t, target, validKeyring(t), 0o600)
				link := filepath.Join(base, "etc", "kek.json")
				if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return layout{link, []string{data}}
			},
			wantRefused: true,
		},
		{
			// Same attack one level up: the directory holding the keyring is
			// the link.
			name: "keyring under a symlinked directory pointing inside the data dir is refused",
			build: func(t *testing.T, base string) layout {
				data := filepath.Join(base, "data")
				writeFile(t, filepath.Join(data, "keys", "kek.json"), validKeyring(t), 0o600)
				linkDir := filepath.Join(base, "etc-keys")
				if err := os.Symlink(filepath.Join(data, "keys"), linkDir); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return layout{filepath.Join(linkDir, "kek.json"), []string{data}}
			},
			wantRefused: true,
		},
		{
			// The data dir itself is declared through a link, as happens
			// with /var/lib/app pointing at a mounted volume.
			name: "data dir declared through a symlink still contains the keyring",
			build: func(t *testing.T, base string) layout {
				volume := filepath.Join(base, "volume")
				kek := filepath.Join(volume, "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				link := filepath.Join(base, "data")
				if err := os.Symlink(volume, link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return layout{kek, []string{link}}
			},
			wantRefused: true,
		},
		{
			// A prefix comparison on strings would treat data-keys as being
			// inside data and refuse a correct deployment, which teaches
			// operators to disable the check.
			name: "sibling directory sharing a name prefix with the data dir is accepted",
			build: func(t *testing.T, base string) layout {
				data := filepath.Join(base, "data")
				if err := os.MkdirAll(data, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				kek := filepath.Join(base, "data-keys", "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				return layout{kek, []string{data}}
			},
			wantRefused: false,
		},
		{
			// First start: the server has not created its data dir yet.
			name: "data dir that does not exist yet is accepted",
			build: func(t *testing.T, base string) layout {
				kek := filepath.Join(base, "keys", "kek.json")
				writeFile(t, kek, validKeyring(t), 0o600)
				return layout{kek, []string{filepath.Join(base, "data")}}
			},
			wantRefused: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.build(t, t.TempDir())
			p, err := LoadFileProvider(l.kekPath, l.dataDirs...)
			if !tc.wantRefused {
				if err != nil {
					t.Fatalf("keyring outside every data dir must load: %v", err)
				}
				p.Close()
				return
			}
			if err == nil {
				p.Close()
				t.Fatal("keyring stored with the data it protects was loaded; it must be refused")
			}
			if !strings.Contains(err.Error(), "is inside the data directory") {
				t.Fatalf("refused, but not for its placement: %v", err)
			}
		})
	}
}

func TestMalformedKeyringIsRefused(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	good := b64(KeySize)

	cases := []struct {
		name    string
		doc     string
		wantErr error // nil when no sentinel applies
	}{
		{"malformed JSON", `{"current":1,"keys":{"1":"` + good + `"}`, nil},
		{"not an object", `"` + good + `"`, nil},
		{"empty document", ``, nil},
		// Starting with no keys would defer the failure to the first Seal,
		// long after the operator stopped watching the logs.
		{"empty key map", `{"current":1,"keys":{}}`, ErrNoKeys},
		{"missing key map", `{"current":1}`, ErrNoKeys},
		{"non-numeric version", `{"current":1,"keys":{"1":"` + good + `","v2":"` + good + `"}}`, nil},
		{"negative version", `{"current":1,"keys":{"1":"` + good + `","-2":"` + good + `"}}`, nil},
		// Truncated to 32 bits this is version 1, which would collide with
		// the real one.
		{"version beyond uint32", `{"current":1,"keys":{"1":"` + good + `","4294967297":"` + good + `"}}`, nil},
		{"bad base64", `{"current":1,"keys":{"1":"!!not base64!!"}}`, nil},
		// 31 and 33 bytes are what a truncated paste or a stray newline byte
		// inside the decoded value produce.
		{"31 byte key", `{"current":1,"keys":{"1":"` + b64(31) + `"}}`, ErrBadKeySize},
		{"33 byte key", `{"current":1,"keys":{"1":"` + b64(33) + `"}}`, ErrBadKeySize},
		// An AES-128 sized key is valid for the cipher, so it has to be
		// refused here.
		{"16 byte key", `{"current":1,"keys":{"1":"` + b64(16) + `"}}`, ErrBadKeySize},
		{"one bad key among good ones", `{"current":1,"keys":{"1":"` + good + `","2":"` + b64(31) + `"}}`, ErrBadKeySize},
		{"current names an absent version", `{"current":3,"keys":{"1":"` + good + `","2":"` + good + `"}}`, ErrUnknownVersion},
		// A document without "current" decodes to version 0.
		{"current omitted", `{"keys":{"1":"` + good + `"}}`, ErrUnknownVersion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			check := func(t *testing.T, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("an invalid keyring was loaded; the server must refuse to start on it")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want an error wrapping %v", err, tc.wantErr)
				}
			}

			t.Run("file", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "kek.json")
				writeFile(t, path, []byte(tc.doc), 0o600)
				p, err := LoadFileProvider(path)
				if err == nil {
					p.Close()
				}
				check(t, err)
			})
			t.Run("env", func(t *testing.T) {
				t.Setenv(testEnvVar, tc.doc)
				p, err := LoadEnvProvider(testEnvVar)
				if err == nil {
					p.Close()
				}
				check(t, err)
			})
		})
	}
}

func TestMissingKeyringFileIsRefused(t *testing.T) {
	if _, err := LoadFileProvider(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("loading a keyring that does not exist must fail, never fall back to a generated key")
	}
}

func TestCloseZeroizesKeyMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	writeFile(t, path, validKeyring(t), 0o600)
	p, err := LoadFileProvider(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Hold on to the internal backing arrays. Dropping the map entries alone
	// would satisfy the API checks below while leaving the keys in memory
	// until the collector reclaims them.
	var internal [][]byte
	for _, k := range p.keyring.keys {
		internal = append(internal, k)
	}
	if len(internal) != 3 {
		t.Fatalf("expected 3 retained keys before Close, got %d", len(internal))
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i, k := range internal {
		if !bytes.Equal(k, make([]byte, KeySize)) {
			t.Errorf("retained key %d still holds key material after Close", i)
		}
	}
	if _, key, err := p.Current(); !errors.Is(err, ErrNoKeys) || key != nil {
		t.Errorf("Current after Close: got (%v, %v), want (nil, ErrNoKeys)", key, err)
	}
	if key, err := p.ByVersion(2); !errors.Is(err, ErrUnknownVersion) || key != nil {
		t.Errorf("ByVersion after Close: got (%v, %v), want (nil, ErrUnknownVersion)", key, err)
	}
	if v := p.Versions(); len(v) != 0 {
		t.Errorf("Versions after Close = %v, want none", v)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v; shutdown paths may call it more than once", err)
	}
}

func TestEnvProviderParsesAndUnsetsVariable(t *testing.T) {
	t.Setenv(testEnvVar, string(validKeyring(t)))

	p, err := LoadEnvProvider(testEnvVar)
	if err != nil {
		t.Fatalf("LoadEnvProvider on a valid document: %v", err)
	}
	defer p.Close()

	// Left in place, the keyring would be inherited by every child process
	// and stay readable through /proc/<pid>/environ.
	if val, ok := os.LookupEnv(testEnvVar); ok {
		t.Fatalf("%s is still set (%d bytes) after loading; the KEK must not stay in the process environment", testEnvVar, len(val))
	}

	v, key, err := p.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v != 2 || !bytes.Equal(key, testKey(0x20)) {
		t.Errorf("env provider returned version %d with the wrong key material", v)
	}
	if got, want := p.Versions(), []uint32{1, 2, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("Versions() = %v, want %v", got, want)
	}
	old, err := p.ByVersion(1)
	if err != nil || !bytes.Equal(old, testKey(0x10)) {
		t.Errorf("ByVersion(1) from the env provider: wrong key or error %v", err)
	}
}

func TestEnvProviderRefusals(t *testing.T) {
	t.Run("unset variable is refused", func(t *testing.T) {
		t.Setenv(testEnvVar, "placeholder")
		if err := os.Unsetenv(testEnvVar); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
		if _, err := LoadEnvProvider(testEnvVar); err == nil {
			t.Fatal("an unset variable must be an error, never an empty keyring")
		}
	})

	t.Run("blank variable is refused", func(t *testing.T) {
		t.Setenv(testEnvVar, " \n\t")
		if _, err := LoadEnvProvider(testEnvVar); err == nil {
			t.Fatal("a blank variable must be an error, never an empty keyring")
		}
	})

	// A document that fails validation may still contain real key material,
	// for instance one good key and one truncated key. It has to leave the
	// environment as well.
	t.Run("variable is unset even when parsing fails", func(t *testing.T) {
		good := base64.StdEncoding.EncodeToString(testKey(0x10))
		t.Setenv(testEnvVar, `{"current":9,"keys":{"1":"`+good+`"}}`)
		if _, err := LoadEnvProvider(testEnvVar); err == nil {
			t.Fatal("expected the document to be refused")
		}
		if _, ok := os.LookupEnv(testEnvVar); ok {
			t.Fatalf("%s is still set after a failed load", testEnvVar)
		}
	})
}

// TestNonCanonicalVersionsAreRefused guards against two spellings of one
// version.
//
// "1" and "01" parse to the same number. A keyring holding both with different
// key material would keep whichever entry the map iteration visited last, so
// the key protecting the database could differ between two starts of the same
// binary on the same file.
func TestNonCanonicalVersionsAreRefused(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, KeySize))
	for _, version := range []string{"01", "+1", " 1", "1 ", "0"} {
		doc := `{"current":1,"keys":{"` + version + `":"` + key + `"}}`
		if _, err := parseKeyring([]byte(doc)); err == nil {
			t.Errorf("key version %q was accepted; only the canonical decimal form "+
				"may name a key, and versions start at 1", version)
		}
	}
}
