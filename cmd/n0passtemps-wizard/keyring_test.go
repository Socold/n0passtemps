package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/crypto/kek"
)

// These subcommands create the key material a deployment lives on: the keyring
// that opens every sealed record and the Ed25519 key every assertion is
// verified against. They run once, on a host, usually by somebody following the
// four closing steps runSetup prints, and a mistake in them is discovered when
// the data is already sealed under it.
//
// The properties below are the ones whose failure is silent. A keyring written
// group-readable produces a service that refuses to start, which is loud. A
// rotation that dropped the previous key produces a service that starts and
// cannot read half its rows, which is not.

// readKeyring parses a keyring file the way the provider does.
func readKeyring(t *testing.T, path string) keyringFile {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a path this test just wrote
	if err != nil {
		t.Fatalf("read keyring: %v", err)
	}
	var doc keyringFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse keyring: %v", err)
	}
	return doc
}

// TestKekInitWritesALoadableKeyring checks the file against the provider that
// has to read it, rather than against this test's idea of the format.
func TestKekInitWritesALoadableKeyring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := kekInit([]string{"-out", path}); err != nil {
		t.Fatalf("kek init: %v", err)
	}

	// Mode 0600, because the provider refuses anything readable by group or
	// other and the comment on kekInit says so.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}

	provider, err := kek.LoadFileProvider(path)
	if err != nil {
		t.Fatalf("the provider refuses the keyring this tool just wrote: %v", err)
	}
	version, key, err := provider.Current()
	if err != nil {
		t.Fatalf("current key: %v", err)
	}
	if version != 1 {
		t.Errorf("current version = %d, want 1", version)
	}
	if len(key) != kek.KeySize {
		t.Errorf("key is %d bytes, want %d", len(key), kek.KeySize)
	}
}

// TestKekInitDoesNotOverwriteWithoutForce is the guard on a command whose
// comment calls overwriting "destroying every secret sealed under it".
func TestKekInitDoesNotOverwriteWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := kekInit([]string{"-out", path}); err != nil {
		t.Fatalf("first init: %v", err)
	}
	first := readKeyring(t, path)

	if err := kekInit([]string{"-out", path}); err == nil {
		t.Fatal("a second init overwrote the keyring without -force")
	}
	if got := readKeyring(t, path); got.Keys["1"] != first.Keys["1"] {
		t.Fatal("the refused init changed the file anyway")
	}

	if err := kekInit([]string{"-out", path, "-force"}); err != nil {
		t.Fatalf("forced init: %v", err)
	}
	if got := readKeyring(t, path); got.Keys["1"] == first.Keys["1"] {
		t.Error("-force did not generate a new key")
	}
}

// TestKekInitGeneratesADistinctKeyEachTime is the one property a random
// generator has that a broken one does not.
func TestKekInitGeneratesADistinctKeyEachTime(t *testing.T) {
	dir := t.TempDir()
	seen := make(map[string]struct{}, 8)
	for i := range 8 {
		path := filepath.Join(dir, string(rune('a'+i))+".json")
		if err := kekInit([]string{"-out", path}); err != nil {
			t.Fatalf("init %d: %v", i, err)
		}
		key := readKeyring(t, path).Keys["1"]
		if _, dup := seen[key]; dup {
			t.Fatal("two keyrings were written with the same key")
		}
		seen[key] = struct{}{}
	}
}

// TestKekRotateKeepsEveryPreviousKey is the property the comment on kekRotate
// spends a paragraph on, and the one whose failure is silent.
//
// Each sealed record names the version it was sealed under. A rotation that
// dropped the predecessor would produce a service that starts, serves, and
// cannot open any record written before today.
func TestKekRotateKeepsEveryPreviousKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := kekInit([]string{"-out", path}); err != nil {
		t.Fatalf("init: %v", err)
	}
	original := readKeyring(t, path).Keys["1"]

	for want := 2; want <= 4; want++ {
		if err := kekRotate([]string{"-file", path}); err != nil {
			t.Fatalf("rotate to %d: %v", want, err)
		}
		doc := readKeyring(t, path)
		if doc.Current != uint32(want) {
			t.Fatalf("current = %d after rotation, want %d", doc.Current, want)
		}
		if len(doc.Keys) != want {
			t.Fatalf("keyring holds %d keys after %d rotations, want %d", len(doc.Keys), want-1, want)
		}
		if doc.Keys["1"] != original {
			t.Fatal("rotation changed the first key; every record sealed under it is now unreadable")
		}
	}

	// The provider opens every retained version, which is what "existing
	// records keep working" means in practice.
	provider, err := kek.LoadFileProvider(path)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	for v := uint32(1); v <= 4; v++ {
		key, err := provider.ByVersion(v)
		if err != nil {
			t.Errorf("version %d cannot be opened after rotation: %v", v, err)
			continue
		}
		if len(key) != kek.KeySize {
			t.Errorf("version %d is %d bytes, want %d", v, len(key), kek.KeySize)
		}
	}
}

// TestKekRotateRefusesAFileItCannotRead covers the two ways the command is
// pointed at something that is not a keyring.
func TestKekRotateRefusesAFileItCannotRead(t *testing.T) {
	dir := t.TempDir()

	if err := kekRotate([]string{"-file", filepath.Join(dir, "absent.json")}); err == nil {
		t.Error("rotated a keyring that does not exist")
	}

	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := kekRotate([]string{"-file", garbage}); err == nil {
		t.Error("rotated a file that is not a keyring")
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"current":0,"keys":{}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := kekRotate([]string{"-file", empty}); err == nil {
		t.Error("rotated a keyring holding no keys")
	}
}

// TestKekRotateNumbersAboveTheHighestVersion checks the loop that picks the
// successor, which reads every version rather than trusting current.
//
// A file whose current is behind a version it holds is what a partially applied
// rotation leaves, and numbering the successor from current would then reuse a
// version that already names different key material.
func TestKekRotateNumbersAboveTheHighestVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	doc := keyringFile{
		Current: 1,
		Keys: map[string]string{
			"1": base64.StdEncoding.EncodeToString(make([]byte, kek.KeySize)),
			"7": base64.StdEncoding.EncodeToString(append(make([]byte, kek.KeySize-1), 1)),
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := kekRotate([]string{"-file", path}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got := readKeyring(t, path)
	if got.Current != 8 {
		t.Errorf("current = %d, want 8: the successor must be above every version held", got.Current)
	}
	if _, ok := got.Keys["8"]; !ok {
		t.Error("no key was written for version 8")
	}
}

// TestKekInspectReadsWhatInitWrites joins the two, and covers the warning an
// operator sees when the file has drifted to a mode the service refuses.
func TestKekInspectReadsWhatInitWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := kekInit([]string{"-out", path}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := kekInspect([]string{"-file", path}); err != nil {
		t.Fatalf("inspect: %v", err)
	}

	// The mode warning path. Nothing is asserted about the text; what matters
	// is that inspecting a world-readable keyring is not itself an error,
	// because the operator is running this to find out.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := kekInspect([]string{"-file", path}); err != nil {
		t.Errorf("inspect refused a keyring with a bad mode: %v", err)
	}

	if err := kekInspect([]string{"-file", filepath.Join(t.TempDir(), "absent.json")}); err == nil {
		t.Error("inspected a keyring that does not exist")
	}
}

// TestRunKEKDispatches covers the subcommand table, including the message an
// operator gets for a name that does not exist.
func TestRunKEKDispatches(t *testing.T) {
	if err := runKEK(nil); err == nil {
		t.Error("no subcommand was accepted")
	}
	err := runKEK([]string{"frobnicate"})
	if err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	for _, name := range []string{"init", "rotate", "seal", "inspect"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error for an unknown subcommand does not mention %q: %v", name, err)
		}
	}

	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := runKEK([]string{"init", "-out", path}); err != nil {
		t.Fatalf("dispatch to init: %v", err)
	}
	if err := runKEK([]string{"rotate", "-file", path}); err != nil {
		t.Fatalf("dispatch to rotate: %v", err)
	}
	if err := runKEK([]string{"inspect", "-file", path}); err != nil {
		t.Fatalf("dispatch to inspect: %v", err)
	}
}

// TestRunAssertionKeyDispatches covers the other subcommand table.
func TestRunAssertionKeyDispatches(t *testing.T) {
	if err := runAssertionKey(nil); err == nil {
		t.Error("no subcommand was accepted")
	}
	if err := runAssertionKey([]string{"frobnicate"}); err == nil {
		t.Error("an unknown subcommand was accepted")
	}

	path := filepath.Join(t.TempDir(), "assertion-key.pem")
	if err := runAssertionKey([]string{"init", "-out", path}); err != nil {
		t.Fatalf("dispatch to init: %v", err)
	}
	if err := runAssertionKey([]string{"inspect", "-file", path}); err != nil {
		t.Fatalf("dispatch to inspect: %v", err)
	}
}

// TestAssertionKeyInitWritesAKeyTheIssuerAccepts checks the file against the
// package that signs with it.
func TestAssertionKeyInitWritesAKeyTheIssuerAccepts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assertion-key.pem")
	if err := assertionKeyInit([]string{"-out", path}); err != nil {
		t.Fatalf("assertion-key init: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}

	// inspect loads the key and builds an issuer and a JWK Set from it, which
	// is the whole of what the service does with the file at startup.
	if err := assertionKeyInspect([]string{"-file", path}); err != nil {
		t.Fatalf("the issuer refuses the key this tool just wrote: %v", err)
	}

	if err := assertionKeyInit([]string{"-out", path}); err == nil {
		t.Error("a second init overwrote the signing key without -force")
	}
}

// TestAssertionKeyInspectRefusesWhatIsNotAKey covers the failure an operator
// meets when they point it at the keyring by mistake, which is the neighbouring
// file with a similar name.
func TestAssertionKeyInspectRefusesWhatIsNotAKey(t *testing.T) {
	dir := t.TempDir()
	keyring := filepath.Join(dir, "keyring.json")
	if err := kekInit([]string{"-out", keyring}); err != nil {
		t.Fatalf("init keyring: %v", err)
	}
	if err := assertionKeyInspect([]string{"-file", keyring}); err == nil {
		t.Error("the keyring was accepted as a signing key")
	}
	if err := assertionKeyInspect([]string{"-file", filepath.Join(dir, "absent.pem")}); err == nil {
		t.Error("a key that does not exist was inspected")
	}
}

// TestPepperRefusesToBeShorterThanItsHashOutput pins the bound, which exists
// because the pepper is an HMAC key.
func TestPepperRefusesToBeShorterThanItsHashOutput(t *testing.T) {
	if err := runPepper([]string{"-bytes", "16"}); err == nil {
		t.Error("a 16-byte pepper was accepted; it is an HMAC key and 32 is the hash output length")
	}
	if err := runPepper([]string{"-bytes", "32"}); err != nil {
		t.Errorf("a 32-byte pepper was refused: %v", err)
	}
	if err := runPepper([]string{"-bytes", "64"}); err != nil {
		t.Errorf("a 64-byte pepper was refused: %v", err)
	}
}
