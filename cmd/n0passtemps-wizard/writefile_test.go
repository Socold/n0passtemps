package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is what every subcommand that produces key material ends in, and
// kek rotate calls it on the one file that holds every key version. The
// properties below are the ones a rewrite in place did not have: the old
// content survives a write that fails, the mode printed to the operator is the
// mode on disk, and nothing at the destination is written through.

// entries lists a directory, so a test can say exactly what a write left in it.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(list))
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

// TestTheKeyringIsReplacedAtomically checks the replacement from the outside:
// the new content is there, under the mode asked for, and nothing else is.
//
// The existing file is 0644 on purpose. A mode handed to open applies only to a
// file that open creates, so a rewrite in place kept whatever mode it found
// while kek rotate went on printing "mode 0600".
func TestTheKeyringIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write the existing file: %v", err)
	}
	// Chmod rather than the mode above, which the umask may already have cut.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := writeFile(path, []byte("new"), 0o600, true); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600: the replaced file kept the mode of the one before it", perm)
	}
	if names := entries(t, dir); len(names) != 1 || names[0] != "keyring.json" {
		t.Errorf("the directory holds %v after a successful write, want only keyring.json", names)
	}
}

// TestWriteFileRefusesAnExistingFileWithoutForce is the default the whole tool
// relies on, checked at the function rather than through one subcommand.
func TestWriteFileRefusesAnExistingFileWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write the existing file: %v", err)
	}

	err := writeFile(path, []byte("new"), 0o600, false)
	if err == nil {
		t.Fatal("an existing file was overwritten without -force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want it to say the file already exists", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "old" {
		t.Errorf("content = %q after a refused write, want it untouched", got)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("the directory holds %v after a refused write, want only keyring.json", names)
	}
}

// TestWriteFileRefusesASymbolicLinkWithoutForce covers the link that Stat
// would have read as absent: one whose target does not exist yet. Followed, it
// lets whoever placed it choose where the keyring is written.
func TestWriteFileRefusesASymbolicLinkWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "keyring.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}

	if err := writeFile(path, []byte("new"), 0o600, false); err == nil {
		t.Fatal("a symbolic link at the destination was accepted without -force")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Error("the write went through the link and created its target")
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Errorf("the directory holds %v after a refused write, want only the link", names)
	}
}

// TestWriteFileReplacesASymbolicLinkRatherThanFollowingIt is the same link
// with -force: the path ends up holding the file, and the target is left alone.
func TestWriteFileReplacesASymbolicLinkRatherThanFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(target, []byte("not a keyring"), 0o600); err != nil {
		t.Fatalf("write the target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}

	if err := writeFile(path, []byte("new"), 0o600, true); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("the destination is %v, want a regular file in place of the link", info.Mode())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read the target: %v", err)
	}
	if string(got) != "not a keyring" {
		t.Errorf("the link's target now holds %q: the write followed the link", got)
	}
}

// TestAFailedWriteLeavesNoTemporaryFile checks both ends of the failure path.
//
// A directory at the destination fails at the rename, after the temporary file
// is complete, which is the case where forgetting to remove it would leave a
// full copy of a keyring under a name nobody looks for. A directory that cannot
// be created fails before anything is written.
func TestAFailedWriteLeavesNoTemporaryFile(t *testing.T) {
	t.Run("the destination is a directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "keyring.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		if err := writeFile(path, []byte("new"), 0o600, true); err == nil {
			t.Fatal("a directory at the destination was replaced by a file")
		}
		if names := entries(t, dir); len(names) != 1 || names[0] != "keyring.json" {
			t.Errorf("the directory holds %v after a failed write, want only keyring.json", names)
		}
		if names := entries(t, path); len(names) != 0 {
			t.Errorf("the destination directory holds %v after a failed write, want nothing", names)
		}
	})

	t.Run("the parent cannot be created", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "kek")
		if err := os.WriteFile(blocker, []byte("a file, not a directory"), 0o600); err != nil {
			t.Fatalf("write the blocker: %v", err)
		}

		path := filepath.Join(blocker, "sub", "keyring.json")
		if err := writeFile(path, []byte("new"), 0o600, false); err == nil {
			t.Fatal("a keyring was written beneath a regular file")
		}
		if names := entries(t, dir); len(names) != 1 || names[0] != "kek" {
			t.Errorf("the directory holds %v after a failed write, want only kek", names)
		}
	})
}
