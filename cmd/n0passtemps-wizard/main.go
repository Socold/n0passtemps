// Command n0passtemps-wizard prepares a deployment.
//
// It generates the two secrets the service needs, writes a configuration file
// and a compose file, and validates what it produced. It exists because the
// alternative is a README asking an operator to run four openssl commands and
// hand-edit a TOML file, which is where deployments go wrong: a keyring placed
// beside the database, a pepper that is sixteen bytes of a passphrase, a
// relying party identifier written as a URL.
//
// Nothing here is required. Every file it writes can be written by hand, and
// the service validates its configuration at startup either way.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// commands are the subcommands, kept in a table so the usage text and the
// dispatch cannot disagree.
var commands = []struct {
	name    string
	summary string
	run     func(args []string) error
}{
	{"setup", "ask a few questions and write config.toml, docker-compose.yml and .env", runSetup},
	{"kek", "manage the key encryption keyring (init, rotate, inspect)", runKEK},
	{"assertion-key", "manage the Ed25519 key that signs assertions (init, inspect)", runAssertionKey},
	{"pepper", "generate the subject reference pepper", runPepper},
	{"check", "validate a configuration file without starting the service", runCheck},
	{"verify", "check that a database, a keyring and a pepper still open together", runVerify},
}

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	for _, c := range commands {
		if c.name == args[0] {
			if err := c.run(args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "n0passtemps-wizard %s: %v\n", c.name, err)
				os.Exit(exitCodeFor(err))
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "n0passtemps-wizard: unknown command %q\n\n", args[0])
	usage()
	os.Exit(2)
}

// exitCodeFor maps a command's error to a process exit status.
//
// Every command reports 1 for a failure, as before. verify adds one status,
// because it is written to be run from a cron job and the difference between
// "your backup will not open" and "I could not run" is the difference between
// paging someone and fixing a path. See the sentinels in verify.go.
func exitCodeFor(err error) int {
	if errors.Is(err, errCannotVerify) {
		return 2
	}
	return 1
}

func usage() {
	fmt.Fprint(os.Stderr, "n0passtemps-wizard prepares a deployment.\n\n"+
		"Usage:\n  n0passtemps-wizard <command> [flags]\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", c.name, c.summary)
	}
	fmt.Fprint(os.Stderr, "\nRun a command with -h for its flags.\n")
}

// prompt reads one answer, returning def when the operator presses return.
func prompt(r *bufio.Reader, question, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", question, def)
	} else {
		fmt.Printf("%s: ", question)
	}
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, os.ErrClosed) {
		if line == "" {
			return "", fmt.Errorf("read answer: %w", err)
		}
	}
	answer := strings.TrimSpace(line)
	if answer == "" {
		return def, nil
	}
	return answer, nil
}

// promptYesNo reads a boolean answer.
func promptYesNo(r *bufio.Reader, question string, def bool) (bool, error) {
	d := "n"
	if def {
		d = "y"
	}
	for {
		answer, err := prompt(r, question+" (y/n)", d)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Println("  Answer y or n.")
	}
}

// writeFile writes a generated file, refusing to overwrite silently.
//
// Overwriting a config.toml is an inconvenience. Overwriting a keyring
// destroys every secret sealed under it, which is why the refusal is the
// default everywhere in this tool and -force has to be asked for.
//
// The content never goes into the destination directly. It is written to a
// temporary file beside it, flushed, and renamed over it, so the destination
// holds either what it held before or all of the new content. The keyring is
// the reason: kek rotate rewrites the one file that carries every key version,
// and it is the only file here whose loss cannot be undone. Truncating it in
// place would leave an empty keyring behind a crash, a power cut or a full
// disk, and every sealed secret unreadable with it.
func writeFile(path string, content []byte, mode os.FileMode, force bool) error {
	// Lstat rather than Stat, so a symbolic link at the destination counts as a
	// file that exists, wherever it points and whether or not its target does.
	if _, err := os.Lstat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; move it aside or pass -force", path)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	tmp, err := writeTemp(path, content, mode)
	if err != nil {
		return err
	}

	// Rename replaces the destination itself rather than writing through it.
	// A symbolic link placed there is therefore replaced, not followed, and the
	// file that ends up at the path always carries the mode asked for, whatever
	// the mode of the one it replaces.
	if err = os.Rename(tmp, path); err != nil {
		removeTemp(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

// writeTemp writes content to a new file beside path and returns its name.
//
// The same directory, because a rename is only atomic within one filesystem.
// On any failure the temporary file is removed, so a refused write leaves
// nothing behind for the operator to mistake for a keyring.
func writeTemp(path string, content []byte, mode os.FileMode) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("name a temporary file: %w", err)
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix))

	// O_EXCL refuses a name that is already taken, symbolic links included, so
	// nothing placed at the temporary name beforehand is written through. The
	// file is created with its final mode rather than chmod'd afterwards, so
	// key material is never readable more widely than it will end up.
	//
	// #nosec G304 -- the name is derived from the path the operator asked the wizard to write, and O_EXCL refuses
	// anything that already exists there
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", tmp, err)
	}

	if _, err = f.Write(content); err != nil {
		// The write already failed, so a close error would be the same fault
		// reported twice and the file is incomplete either way.
		_ = f.Close()
		removeTemp(tmp)
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}

	// Flushed before the rename. Without it the rename can reach the disk ahead
	// of the data, and a power cut then leaves the new name on an empty file.
	if err = f.Sync(); err != nil {
		// As above: the sync is the fault worth reporting.
		_ = f.Close()
		removeTemp(tmp)
		return "", fmt.Errorf("sync %s: %w", tmp, err)
	}

	// Checked, not deferred. What this function writes is a keyring, a signing
	// key or a configuration file, and a close that fails is how a short file
	// comes to exist: the bytes were accepted by the kernel and never reached
	// the disk. Discarding that error would leave the operator with an artefact
	// that looks written and does not open, which is the failure the verify
	// subcommand exists to catch long afterwards.
	if err = f.Close(); err != nil {
		removeTemp(tmp)
		return "", fmt.Errorf("close %s: %w", tmp, err)
	}
	return tmp, nil
}

// removeTemp deletes a temporary file on a path that has already failed.
func removeTemp(tmp string) {
	// The caller is returning the error that matters. One from the removal
	// would only add that a stray dot file was left beside the destination,
	// which is untidy and harms nothing.
	_ = os.Remove(tmp)
}

// syncDir flushes a directory, which is where a rename is recorded.
//
// Until it is flushed, a power cut can bring back the previous entry. For a
// rotated keyring that is the old keyring, complete, so nothing is lost; but
// the command would have reported a key version the disk does not hold.
func syncDir(dir string) error {
	// #nosec G304 -- the parent of the path the operator asked the wizard to write, opened read-only to flush it
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	if err = d.Sync(); err != nil {
		// The sync is the fault worth reporting, and nothing was written
		// through this handle for a close to lose.
		_ = d.Close()
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err = d.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dir, err)
	}
	return nil
}
