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
	fmt.Fprint(os.Stderr, "n0passtemps-wizard prepares a deployment.\n\nUsage:\n  n0passtemps-wizard <command> [flags]\n\nCommands:\n")
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
func writeFile(path string, content []byte, mode os.FileMode, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; move it aside or pass -force", path)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	// The file is created with its final mode rather than chmod'd afterwards,
	// so there is no window in which a keyring is world-readable.
	//
	// #nosec G304 -- the destination is the path the operator asked the wizard to write, and an existing file is
	// refused above unless -force was passed
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
