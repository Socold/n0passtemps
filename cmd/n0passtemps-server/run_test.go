package main

import (
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/config"
)

// run is the whole of the process: it parses the flags, loads the
// configuration, opens the store and the keyring, and serves until a signal.
// Most of that cannot be reached from a test without starting a listener and
// sending a signal to the test binary, but three of its paths return before any
// of it happens, and those three are the ones an operator is told to run.
//
// -check-config is what CONFIGURATION.md and the wizard both tell them to run
// after editing a file. -migrate is what a deployment pipeline runs before it
// starts the new version. -version is what an incident report asks for. None of
// them had a test, so a change that broke one would have been found by whoever
// was relying on it at the time.

// withArgs runs fn with os.Args set and the global flag set reset, because run
// parses into flag.CommandLine and a second parse in one process would
// otherwise see the first call's flags.
func withArgs(t *testing.T, args []string, fn func()) {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	os.Args = args
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	fn()
}

// writeRunnableConfig writes a configuration the service would accept, with the
// keyring and the signing key beside it but outside the data directory.
func writeRunnableConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "secrets")
	dataDir := filepath.Join(dir, "data")
	for _, d := range []string{keyDir, dataDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	keyPath := filepath.Join(keyDir, "keyring.json")
	writeKeyring(t, keyPath)

	body := "" +
		"[tenant]\nid = \"acme\"\nname = \"Acme Ltd\"\n\n" +
		"[server]\naddr = \"127.0.0.1:0\"\n\n" +
		"[database]\ndriver = \"sqlite\"\n" +
		"dsn = " + quote(filepath.Join(dataDir, "store.db")) + "\n" +
		"data_dir = " + quote(dataDir) + "\n\n" +
		"[kek]\nprovider = \"file\"\npath = " + quote(keyPath) + "\n\n" +
		"[assertion]\nsigning_key_path = " + quote(filepath.Join(keyDir, "assert.pem")) + "\n\n" +
		"[webauthn]\nrp_id = \"localhost\"\norigins = [\"http://localhost:8080\"]\n"

	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(config.EnvPrefix+"SUBJECT_PEPPER",
		base64.StdEncoding.EncodeToString([]byte("a-test-pepper-of-thirty-two-byte")))
	return path
}

// quote renders a path as a TOML string.
func quote(s string) string { return "\"" + strings.ReplaceAll(s, "\\", "\\\\") + "\"" }

// TestVersionReturnsWithoutTouchingAnything is the flag an incident report asks
// for, and it has to work on a host where nothing else is configured.
func TestVersionReturnsWithoutTouchingAnything(t *testing.T) {
	withArgs(t, []string{"n0passtemps-server", "-version"}, func() {
		if err := run(); err != nil {
			t.Fatalf("-version returned %v", err)
		}
	})
}

// TestCheckConfigAcceptsAValidFileAndRefusesABadOne is the command the wizard
// and CONFIGURATION.md both point at.
func TestCheckConfigAcceptsAValidFileAndRefusesABadOne(t *testing.T) {
	path := writeRunnableConfig(t)

	withArgs(t, []string{"n0passtemps-server", "-check-config", "-config", path}, func() {
		if err := run(); err != nil {
			t.Fatalf("a valid configuration was refused: %v", err)
		}
	})

	// A file that does not validate reports every problem rather than the
	// first, which is the property the validator exists for.
	bad := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(bad, []byte("[tenant]\nid = \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withArgs(t, []string{"n0passtemps-server", "-check-config", "-config", bad}, func() {
		err := run()
		if err == nil {
			t.Fatal("an invalid configuration was accepted")
		}
		if !strings.Contains(err.Error(), "configuration is not valid") {
			t.Errorf("the error does not say what was wrong:\n%v", err)
		}
		if strings.Count(err.Error(), "\n") < 2 {
			t.Errorf("only one problem was reported, so an operator fixes them one at a time:\n%v", err)
		}
	})

	// A path that does not exist is a different mistake and reads differently.
	withArgs(t, []string{"n0passtemps-server", "-check-config", "-config",
		filepath.Join(t.TempDir(), "absent.toml")}, func() {
		if err := run(); err == nil {
			t.Error("a configuration file that does not exist was accepted")
		}
	})
}

// TestMigrateAppliesTheSchemaAndReturns is what a deployment pipeline runs
// before it starts the new version, and it has to be safe to run twice.
func TestMigrateAppliesTheSchemaAndReturns(t *testing.T) {
	path := writeRunnableConfig(t)

	for _, pass := range []string{"first", "second"} {
		withArgs(t, []string{"n0passtemps-server", "-migrate", "-config", path}, func() {
			if err := run(); err != nil {
				t.Fatalf("the %s migration pass returned %v", pass, err)
			}
		})
	}

	// The database now exists and carries the schema, which is what the
	// pipeline was relying on.
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err = os.Stat(cfg.Database.DSN); err != nil {
		t.Fatalf("no database was created at %s: %v", cfg.Database.DSN, err)
	}

	st, err := openStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("open the migrated store: %v", err)
	}
	defer func() { _ = st.Close() }()
	if _, _, err = st.ChainHead(t.Context()); err != nil {
		t.Errorf("the audit chain is not queryable after -migrate: %v", err)
	}
}
