package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// TestShippedExampleValidates guards the annotated example against drift.
//
// The example file documents every key, so it is the first thing an operator
// copies from. A key renamed in this package without the example being updated
// would produce a file that fails to load with "unknown field", which is a
// confusing first experience of the software. Loading it here turns that into a
// failed build instead.
func TestShippedExampleValidates(t *testing.T) {
	path := filepath.Join("..", "..", "config", "config.example.toml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example not present: %v", err)
	}

	// The example deliberately contains no secret, so the one the validator
	// insists on is supplied here.
	t.Setenv(EnvPrefix+"SUBJECT_PEPPER",
		base64.StdEncoding.EncodeToString(make([]byte, MinPepperBytesForTest)))

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the shipped example does not validate:\n%v", err)
	}

	// A handful of spot checks, so a truncated or half-written example is
	// caught as well as an invalid one.
	if cfg.Tenant.ID == "" {
		t.Error("example sets no tenant id")
	}
	if cfg.WebAuthn.RPID == "" {
		t.Error("example sets no relying party identifier")
	}
	if len(cfg.WebAuthn.Origins) == 0 {
		t.Error("example lists no origin")
	}
}

// TestExampleEnvFileNamesRealVariables checks the other shipped example.
//
// Every N0PASSTEMPS_ variable it mentions, commented out or not, must be one
// this package actually reads. An example naming a variable that does nothing
// is worse than one that omits it, because the operator believes they have
// configured something.
func TestExampleEnvFileNamesRealVariables(t *testing.T) {
	path := filepath.Join("..", "..", "config", ".env.example")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("example not present: %v", err)
	}

	known := knownEnvKeysForTest()
	for _, name := range envVarsMentioned(string(raw)) {
		// Not every variable in the file is read by this package, and the
		// exceptions are each read by something else:
		//
		//   SUBJECT_PEPPER  read by internal/subject, which this package only
		//                   names through subject.pepper_env
		//   KEK             read by internal/crypto/kek, likewise named
		//                   through kek.env_var
		//   VERSION         consumed by the compose files to pin the image
		//   PUBLISH         consumed by the compose files for the host port
		//
		// A variable that is in neither set does nothing at all, and an
		// example naming one is worse than an example omitting it, because the
		// operator believes they have configured something.
		switch name {
		case EnvPrefix + "SUBJECT_PEPPER",
			EnvPrefix + "KEK",
			EnvPrefix + "VERSION",
			EnvPrefix + "PUBLISH":
			continue
		}
		if !known[name] {
			t.Errorf("%s names %s, which this package never reads", path, name)
		}
	}
}
