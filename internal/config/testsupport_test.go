package config

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// MinPepperBytesForTest mirrors the subject package's minimum without importing
// it, which would be a cycle.
const MinPepperBytesForTest = 32

// TestEnvKeysAreRecorded is a guard on the guard: if the recording mechanism
// stops working, the example-file test would pass vacuously.
func TestEnvKeysAreRecorded(t *testing.T) {
	keys := recordedEnvKeys()
	if len(keys) < 40 {
		t.Fatalf("applyEnv consulted %d keys, which is too few to be the real set", len(keys))
	}
	want := []string{"WEBAUTHN_RP_ID", "DATABASE_DSN", "TENANT_ID", "LOGGING_LEVEL"}
	have := map[string]bool{}
	for _, k := range keys {
		have[k] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("%s is not among the recorded keys", w)
		}
	}
}

// envVarPattern finds the prefixed variables mentioned in a file.
var envVarPattern = regexp.MustCompile(`N0PASSTEMPS_[A-Z0-9_]+`)

func envVarsMentioned(body string) []string {
	seen := map[string]struct{}{}
	for _, m := range envVarPattern.FindAllString(body, -1) {
		seen[strings.TrimRight(m, "_")] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// knownEnvKeysForTest reports which prefixed variables applyEnv consults.
//
// It is derived by running applyEnv against a recording of every lookup, so the
// set cannot drift from the code the way a hand-written list would.
func knownEnvKeysForTest() map[string]bool {
	out := map[string]bool{}
	for _, k := range recordedEnvKeys() {
		out[EnvPrefix+k] = true
	}
	return out
}
