package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// composeOnlyVars are the prefixed variables the shipped deployment files use
// for their own interpolation rather than passing to the binary.
//
// They are legitimate, so they are listed rather than treated as errors. The
// list is explicit because the alternative, exempting anything that looks like
// a deployment concern, is how the names drift in the first place.
var composeOnlyVars = map[string]string{
	"N0PASSTEMPS_VERSION":     "pins the image tag in the compose files",
	"N0PASSTEMPS_PUBLISH":     "the host address the container port is published on",
	"N0PASSTEMPS_HTTP_PORT":   "the host port the container port is published on",
	"N0PASSTEMPS_CONFIG_FILE": "the host path of the configuration file to mount",
}

// clientVars are consumed by the shipped example clients, which are programs
// that CALL the service rather than configure it. They have nothing to do with
// applyEnv and are listed so that the check below still covers the examples
// for a misspelling of a server variable.
var clientVars = map[string]string{
	"N0PASSTEMPS_URL":               "base URL of the service the example talks to",
	"N0PASSTEMPS_API_KEY":           "the api key the example authenticates with",
	"N0PASSTEMPS_ADMIN_TOKEN":       "the administrative token the example authenticates with",
	"N0PASSTEMPS_ISSUER":            "expected iss claim when the example verifies an assertion",
	"N0PASSTEMPS_EXPECTED_AUDIENCE": "expected aud claim when the example verifies an assertion",
	"N0PASSTEMPS_CA_FILE":           "certificate authority the example trusts for TLS",
	"N0PASSTEMPS_SKIP_MINT":         "lets the admin example reuse an existing key",
}

// testVars are read by the test suites, never by the binary. They are listed so
// the build files can be checked too: the Makefile once exported
// N0PASSTEMPS_TEST_POSTGRES_URL while the suite read ..._DSN, and since an
// unset variable makes the suite skip rather than fail, "make test-integration"
// reported success without running a single PostgreSQL test.
var testVars = map[string]string{
	"N0PASSTEMPS_TEST_POSTGRES_DSN": "connection string for the PostgreSQL integration suite",
	"N0PASSTEMPS_TEST_MDS_BLOB":     "path to a FIDO metadata BLOB for the attestation test",
}

// externallyReadVars are read by a package other than this one, so they never
// appear in applyEnv.
var externallyReadVars = map[string]string{
	"N0PASSTEMPS_SUBJECT_PEPPER": "read by internal/subject, named through subject.pepper_env",
	"N0PASSTEMPS_KEK":            "read by internal/crypto/kek, named through kek.env_var",
}

var deployVarPattern = regexp.MustCompile(`N0PASSTEMPS_[A-Z0-9_]+`)

// TestDeploymentFilesNameRealVariables is a regression guard.
//
// The shipped deployment files were written against invented variable names:
// N0PASSTEMPS_LISTEN_ADDR, N0PASSTEMPS_LOG_LEVEL, N0PASSTEMPS_KEK_FILE,
// N0PASSTEMPS_DATA_DIR, N0PASSTEMPS_DATABASE_URL and N0PASSTEMPS_CONFIG. None
// of them is read by anything. The failure mode is the worst kind: the service
// starts, ignores every one of those settings, and runs on its defaults while
// the operator believes it is configured. A container binding the wrong address
// or using the wrong keyring path is not a subtle difference.
//
// Nothing in a build or a test suite catches that, because an unrecognised
// environment variable is not an error anywhere. So it is checked here.
func TestDeploymentFilesNameRealVariables(t *testing.T) {
	root := filepath.Join("..", "..")
	known := knownEnvKeysForTest()

	type site struct {
		file string
		name string
	}
	var unknown []site

	for _, dir := range []string{"deploy", "config", "examples", ".github", "Makefile"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, name := range deployVarPattern.FindAllString(string(raw), -1) {
				name = strings.TrimRight(name, "_")
				if known[name] {
					continue
				}
				if _, ok := composeOnlyVars[name]; ok {
					continue
				}
				if _, ok := externallyReadVars[name]; ok {
					continue
				}
				if _, ok := clientVars[name]; ok {
					continue
				}
				if _, ok := testVars[name]; ok {
					continue
				}
				unknown = append(unknown, site{file: rel, name: name})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if len(unknown) == 0 {
		return
	}

	// Deduplicate so one variable used in six files reports once.
	seen := map[string][]string{}
	for _, u := range unknown {
		seen[u.name] = append(seen[u.name], u.file)
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		files := seen[n]
		sort.Strings(files)
		t.Errorf("%s is set in %s but nothing reads it; the service would start and "+
			"silently ignore it. Either use the name applyEnv consults, or add it to "+
			"composeOnlyVars with a reason if it is consumed by the deployment tooling "+
			"rather than the binary.", n, strings.Join(dedupe(files), ", "))
	}
}

// TestComposeOnlyVarsAreNotAlsoRealKeys keeps the two lists from overlapping.
//
// A name in both would mean the exemption is hiding a real key, so a typo in
// that key would no longer be reported.
func TestComposeOnlyVarsAreNotAlsoRealKeys(t *testing.T) {
	known := knownEnvKeysForTest()
	for name, why := range composeOnlyVars {
		if known[name] {
			t.Errorf("%s is exempted as deployment tooling (%q) but applyEnv does read "+
				"it; remove the exemption", name, why)
		}
	}
	for name, why := range externallyReadVars {
		if known[name] {
			t.Errorf("%s is listed as externally read (%q) but applyEnv reads it too; "+
				"remove the entry", name, why)
		}
	}
	for name, why := range clientVars {
		if known[name] {
			t.Errorf("%s is listed as an example client variable (%q) but applyEnv "+
				"reads it too; remove the entry", name, why)
		}
	}
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// TestShippedKubernetesConfigLoads is the other half of the deployment guard.
//
// The ConfigMap carries a TOML document, and the loader refuses unknown fields,
// so a key that does not exist stops the pod starting rather than being
// ignored. The shipped manifest was written against four keys that do not
// exist: server.listen_addr, server.public_url, kek.file and
// features.admin_rbac_enabled. Nobody would find that until they applied it.
//
// The TOML is extracted with a deliberately small parser rather than a YAML
// dependency, because adding one to an authentication product for the sake of
// one test is the wrong trade.
func TestShippedKubernetesConfigLoads(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "kubernetes", "configmap.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("manifest not present: %v", err)
	}

	toml, err := extractBlockScalar(string(raw), "config.toml: |")
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if strings.TrimSpace(toml) == "" {
		t.Fatalf("%s: the embedded configuration is empty", path)
	}

	tmp := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(tmp, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	// The manifest deliberately omits the secrets and the database connection
	// string, which arrive from a Secret as environment variables. They are
	// supplied here the same way the cluster would.
	t.Setenv(EnvPrefix+"SUBJECT_PEPPER", strings.Repeat("a", 44))
	t.Setenv(EnvPrefix+"DATABASE_DSN",
		"postgres://n0passtemps:placeholder@postgres:5432/n0passtemps?sslmode=verify-full")

	if _, err := Load(tmp); err != nil {
		t.Fatalf("the shipped Kubernetes configuration does not load, so the pod would "+
			"fail to start:\n%v", err)
	}
}

// extractBlockScalar pulls an indented YAML block scalar out of a document.
func extractBlockScalar(doc, marker string) (string, error) {
	i := strings.Index(doc, marker)
	if i < 0 {
		return "", errors.New("config: block scalar marker " + marker + " not found")
	}

	lines := strings.Split(doc[i+len(marker):], "\n")
	var out []string
	indent := -1
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			out = append(out, "")
			continue
		}
		lead := len(line) - len(strings.TrimLeft(line, " "))
		if indent < 0 {
			indent = lead
		}
		if lead < indent {
			break
		}
		out = append(out, line[indent:])
	}
	return strings.Join(out, "\n"), nil
}
