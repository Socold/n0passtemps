package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The wizard prints the image to run and writes the version to pin into .env,
// and docs/DEPLOYMENT.md carries the same command for an operator who never
// runs the wizard. All three went on saying 1.1.0 through 1.1.1 and 1.1.2, so
// anybody following the instructions after the September security review would
// have pinned an image from before its fixes and had no way to know.
//
// That is a worse failure than a stale number in prose: the operator did
// exactly what they were told, the service starts, and the deployment is a
// release behind on security fixes with nothing to indicate it.
//
// The version this checks against is the newest entry in CHANGELOG.md, which is
// the one place a release is recorded before it is tagged.

// changelogVersion is the newest released version, read from the changelog.
func changelogVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("CHANGELOG.md carries no released version heading")
	}
	return string(m[1])
}

// TestTheWizardPinsTheCurrentImage holds the two strings it produces to the
// newest release.
func TestTheWizardPinsTheCurrentImage(t *testing.T) {
	want := changelogVersion(t)

	a := answers{Deployment: "sqlite", RPID: "localhost", Origin: "http://localhost:8080",
		Addr: "127.0.0.1:8080", TenantName: "Example Ltd", Lite: true}

	env := renderEnv(a)
	if !strings.Contains(env, "N0PASSTEMPS_VERSION="+want+"\n") {
		line := "N0PASSTEMPS_VERSION=" + firstVersionIn(env)
		t.Errorf(".env pins %q and the newest release is %s", line, want)
	}

	// The closing instructions are printed rather than returned, so the image
	// is read out of the source. A constant is the only place it lives.
	src, err := os.ReadFile("setup.go")
	if err != nil {
		t.Fatalf("read setup.go: %v", err)
	}
	if !strings.Contains(string(src), "ghcr.io/socold/n0passtemps:"+want) {
		t.Errorf("the closing instructions do not name the %s image", want)
	}
}

// TestTheDeploymentGuidePinsTheCurrentImage covers the operator who never runs
// the wizard and copies the commands out of the guide instead.
func TestTheDeploymentGuidePinsTheCurrentImage(t *testing.T) {
	want := changelogVersion(t)

	raw, err := os.ReadFile("../../docs/DEPLOYMENT.md")
	if err != nil {
		t.Fatalf("read DEPLOYMENT.md: %v", err)
	}

	pinned := regexp.MustCompile(`ghcr\.io/socold/n0passtemps:(\d+\.\d+\.\d+)`).FindAllStringSubmatch(string(raw), -1)
	if len(pinned) == 0 {
		t.Fatal("DEPLOYMENT.md names no pinned image, so an operator has nothing to copy")
	}
	for _, m := range pinned {
		if m[1] != want {
			t.Errorf("DEPLOYMENT.md pins %s and the newest release is %s", m[1], want)
		}
	}
}

// TestTheSpecificationDeclaresTheCurrentVersion keeps the document a client is
// generated from in step with the release it describes.
func TestTheSpecificationDeclaresTheCurrentVersion(t *testing.T) {
	want := changelogVersion(t)

	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	m := regexp.MustCompile(`(?m)^ {2}version: (\S+)`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("openapi.yaml declares no version")
	}
	if got := string(m[1]); got != want {
		t.Errorf("the specification declares %s and the newest release is %s", got, want)
	}
}

// firstVersionIn pulls a version out of the rendered file, so a failure prints
// what was actually there.
func firstVersionIn(s string) string {
	m := regexp.MustCompile(`N0PASSTEMPS_VERSION=(\S*)`).FindStringSubmatch(s)
	if m == nil {
		return "(absent)"
	}
	return m[1]
}

// TestTheDocumentedDependencyCountIsTheRealOne holds the number four documents
// state to what go.mod actually declares.
//
// It is not a vanity figure. docs/THREAT-MODEL.md counts a supply-chain
// attacker's entry points with it, so a number that drifts low understates the
// attack surface in the one document written to describe it. It had drifted
// twice: the review found "six" where there were eight, corrected three places
// and missed CONTRIBUTING.md, and go.mod itself listed go-webauthn/x as
// indirect while internal/webauthn imported it directly, which hid a ninth.
func TestTheDocumentedDependencyCountIsTheRealOne(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	// The first require block holds the direct ones; indirect entries carry the
	// marker and the second block is entirely indirect.
	block := regexp.MustCompile(`(?s)require \((.*?)\n\)`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("go.mod has no require block")
	}
	direct := 0
	for _, line := range strings.Split(string(block[1]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.Contains(line, "// indirect") {
			continue
		}
		direct++
	}
	if direct == 0 {
		t.Fatal("no direct dependencies were found; the shape of go.mod has changed")
	}

	words := map[int]string{6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}
	want, ok := words[direct]
	if !ok {
		t.Fatalf("go.mod declares %d direct dependencies and this test has no word for that", direct)
	}

	for _, doc := range []string{"../../docs/ARCHITECTURE.md", "../../docs/THREAT-MODEL.md",
		"../../CONTRIBUTING.md", "../../README.md"} {
		body, rerr := os.ReadFile(doc)
		if rerr != nil {
			t.Fatalf("read %s: %v", doc, rerr)
		}
		stated := regexp.MustCompile(`(?i)\b(six|seven|eight|nine|ten|eleven|twelve) direct`).FindAllStringSubmatch(string(body), -1)
		if len(stated) == 0 {
			continue
		}
		for _, m := range stated {
			if !strings.EqualFold(m[1], want) {
				t.Errorf("%s says %q direct dependencies and go.mod declares %d",
					strings.TrimPrefix(doc, "../../"), m[1], direct)
			}
		}
	}
}
