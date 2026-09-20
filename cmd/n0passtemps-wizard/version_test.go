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
