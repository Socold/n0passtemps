package api

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// specPath is the document an integrator writes a client against.
const specPath = "../../api/openapi.yaml"

// TestTheSpecificationIsTheAPISurface holds api/openapi.yaml to what the router
// actually serves.
//
// The specification is the contract for a product whose support model is
// documentation and nothing else: an integrator who cannot find a route in this
// file has no second place to look, and a route described here that does not
// exist sends them to write a client against nothing. Neither failure produces
// a test failure anywhere else in this repository, which is how GET /v1/metrics
// shipped, was scraped, was documented in MONITORING.md and in EXTENSIONS.md,
// and was absent from the specification for a release.
//
// Deliberately both directions. The undocumented route is the likelier mistake,
// because adding a route is a change to Go and adding it to the specification is
// a change to YAML that compiles either way. The documented-but-absent route is
// the worse one, because it fails at the integrator's end rather than at ours.
func TestTheSpecificationIsTheAPISurface(t *testing.T) {
	served := servedOperations(t)
	documented := documentedOperations(t)

	if reflect.DeepEqual(served, documented) {
		return
	}

	for _, op := range absentFrom(served, documented) {
		t.Errorf("%s is served by router.go and absent from api/openapi.yaml; "+
			"an integrator has no way to find it", op)
	}
	for _, op := range absentFrom(documented, served) {
		t.Errorf("%s is in api/openapi.yaml and served by nothing; "+
			"a client written against it gets 404", op)
	}
}

// handleCall matches one route registration in router.go.
//
// It requires a method, which is what excludes the three registrations that are
// deliberately outside the document: mux.Handle("/admin/") is the
// server-rendered operator console and serves HTML, mux.Handle("/") is the
// catch-all that answers anything unmatched, and neither is part of the JSON
// API. OPTIONS is excluded below for the same reason: the preflight handler is
// registered once for the whole /v1/ prefix and answers no route of its own.
var handleCall = regexp.MustCompile(`(?m)^\s*mux\.Handle\("(GET|POST|PUT|DELETE|PATCH|OPTIONS) (\S+)"`)

func servedOperations(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	var out []string
	for _, m := range handleCall.FindAllStringSubmatch(string(raw), -1) {
		method, pattern := m[1], m[2]
		if method == "OPTIONS" {
			continue
		}
		out = append(out, method+" "+pattern)
	}
	if len(out) < 40 {
		t.Fatalf("found %d route registrations, which is too few to be the real set; "+
			"the pattern in this test has stopped matching router.go", len(out))
	}
	sort.Strings(out)
	return out
}

var (
	// specPathLine matches a path item, which sits at two spaces of indent.
	specPathLine = regexp.MustCompile(`(?m)^ {2}(/\S*):\s*$`)
	// specMethodLine matches an operation, at four spaces under its path item.
	specMethodLine = regexp.MustCompile(`(?m)^ {4}(get|post|put|delete|patch):\s*$`)
)

func documentedOperations(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}

	// Only the paths section, so that component schemas and the tag list, which
	// are indented the same way, are not read as routes.
	body := string(raw)
	const heading = "\npaths:\n"
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatalf("%s no longer has a paths section", specPath)
	}
	body = body[start+len(heading):]
	if end := strings.Index(body, "\ncomponents:\n"); end >= 0 {
		body = body[:end]
	}

	var out []string
	var path string
	for _, line := range strings.Split(body, "\n") {
		if m := specPathLine.FindStringSubmatch(line); m != nil {
			path = m[1]
			continue
		}
		if m := specMethodLine.FindStringSubmatch(line); m != nil {
			if path == "" {
				t.Fatalf("operation %q before any path item; the document's shape has changed", m[1])
			}
			out = append(out, strings.ToUpper(m[1])+" "+path)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no operations found in %s; the document's shape has changed", specPath)
	}
	sort.Strings(out)
	return out
}

// absentFrom returns the members of a that are not in b. Both are sorted.
func absentFrom(a, b []string) []string {
	have := make(map[string]struct{}, len(b))
	for _, s := range b {
		have[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := have[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
