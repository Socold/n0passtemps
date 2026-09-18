package audit

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// cataloguePath is the document a SIEM engineer maps rules against.
const cataloguePath = "../../docs/SIEM.md"

// TestTheCatalogueIsTheVocabulary holds docs/SIEM.md to what this package
// declares.
//
// The catalogue is published as a closed set: a rule written against it assumes
// that a name absent from the table is a name this version does not emit. That
// assumption is worth something only if it is checked, and a hand-maintained
// table drifts within one release. Two of these names spent their whole life as
// string literals at four call sites and appeared in MONITORING.md without ever
// being constants, which is how a vocabulary comes to have members nobody
// declared.
//
// Deliberately not a test that every event type is *used*: an event declared and
// not yet raised is a name reserved, and finding out about it from the
// documentation is the right outcome.
func TestTheCatalogueIsTheVocabulary(t *testing.T) {
	declared := declaredEventTypes(t)
	documented := documentedEventTypes(t)

	if reflect.DeepEqual(declared, documented) {
		return
	}

	for _, name := range missing(declared, documented) {
		t.Errorf("%s is declared in events.go and absent from %s; "+
			"a rule written against the catalogue will not know it exists",
			name, filepath.Base(cataloguePath))
	}
	for _, name := range missing(documented, declared) {
		t.Errorf("%s is in %s and declared nowhere; "+
			"either the constant was removed, which renames history, or the row is a typo",
			name, filepath.Base(cataloguePath))
	}
}

// TestTheCatalogueIsSorted keeps the table reviewable.
//
// A row added at the end rather than in place is how a duplicate gets in
// unnoticed, and a diff of an unsorted table shows a move as a deletion and an
// insertion.
func TestTheCatalogueIsSorted(t *testing.T) {
	documented := documentedEventTypes(t)
	for n := 1; n < len(documented); n++ {
		if documented[n-1] >= documented[n] {
			t.Errorf("the catalogue is not sorted: %q comes before %q", documented[n-1], documented[n])
		}
	}
}

// eventConstant matches one declaration in events.go.
var eventConstant = regexp.MustCompile(`(?m)^\tEvent[A-Za-z0-9]+\s+=\s+"([a-z0-9_.]+)"$`)

func declaredEventTypes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("events.go")
	if err != nil {
		t.Fatalf("read events.go: %v", err)
	}
	var out []string
	for _, m := range eventConstant.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, m[1])
	}
	if len(out) < 50 {
		t.Fatalf("found %d event constants, which is too few to be the real set; "+
			"the pattern in this test has stopped matching the file", len(out))
	}
	sort.Strings(out)
	return out
}

// catalogueRow matches a row of the event table, which is the only table in the
// document whose first cell is a backquoted dotted name.
var catalogueRow = regexp.MustCompile("(?m)^\\| `([a-z0-9_.]+)` \\|")

func documentedEventTypes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(cataloguePath)
	if err != nil {
		t.Fatalf("read %s: %v", cataloguePath, err)
	}
	// Only the vocabulary table, so that the rule table below it, which quotes
	// queries rather than names, is not read as declarations.
	body := string(raw)
	const heading = "## The audit event vocabulary"
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatalf("%s no longer has a %q section", cataloguePath, heading)
	}
	body = body[start+len(heading):]
	if end := strings.Index(body, "\n## "); end >= 0 {
		body = body[:end]
	}

	var out []string
	for _, m := range catalogueRow.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("no event rows found in %s; the table's shape has changed", cataloguePath)
	}
	sort.Strings(out)
	return out
}

// missing returns the members of a that are absent from b. Both are sorted.
func missing(a, b []string) []string {
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
