package alerts

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/store"
)

const (
	// cataloguePath is the document an operator builds a rota against.
	cataloguePath = "../../docs/MONITORING.md"
	// readmePath states the count in prose, in two places.
	readmePath = "../../README.md"
	// catalogueHeading opens the table.
	catalogueHeading = "## The alert types"
)

// TestTheCatalogueIsTheAlertTypes holds docs/MONITORING.md to what this package
// declares.
//
// The table is the operator's contract in the same way the SIEM vocabulary is
// the analyst's: a rota built from it assumes a condition absent from the table
// is a condition this version does not raise. Three types were added after the
// table was first written, and the table kept up while the prose counting it did
// not, which is the drift this file exists to stop.
//
// The severity column is checked as well as the names. A row that understates a
// severity is worse than a missing row, because it is read and believed: an
// operator who sees `warning` against the one condition that is critical has
// been told, in writing, not to get out of bed for it.
func TestTheCatalogueIsTheAlertTypes(t *testing.T) {
	declared := declaredTypes(t)
	documented := documentedTypes(t)

	declaredNames := sortedKeys(declared)
	documentedNames := sortedNames(documented)

	if !reflect.DeepEqual(declaredNames, documentedNames) {
		for _, name := range absentFrom(declaredNames, documentedNames) {
			t.Errorf("%s is declared in alerts.go and absent from the catalogue; "+
				"an operator has no row telling them what to do when it fires", name)
		}
		for _, name := range absentFrom(documentedNames, declaredNames) {
			t.Errorf("%s is in the catalogue and declared nowhere; "+
				"a rota waits for an alert that cannot arrive", name)
		}
		return
	}

	for _, row := range documented {
		want := declared[row.name]
		if row.severity != want {
			t.Errorf("the catalogue gives %s severity %q and alerts.go declares %q",
				row.name, row.severity, want)
		}
	}
}

// TestTheCatalogueIsNumberedInOrder keeps the table reviewable.
//
// The rows carry an ordinal, so a row inserted without renumbering, or a row
// removed without closing the gap, is a table two readers cite differently.
func TestTheCatalogueIsNumberedInOrder(t *testing.T) {
	for n, row := range documentedTypes(t) {
		if row.ordinal != n+1 {
			t.Errorf("catalogue row for %s is numbered %d and is in position %d",
				row.name, row.ordinal, n+1)
		}
	}
}

// TestTheReadmeCountsTheAlertTypes holds the prose to the declared set.
//
// README.md states the count twice, in words. Both were written when there were
// ten and stayed at ten through three additions, which is the failure a count
// written by hand has: it is correct once, it is never wrong loudly, and the
// reader who trusts it is the one deciding whether this product does enough.
func TestTheReadmeCountsTheAlertTypes(t *testing.T) {
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read %s: %v", readmePath, err)
	}

	want := len(declaredTypes(t))
	spelled, ok := numberWords[want]
	if !ok {
		t.Fatalf("there are now %d alert types and this test has no word for that number", want)
	}

	found := countPhrase.FindAllStringSubmatch(string(raw), -1)
	if len(found) == 0 {
		t.Fatalf("README.md no longer states the number of alert types; "+
			"either the sentences were rewritten, in which case delete this test, "+
			"or the phrase moved and the count is now unchecked (expected %q)", spelled)
	}
	for _, m := range found {
		if !strings.EqualFold(m[1], spelled) {
			t.Errorf("README.md says %q alert types and %d are declared; the prose should read %q",
				m[1], want, spelled)
		}
	}
}

// countPhrase matches the prose statement of how many alert types there are.
var countPhrase = regexp.MustCompile(`(?i)\b([a-z]+) alert types\b`)

// numberWords spells the counts this catalogue can plausibly reach. The
// catalogue is short on purpose, so the range is short on purpose.
var numberWords = map[int]string{
	8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
	13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
	17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty",
}

// catalogueRow matches one row of the alert table. The severity cell is
// optionally emphasised, which the document does for the single critical
// condition.
var catalogueRow = regexp.MustCompile(
	"(?m)^\\| ([0-9]+) \\| `([a-z0-9_.]+)` \\| \\*{0,2}([a-z]+)\\*{0,2} \\|")

type catalogueEntry struct {
	ordinal  int
	name     string
	severity store.Severity
}

func documentedTypes(t *testing.T) []catalogueEntry {
	t.Helper()
	raw, err := os.ReadFile(cataloguePath)
	if err != nil {
		t.Fatalf("read %s: %v", cataloguePath, err)
	}

	// Only the alert table, so that the tables above and below it, which quote
	// configuration keys and metric names, are not read as declarations.
	body := string(raw)
	start := strings.Index(body, catalogueHeading)
	if start < 0 {
		t.Fatalf("%s no longer has a %q section", cataloguePath, catalogueHeading)
	}
	body = body[start+len(catalogueHeading):]
	if end := strings.Index(body, "\n## "); end >= 0 {
		body = body[:end]
	}

	var out []catalogueEntry
	for _, m := range catalogueRow.FindAllStringSubmatch(body, -1) {
		ordinal, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("catalogue row %q has an unreadable ordinal: %v", m[2], err)
		}
		out = append(out, catalogueEntry{ordinal: ordinal, name: m[2], severity: store.Severity(m[3])})
	}
	if len(out) == 0 {
		t.Fatalf("no alert rows found in %s; the table's shape has changed", cataloguePath)
	}
	return out
}

// declaredTypes reads the specs table this package defines, which is the set the
// service can actually raise.
func declaredTypes(t *testing.T) map[string]store.Severity {
	t.Helper()
	out := make(map[string]store.Severity, len(specs))
	for typ := range specs {
		out[string(typ)] = typ.Severity()
	}
	if len(out) < 10 {
		t.Fatalf("found %d alert types, which is too few to be the real set", len(out))
	}
	return out
}

// sortedKeys returns the declared names, sorted.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedNames returns the documented names, sorted. Duplicates survive, so that
// a name entered twice is reported rather than silently collapsed.
func sortedNames(rows []catalogueEntry) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.name)
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
