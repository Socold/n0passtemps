package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/config"
)

// TestEveryGatedOperationIsAConfigurableOne holds the operation names the
// handlers pass to the approval gate to the closed list in internal/config.
//
// The gate matches by string comparison against
// features.dual_approval_operations, and the configuration validator accepts
// only the names in config.DualApprovalOperationNames. Nothing else connects
// the two lists, so each may drift from the other in silence and in a different
// direction.
//
// A name in the configuration that no handler passes is the worse half. The
// operator turns it on, the screen and the documentation say the operation is
// held for a second administrator, and it is held for nobody, because nothing
// ever asks. A literal in a handler that the configuration does not accept is
// the other half: the operation can never be listed, so the gate never fires
// and an operation somebody meant to guard runs on one signature.
//
// The literals are read from the call sites rather than from a list kept by
// hand in this file. A hand-kept list catches a name added to the
// configuration, which is the direction a reviewer notices anyway, and misses
// the one where a new handler invents a name of its own: the list would be as
// out of date as the thing it is checking. Reading the source means a call site
// added tomorrow is compared tomorrow.
func TestEveryGatedOperationIsAConfigurableOne(t *testing.T) {
	gated := gatedOperations(t)
	configurable := append([]string(nil), config.DualApprovalOperationNames...)
	sort.Strings(configurable)

	for _, op := range absentFrom(gated, configurable) {
		t.Errorf("a handler holds %q for approval and config.DualApprovalOperationNames does not list it, "+
			"so the operation can never be turned on and the gate never fires", op)
	}
	for _, op := range absentFrom(configurable, gated) {
		t.Errorf("config.DualApprovalOperationNames lists %q and no handler passes it to the approval gate, "+
			"so an operator who turns it on is told an operation is held that nothing holds", op)
	}
}

// gateCall matches one call to the gate and captures the operation it names.
//
// The shape is fixed because every call site is written the same way: the
// request, the caller, the tenant, then the operation as a literal.
var gateCall = regexp.MustCompile(`s\.approvalGate\(\s*r,\s*caller,\s*tenantID,\s*"([^"]+)"`)

// gatedFiles are the two files that hold an approval-gated handler. A third
// one would have to be added here, which is the point at which somebody reads
// this test and the failure it would otherwise not produce.
var gatedFiles = []string{"admin.go", "bulk.go"}

func gatedOperations(t *testing.T) []string {
	t.Helper()

	var out []string
	calls := 0
	for _, name := range gatedFiles {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(raw)
		calls += strings.Count(body, "s.approvalGate(")
		for _, m := range gateCall.FindAllStringSubmatch(body, -1) {
			out = append(out, m[1])
		}
	}

	if calls == 0 {
		t.Fatalf("no call to the approval gate was found in %s; either the gate has been renamed or "+
			"dual approval now guards nothing", strings.Join(gatedFiles, " and "))
	}
	if calls != len(out) {
		t.Fatalf("%d calls to the approval gate, %d of which name their operation as a literal; "+
			"an operation assembled at run time cannot be held to the list in internal/config, "+
			"so write it as a literal or extend this test", calls, len(out))
	}

	sort.Strings(out)
	return out
}
