package ui

import (
	"net"
	"strings"
	"testing"
)

// parseCIDRs and ipInAny are the whole of admin.ip_allow_list, which the
// validator now requires on any listener beyond loopback because /admin/v1 is
// served on the same port whether or not the console is enabled. They decide
// whether a request reaches the administrative surface at all, and they were
// reached only incidentally, through whichever address a test happened to use.

// TestParseCIDRsDropsWhatItCannotParse is the behaviour worth knowing about,
// because it is the one with a sharp edge.
//
// An entry that does not parse is skipped rather than reported, so a typo in
// the allow list silently narrows it. That is the safe direction: the result is
// an administrator locked out rather than a network let in. The validator
// refuses a malformed entry before it ever reaches here, which is where the
// operator is told.
func TestParseCIDRsDropsWhatItCannotParse(t *testing.T) {
	got := parseCIDRs([]string{
		"10.0.0.0/8",
		"not-a-cidr",
		"192.0.2.10", // an address without a prefix length
		"2001:db8::/32",
		"",
	})
	if len(got) != 2 {
		t.Fatalf("parsed %d networks, want 2: %v", len(got), got)
	}
	if got[0].String() != "10.0.0.0/8" {
		t.Errorf("first network = %s, want 10.0.0.0/8", got[0])
	}
	if got[1].String() != "2001:db8::/32" {
		t.Errorf("second network = %s, want 2001:db8::/32", got[1])
	}

	if n := parseCIDRs(nil); len(n) != 0 {
		t.Errorf("a nil list produced %d networks", len(n))
	}
}

// TestIpInAnyIsTheAllowList, across both families and at the boundaries.
func TestIpInAnyIsTheAllowList(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.0/8", "192.0.2.10/32", "2001:db8::/32"})

	for addr, want := range map[string]bool{
		"10.0.0.1":       true,
		"10.255.255.255": true,
		"9.255.255.255":  false,
		"11.0.0.1":       false,
		"192.0.2.10":     true,
		"192.0.2.11":     false,
		"2001:db8::1":    true,
		"2001:db9::1":    false,
		"127.0.0.1":      false,
	} {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("%q is not an address", addr)
			}
			if got := ipInAny(ip, nets); got != want {
				t.Errorf("ipInAny(%s) = %t, want %t", addr, got, want)
			}
		})
	}

	// An empty allow list admits nobody, which is what makes the setting a
	// list of who may rather than a list of who may not.
	if ipInAny(net.ParseIP("10.0.0.1"), nil) {
		t.Error("an empty allow list admitted an address")
	}
	// An unparseable address cannot be admitted by accident.
	if ipInAny(nil, nets) {
		t.Error("a nil address was admitted")
	}
}

// TestTruncateLabelCutsOnRunesNotBytes keeps a template from rendering a
// replacement character.
//
// The labels an operator gives a passkey are free text and reach a page, so a
// cut in the middle of a multi-byte character would produce invalid UTF-8 that
// the template escapes into a visible replacement character.
func TestTruncateLabelCutsOnRunesNotBytes(t *testing.T) {
	if got := truncateLabel("a yubikey"); got != "a yubikey" {
		t.Errorf("a short label was changed to %q", got)
	}

	// Each of these is several bytes and one rune, so a byte-wise cut would
	// land inside one of them.
	long := strings.Repeat("é", passkeyLabelMax+10)
	got := truncateLabel(long)
	if n := len([]rune(got)); n != passkeyLabelMax {
		t.Errorf("truncated to %d runes, want %d", n, passkeyLabelMax)
	}
	if !utf8Valid(got) {
		t.Error("truncation produced invalid UTF-8")
	}

	exact := strings.Repeat("x", passkeyLabelMax)
	if truncateLabel(exact) != exact {
		t.Error("a label of exactly the maximum length was truncated")
	}
}

// utf8Valid reports whether s is well-formed, without importing unicode/utf8
// for one call.
func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// TestOperationWordReadsAsEnglishForAnUnknownOperation keeps the approvals page
// readable when the API grows an operation this table has not learnt.
//
// The console prints the operation a queued approval names. A new operation
// added to the API but not to the table here has to read as words rather than
// as an identifier, because the person deciding the approval is reading it to
// decide whether to approve it.
func TestOperationWordReadsAsEnglishForAnUnknownOperation(t *testing.T) {
	got := operationWord("subject.credentials.revoke_all")
	if strings.Contains(got, ".") || strings.Contains(got, "_") {
		t.Errorf("an unmapped operation rendered as %q, which is an identifier", got)
	}
	if got != "subject credentials revoke all" {
		t.Errorf("operationWord = %q", got)
	}
	// A mapped operation keeps its written form.
	for v := range operationWords {
		if operationWord(v) != operationWords[v] {
			t.Errorf("the table entry for %q was not used", v)
		}
		break
	}
}
