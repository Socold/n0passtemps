package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestDotSegmentSubjectReferenceCannotReachAnotherRoute checks what a subject
// reference made of dot segments addresses.
//
// Go's ServeMux resolves dot segments in a request path, and url.PathEscape
// leaves '.' alone, so a reference of "." or ".." is a request for a shorter
// path. A client that escapes its input correctly can therefore still address
// a route the caller did not name, and the concern is whether that lands
// somewhere authenticated and unexpected.
func TestDotSegmentSubjectReferenceCannotReachAnotherRoute(t *testing.T) {
	h := newHarness(t)

	for _, ref := range []string{".", "..", "%2e", "%2e%2e", "..%2f..", "a/../b"} {
		t.Run(ref, func(t *testing.T) {
			for _, tmpl := range []string{
				"/v1/subjects/REF",
				"/v1/totp/REF/verify",
				"/v1/recovery/REF/consume",
				"/v1/webauthn/REF/assert",
			} {
				path := strings.Replace(tmpl, "REF", ref, 1)
				res := h.do(http.MethodPost, path, h.apiKey, map[string]any{"code": "000000"})
				if res.Status == http.StatusOK || res.Status == http.StatusCreated {
					t.Errorf("POST %s succeeded (%d): a dot-segment reference reached a "+
						"route that acted on it; body: %s", path, res.Status, res.Raw)
				}
			}
		})
	}
}

// TestEncodedSlashInSubjectReferenceIsNotADirectorySeparator checks that a
// reference containing a slash is handled as one path segment.
//
// An application is free to use a reference like "tenant/user". If %2F were
// decoded before routing, that reference would address a different route, and
// two distinct users could collide onto one record.
func TestEncodedSlashInSubjectReferenceIsNotADirectorySeparator(t *testing.T) {
	h := newHarness(t)

	const ref = "team-a/alice"
	created := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": ref})
	if created.Status != http.StatusOK {
		t.Fatalf("creating a subject whose reference contains a slash = %d; body: %s",
			created.Status, created.Raw)
	}
	id := created.str(t, "subject_id")

	// Read it back through the path, escaped as a client library would.
	res := h.do(http.MethodGet, "/v1/subjects/team-a%2Falice", h.apiKey, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("reading it back through an escaped path = %d; body: %s", res.Status, res.Raw)
	}
	if got := res.str(t, "subject_id"); got != id {
		t.Errorf("the escaped path resolved to subject %s, want %s", got, id)
	}

	// A different reference that only looks similar must be a different
	// subject, not the same record reached by another spelling.
	other := h.do(http.MethodPost, "/v1/subjects", h.apiKey, map[string]any{"subject_ref": "team-a%2Falice"})
	if other.Status != http.StatusOK {
		t.Fatalf("second subject = %d; body: %s", other.Status, other.Raw)
	}
	if other.str(t, "subject_id") == id {
		t.Error("two different references collided onto one subject")
	}
}
