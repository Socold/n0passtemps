package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Socold/n0passtemps/internal/logging"
)

// TestTheRouteFieldIsThePatternAndNotThePath is a privacy test as much as an
// aggregation one.
//
// RequestLog wraps the multiplexer from outside, and the multiplexer is what
// sets Request.Pattern, on the request it is handed. Reading the pattern while
// building the request-scoped logger therefore found nothing and fell back to
// the concrete path, which on the ceremony routes is the subject reference: the
// documentation asks for an opaque identifier and applications supply email
// addresses. Redaction covers subject_ref and has no reason to look at route,
// so the address travelled in the field next to the redacted one.
func TestTheRouteFieldIsThePatternAndNotThePath(t *testing.T) {
	const (
		pattern = "GET /v1/webauthn/assert/{subject_ref}"
		ref     = "someone@example.com"
	)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	mux := http.NewServeMux()
	mux.Handle(pattern, Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A handler line, written while the pattern is set.
		logging.FromContext(r.Context()).InfoContext(r.Context(), "handler")
		w.WriteHeader(http.StatusOK)
	}), RouteLabel()))

	h := Chain(mux, RequestLog(log))
	req := httptest.NewRequest(http.MethodGet, "/v1/webauthn/assert/"+ref, nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), ref) {
		t.Fatalf("the subject reference reached the log:\n%s", buf.String())
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected a handler line and a request line, got %d:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if got := entry[logging.KeyRoute]; got != pattern {
			t.Errorf("route = %v, want %q (line: %s)", got, pattern, line)
		}
	}
}

// TestTheRouteFieldFallsBackForAnUnmatchedRequest keeps the fallback honest: a
// request that matches no route has no pattern to report, and reporting the
// path there is what an operator needs to see what was asked for.
func TestTheRouteFieldFallsBackForAnUnmatchedRequest(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	h := Chain(http.NewServeMux(), RequestLog(log))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nothing/here", nil))

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if got := entry[logging.KeyRoute]; got != "/nothing/here" {
		t.Errorf("route = %v, want the path for an unmatched request", got)
	}
}
