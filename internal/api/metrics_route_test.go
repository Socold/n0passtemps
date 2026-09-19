package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetricsNeedsACredential keeps the endpoint off the unauthenticated
// surface. Request rates by route, the shape of the 401 and 429 curves and the
// version of the running binary are reconnaissance before they are diagnostics,
// which is the argument ADR 0008 makes about the health report.
func TestMetricsNeedsACredential(t *testing.T) {
	h := newHarness(t)

	if res := h.do(http.MethodGet, "/v1/metrics", "", nil); res.Status != http.StatusUnauthorized {
		t.Errorf("unauthenticated scrape = %d, want 401", res.Status)
	}
	if res := h.do(http.MethodGet, "/v1/metrics", h.apiKey, nil); res.Status != http.StatusOK {
		t.Fatalf("scrape with a key = %d, want 200", res.Status)
	}
}

// TestMetricsServesTheExpositionFormat checks what a scraper needs to see.
func TestMetricsServesTheExpositionFormat(t *testing.T) {
	h := newHarness(t)

	h.do(http.MethodGet, "/v1/health", "", nil)
	res := h.do(http.MethodGet, "/v1/metrics", h.apiKey, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q, want the 0.0.4 text format", ct)
	}

	body := res.Raw
	for _, want := range []string{
		"# TYPE n0passtemps_http_requests_total counter",
		"# TYPE n0passtemps_http_request_duration_seconds histogram",
		`n0passtemps_http_requests_total{route="GET /v1/health",method="GET",status="200"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// TestMetricsLabelsCarryNoSubjectReference is the reason the route label is the
// matched pattern.
//
// A Prometheus series lives as long as the process, so a label taken from a
// request is unbounded memory with a caller holding the pen; and on the routes
// that name a subject it would be a list of users, in a system that is scraped
// every fifteen seconds, retained for months and shared with whoever runs
// monitoring.
func TestMetricsLabelsCarryNoSubjectReference(t *testing.T) {
	h := newHarness(t)

	const ref = "someone@example.com"
	h.do(http.MethodGet, "/v1/subjects/"+ref, h.apiKey, nil)

	body := h.do(http.MethodGet, "/v1/metrics", h.apiKey, nil).Raw
	if strings.Contains(body, ref) {
		t.Fatalf("the subject reference reached a metric label:\n%s", body)
	}
	if !strings.Contains(body, `route="GET /v1/subjects/{subject_ref}"`) {
		t.Errorf("the route label is not the matched pattern:\n%s", body)
	}
}

// TestMetricsCountsRefusalsToo matters because the rate of 401 and 429 is the
// shape of an attack, and a middleware that only counted what reached a handler
// would miss exactly those.
func TestMetricsCountsRefusalsToo(t *testing.T) {
	h := newHarness(t)

	h.do(http.MethodGet, "/v1/health/detail", "", nil)

	body := h.do(http.MethodGet, "/v1/metrics", h.apiKey, nil).Raw
	if !strings.Contains(body, `route="GET /v1/health/detail",method="GET",status="401"`) {
		t.Errorf("a refused request was not counted:\n%s", body)
	}
}

// TestMetricsSaysSoWhenItIsNotConfigured. An empty document scrapes clean and
// reads as "nothing has happened", which a monitoring system believes until
// somebody checks.
func TestMetricsSaysSoWhenItIsNotConfigured(t *testing.T) {
	h := newHarness(t)

	// A server built the way a deployment without a registry builds one: every
	// other collaborator is the harness's, so the credential check still
	// passes and the handler is reached.
	srv := NewServer(Deps{
		Config: h.cfg, Store: h.store, Subjects: nil, Logger: discardLogger(),
		Recorder: nil, Clock: h.clock.now,
	})
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/metrics", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.apiKey)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no registry is wired in", res.StatusCode)
	}
}
