package metrics

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

// TestTheDocumentParsesAsTheFormatDescribes checks the shape a scraper insists
// on: one HELP and one TYPE per metric name, whatever the number of series, and
// every sample line naming a metric that was declared.
func TestTheDocumentParsesAsTheFormatDescribes(t *testing.T) {
	r := New()
	r.SetBuildInfo("1.2.0", "abc123", "go1.27.1")
	r.ObserveRequest("GET /v1/health", "GET", 200, 3*time.Millisecond)
	r.ObserveRequest("GET /v1/health", "GET", 200, 7*time.Millisecond)
	r.ObserveRequest("POST /v1/subjects", "POST", 401, 2*time.Millisecond)
	r.Inc("n0passtemps_throttle_trips_total", "Throttle lockouts.", "dimension", "subject")

	doc := render(t, r)

	helps := map[string]int{}
	types := map[string]int{}
	declared := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(doc), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name := strings.Fields(line)[2]
			helps[name]++
			declared[name] = true
		case strings.HasPrefix(line, "# TYPE "):
			types[strings.Fields(line)[2]]++
		case line == "":
		default:
			name, _, _ := strings.Cut(line, "{")
			name, _, _ = strings.Cut(name, " ")
			base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(
				name, "_bucket"), "_sum"), "_count")
			if !declared[base] {
				t.Errorf("sample %q names a metric with no HELP line", name)
			}
		}
	}
	for name, n := range helps {
		if n != 1 {
			t.Errorf("%s has %d HELP lines, want 1", name, n)
		}
		if types[name] != 1 {
			t.Errorf("%s has %d TYPE lines, want 1", name, types[name])
		}
	}
	if len(helps) != 4 {
		t.Errorf("declared %d metrics, want 4: %v", len(helps), helps)
	}
}

// TestCountersAccumulatePerLabelCombination is the behaviour the whole thing
// rests on.
func TestCountersAccumulatePerLabelCombination(t *testing.T) {
	r := New()
	for range 3 {
		r.ObserveRequest("GET /v1/health", "GET", 200, time.Millisecond)
	}
	r.ObserveRequest("GET /v1/health", "GET", 503, time.Millisecond)

	doc := render(t, r)
	want := []string{
		`n0passtemps_http_requests_total{route="GET /v1/health",method="GET",status="200"} 3`,
		`n0passtemps_http_requests_total{route="GET /v1/health",method="GET",status="503"} 1`,
	}
	for _, w := range want {
		if !strings.Contains(doc, w) {
			t.Errorf("missing:\n  %s\ngot:\n%s", w, doc)
		}
	}
}

// TestTheHistogramIsCumulative pins the property a Prometheus histogram has and
// a naive one does not: each bucket counts everything at or below its bound,
// and +Inf equals the count.
func TestTheHistogramIsCumulative(t *testing.T) {
	r := New()
	// 2ms, 30ms and 3s: one in the third bucket, one in the sixth, one near the
	// top.
	for _, d := range []time.Duration{2 * time.Millisecond, 30 * time.Millisecond, 3 * time.Second} {
		r.ObserveRequest("GET /v1/health", "GET", 200, d)
	}
	doc := render(t, r)

	cases := map[string]string{
		`le="0.001"`:  "0",
		`le="0.0025"`: "1",
		`le="0.025"`:  "1",
		`le="0.05"`:   "2",
		`le="2.5"`:    "2",
		`le="5"`:      "3",
		`le="+Inf"`:   "3",
	}
	for le, want := range cases {
		line := findBucket(t, doc, le)
		if !strings.HasSuffix(line, " "+want) {
			t.Errorf("bucket %s = %q, want it to end in %q", le, line, want)
		}
	}
	if !strings.Contains(doc, `n0passtemps_http_request_duration_seconds_count{route="GET /v1/health",method="GET"} 3`) {
		t.Errorf("count is wrong:\n%s", doc)
	}
}

func findBucket(t *testing.T, doc, le string) string {
	t.Helper()
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "n0passtemps_http_request_duration_seconds_bucket{") &&
			strings.Contains(line, le+"}") {
			return line
		}
	}
	t.Fatalf("no bucket %s in:\n%s", le, doc)
	return ""
}

// TestTheDurationHistogramCarriesNoStatus keeps the series count down: a
// histogram per status multiplies the series by the number of codes a route can
// answer, for a question nobody asks of latency.
func TestTheDurationHistogramCarriesNoStatus(t *testing.T) {
	r := New()
	r.ObserveRequest("GET /v1/health", "GET", 200, time.Millisecond)
	r.ObserveRequest("GET /v1/health", "GET", 503, time.Millisecond)

	doc := render(t, r)
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "n0passtemps_http_request_duration_seconds") &&
			strings.Contains(line, "status=") {
			t.Errorf("the duration histogram carries a status label: %s", line)
		}
	}
	if !strings.Contains(doc, `n0passtemps_http_request_duration_seconds_count{route="GET /v1/health",method="GET"} 2`) {
		t.Errorf("the two requests are not in one series:\n%s", doc)
	}
}

// TestTheDocumentIsStable matters because a scrape that reorders itself is one
// nobody can diff by hand while working out what changed.
func TestTheDocumentIsStable(t *testing.T) {
	build := func() string {
		r := New()
		r.SetBuildInfo("1.2.0", "abc", "go1.27.1")
		for _, route := range []string{"POST /v1/subjects", "GET /v1/health", "GET /v1/jwks.json"} {
			r.ObserveRequest(route, "GET", 200, time.Millisecond)
			r.ObserveRequest(route, "GET", 404, time.Millisecond)
		}
		return render(t, r)
	}
	if a, b := build(), build(); a != b {
		t.Errorf("two identical registries rendered differently:\n%s\n---\n%s", a, b)
	}
}

// TestLabelValuesAreEscaped is a format test rather than a security one: an
// unescaped quote produces a document a scraper rejects wholesale, so one odd
// route would cost every other series.
func TestLabelValuesAreEscaped(t *testing.T) {
	r := New()
	r.ObserveRequest(`GET /v1/"odd"\route`, "GET", 200, time.Millisecond)
	doc := render(t, r)
	if !strings.Contains(doc, `route="GET /v1/\"odd\"\\route"`) {
		t.Errorf("label value is not escaped:\n%s", doc)
	}
}

// TestANilRegistryIsInert lets a caller hold one without checking, which is
// what keeps the request path free of a branch per metric.
//
// It has no assertion because a nil dereference is what fails it, which is why
// the parameter is unused.
func TestANilRegistryIsInert(_ *testing.T) {
	var r *Registry
	r.SetBuildInfo("1", "2", "3")
	r.ObserveRequest("GET /v1/health", "GET", 200, time.Millisecond)
	r.Inc("x", "y")
}

// TestIncDropsAnOddLabel pins the choice not to panic on the request path.
func TestIncDropsAnOddLabel(t *testing.T) {
	r := New()
	r.Inc("n0passtemps_test_total", "help", "a", "1", "dangling")
	doc := render(t, r)
	if !strings.Contains(doc, `n0passtemps_test_total{a="1"} 1`) {
		t.Errorf("odd trailing label was not dropped cleanly:\n%s", doc)
	}
}

// TestAnInventedMethodDoesNotBecomeASeries holds the cardinality bound on the
// one label a caller writes. net/http accepts any token as a method and the
// catch-all route answers all of them without a credential, so a method used
// as a label unchanged is a series per request for whoever wants one.
func TestAnInventedMethodDoesNotBecomeASeries(t *testing.T) {
	r := New()
	for i := range 500 {
		r.ObserveRequest("/", "M"+strconv.Itoa(i), 404, time.Millisecond)
	}

	doc := render(t, r)
	if strings.Contains(doc, `method="M`) {
		t.Fatalf("an invented method became a label:\n%s", doc)
	}
	want := `n0passtemps_http_requests_total{route="/",method="other",status="404"} 500`
	if !strings.Contains(doc, want) {
		t.Errorf("missing %q in:\n%s", want, doc)
	}
}
