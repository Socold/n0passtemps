// Package metrics exposes counters and a latency histogram in the Prometheus
// text exposition format.
//
// # Why this is not client_golang
//
// The exposition format is a few dozen lines and this service publishes a
// handful of series. The reference client library brings a dependency tree an
// order of magnitude larger than what it is used for here, a global default
// registry that collects process and Go runtime metrics whether or not anyone
// asked, and an HTTP handler with its own opinions about compression and
// negotiation. internal/assertion makes the same argument about JWT libraries
// and for the same reason: a format this small is cheaper to write than to
// depend on, and what is written can be read.
//
// What is given up is real: exemplars, native histograms, the collector
// interface and the ability to hand a third-party library a registry to write
// into. If any of those is ever wanted, this package is small enough to throw
// away.
//
// # Cardinality
//
// A Prometheus series is created per distinct label combination and lives for
// as long as the process does. A label whose value comes from a request is
// therefore a memory leak with an attacker holding the pen, and a label whose
// value is a subject reference is a list of users in a system that is scraped,
// retained and shared more widely than the logs are.
//
// So: the route label is the matched pattern and never the path, the status is
// a code and never a message, and nothing here takes a value from a request
// body, a query string or a path segment. The method is the one argument a
// caller writes, since net/http accepts any token, so it is folded onto the
// standard set before it becomes a label; see methodLabel. ObserveRequest is
// the only entry point that a request reaches.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Buckets are the cumulative histogram boundaries for request latency, in
// seconds.
//
// They stop at ten seconds because the server's write timeout is fifteen by
// default, so anything slower is a timeout rather than a slow request and the
// +Inf bucket is where it belongs. The lower end is dense because the
// interesting question on an authentication path is what the fast majority
// costs, not how the tail is shaped: a ceremony that should take five
// milliseconds and takes eighty is the signal, and both fall in the gap of a
// coarser set.
var Buckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Registry holds every series this process publishes.
//
// It is safe for concurrent use. One mutex covers everything, which is the
// right trade at this volume: the map is written once per request and read once
// per scrape, and a sharded design would buy contention that does not exist.
type Registry struct {
	mu sync.Mutex

	counters map[string]*counter
	hists    map[string]*histogram

	// buildInfo is emitted as a gauge of 1 carrying the version labels, which
	// is the convention for identifying what is running.
	buildInfo labelSet
}

// counter is a monotonically increasing value for one label combination.
type counter struct {
	name   string
	help   string
	labels labelSet
	value  uint64
}

// histogram is a cumulative histogram for one label combination.
type histogram struct {
	name   string
	help   string
	labels labelSet
	counts []uint64
	sum    float64
	total  uint64
}

// labelSet is an ordered list of label pairs. It is a slice rather than a map
// so that the rendered order is stable, which makes a scrape diffable.
type labelSet []label

type label struct{ name, value string }

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		counters: make(map[string]*counter),
		hists:    make(map[string]*histogram),
	}
}

// SetBuildInfo records what is running. It is called once, at start.
func (r *Registry) SetBuildInfo(version, commit, goVersion string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buildInfo = labelSet{
		{"version", version},
		{"commit", commit},
		{"go_version", goVersion},
	}
}

// otherMethod is the label every method outside the standard set is folded
// into.
const otherMethod = "other"

// methodLabel maps a request method onto a closed set.
//
// net/http accepts any token as a method and the catch-all route answers all of
// them, so the method is a value a caller chooses. Used as a label unchanged it
// is a series per invented method, kept for the life of the process, from
// requests that need no credential.
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return method
	default:
		return otherMethod
	}
}

// ObserveRequest records one served request.
//
// route must be the matched pattern. Passing a concrete path here creates a
// series per distinct path, which on the ceremony routes means a series per
// user; see the package comment.
func (r *Registry) ObserveRequest(route, method string, status int, d time.Duration) {
	if r == nil {
		return
	}
	method = methodLabel(method)
	labels := labelSet{
		{"route", route},
		{"method", method},
		{"status", strconv.Itoa(status)},
	}
	r.addCounter("n0passtemps_http_requests_total",
		"Requests served, by route, method and response status.", labels, 1)

	// The duration carries no status: a histogram per status multiplies the
	// series count by the number of codes a route can answer, for a question
	// nobody asks of latency.
	r.observe("n0passtemps_http_request_duration_seconds",
		"Time to serve a request, in seconds.",
		labelSet{{"route", route}, {"method", method}}, d.Seconds())
}

// Inc adds one to a named counter.
//
// The names are the conditions MONITORING.md says to alert on, so that an
// operator who has a scrape does not also need a log query for them.
func (r *Registry) Inc(name, help string, labels ...string) {
	if r == nil {
		return
	}
	r.addCounter(name, help, pairs(labels), 1)
}

// pairs turns name, value, name, value into a label set. An odd trailing
// element is dropped rather than panicking: a metric is not worth a crash on
// the request path.
func pairs(kv []string) labelSet {
	out := make(labelSet, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, label{kv[i], kv[i+1]})
	}
	return out
}

func (r *Registry) addCounter(name, help string, labels labelSet, delta uint64) {
	key := seriesKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.counters[key]
	if !ok {
		c = &counter{name: name, help: help, labels: labels}
		r.counters[key] = c
	}
	c.value += delta
}

func (r *Registry) observe(name, help string, labels labelSet, v float64) {
	key := seriesKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hists[key]
	if !ok {
		h = &histogram{name: name, help: help, labels: labels, counts: make([]uint64, len(Buckets))}
		r.hists[key] = h
	}
	h.total++
	h.sum += v
	for i, b := range Buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

func seriesKey(name string, labels labelSet) string {
	var b strings.Builder
	b.WriteString(name)
	for _, l := range labels {
		b.WriteByte(0)
		b.WriteString(l.name)
		b.WriteByte(0)
		b.WriteString(l.value)
	}
	return b.String()
}

// WriteTo renders the registry in the Prometheus text exposition format,
// version 0.0.4.
//
// Series are sorted, and a HELP and TYPE line is emitted once per metric name
// rather than once per series, which is what the format requires.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	snapshot := r.render()
	r.mu.Unlock()

	n, err := io.WriteString(w, snapshot)
	return int64(n), err
}

// render builds the document. The caller holds the lock.
func (r *Registry) render() string {
	var b strings.Builder

	if len(r.buildInfo) > 0 {
		writeHeader(&b, "n0passtemps_build_info",
			"The version, revision and toolchain of the running binary.", "gauge")
		writeSample(&b, "n0passtemps_build_info", r.buildInfo, "1")
	}

	// Grouped by metric name so that HELP and TYPE appear once each, as the
	// format requires and as a strict parser enforces.
	byName := map[string][]*counter{}
	names := make([]string, 0, len(r.counters))
	for _, c := range r.counters {
		if _, seen := byName[c.name]; !seen {
			names = append(names, c.name)
		}
		byName[c.name] = append(byName[c.name], c)
	}
	sort.Strings(names)
	for _, name := range names {
		series := byName[name]
		writeHeader(&b, name, series[0].help, "counter")
		sort.Slice(series, func(i, j int) bool {
			return series[i].labels.String() < series[j].labels.String()
		})
		for _, c := range series {
			writeSample(&b, name, c.labels, strconv.FormatUint(c.value, 10))
		}
	}

	histByName := map[string][]*histogram{}
	histNames := make([]string, 0, len(r.hists))
	for _, h := range r.hists {
		if _, seen := histByName[h.name]; !seen {
			histNames = append(histNames, h.name)
		}
		histByName[h.name] = append(histByName[h.name], h)
	}
	sort.Strings(histNames)
	for _, name := range histNames {
		series := histByName[name]
		writeHeader(&b, name, series[0].help, "histogram")
		sort.Slice(series, func(i, j int) bool {
			return series[i].labels.String() < series[j].labels.String()
		})
		for _, h := range series {
			for i, bound := range Buckets {
				le := label{"le", strconv.FormatFloat(bound, 'g', -1, 64)}
				writeSample(&b, name+"_bucket", append(append(labelSet{}, h.labels...), le),
					strconv.FormatUint(h.counts[i], 10))
			}
			writeSample(&b, name+"_bucket", append(append(labelSet{}, h.labels...), label{"le", "+Inf"}),
				strconv.FormatUint(h.total, 10))
			writeSample(&b, name+"_sum", h.labels, strconv.FormatFloat(h.sum, 'g', -1, 64))
			writeSample(&b, name+"_count", h.labels, strconv.FormatUint(h.total, 10))
		}
	}

	return b.String()
}

func writeHeader(b *strings.Builder, name, help, typ string) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, escapeHelp(help))
	fmt.Fprintf(b, "# TYPE %s %s\n", name, typ)
}

func writeSample(b *strings.Builder, name string, labels labelSet, value string) {
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteString(labels.String())
	}
	b.WriteByte(' ')
	b.WriteString(value)
	b.WriteByte('\n')
}

// String renders a label set as the exposition format writes it.
func (l labelSet) String() string {
	if len(l) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, lb := range l {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(lb.name)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(lb.value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel escapes a label value per the exposition format: backslash,
// double quote and newline, and nothing else.
//
// A route pattern contains braces and a method contains neither, so in practice
// nothing here needs escaping today. It is done anyway, because the cost is a
// replacer and the cost of not doing it is a scrape that fails to parse the
// first time somebody mounts a route with a quote in it.
func escapeLabel(s string) string {
	return labelEscaper.Replace(s)
}

// escapeHelp escapes a HELP line: backslash and newline only. A quote is legal
// in help text.
func escapeHelp(s string) string {
	return helpEscaper.Replace(s)
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)
