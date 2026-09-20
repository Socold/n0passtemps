package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// testNow is deliberately far in the future.
//
// checkDatabase takes its start time from the injected clock and then measures
// with time.Since, which reads the wall clock. With a fixed clock in the past
// the measured latency is years long and every report comes back degraded.
// A fixed clock ahead of the wall clock makes the measurement negative, which
// stays under the threshold, so these tests are deterministic without
// sleeping. See the report accompanying these tests.
var testNow = time.Date(2100, 1, 1, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return testNow }

// fakeStore embeds the interface so that only the four methods the checker
// uses need a body. Anything else panics on the nil embedded value, which is
// the right outcome if a health probe starts touching more of the store than
// it should.
type fakeStore struct {
	store.Store

	pingErr   error
	engine    string
	headSeq   int64
	headErr   error
	alerts    map[store.Severity]int
	alertsErr error

	alertsTenant string
}

func (f *fakeStore) Ping(context.Context) error { return f.pingErr }
func (f *fakeStore) Engine() string             { return f.engine }

func (f *fakeStore) ChainHead(context.Context) (int64, []byte, error) {
	return f.headSeq, nil, f.headErr
}

func (f *fakeStore) CountOpenAlerts(_ context.Context, tenantID string) (map[store.Severity]int, error) {
	f.alertsTenant = tenantID
	return f.alerts, f.alertsErr
}

type fakeKeyring struct {
	version  uint32
	key      []byte
	err      error
	versions []uint32
}

func (k *fakeKeyring) Current() (uint32, []byte, error) { return k.version, k.key, k.err }
func (k *fakeKeyring) Versions() []uint32               { return k.versions }

func healthyStore() *fakeStore {
	return &fakeStore{engine: "sqlite", headSeq: 42}
}

func healthyKeyring() *fakeKeyring {
	return &fakeKeyring{version: 3, key: []byte("0123456789abcdef0123456789abcdef"), versions: []uint32{2, 3}}
}

func baseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Tenant.ID = "tenant-a"
	cfg.Features.KEKRotationReminder = true
	cfg.KEK.RotationInterval = config.Duration{Duration: 90 * 24 * time.Hour}
	return cfg
}

func TestLiveness(t *testing.T) {
	tests := []struct {
		name    string
		pingErr error
		want    Status
	}{
		{"database reachable", nil, StatusOK},
		{"database unreachable", errors.New("connection refused"), StatusError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := healthyStore()
			st.pingErr = tc.pingErr
			c := New(baseConfig(), st, healthyKeyring(), testNow, fixedClock)

			if got := c.Liveness(context.Background()).Status; got != tc.want {
				t.Errorf("status = %q, want %q: a process that cannot reach its store must be taken out of rotation", got, tc.want)
			}
		})
	}

	t.Run("discloses exactly one field", func(t *testing.T) {
		// This report is served without authentication. Anything beyond the
		// status, such as a version, an engine or an error string, tells an
		// anonymous caller which advisories to look up.
		st := healthyStore()
		st.pingErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")
		c := New(baseConfig(), st, healthyKeyring(), testNow, fixedClock)

		for _, l := range []Liveness{c.Liveness(context.Background()), {Status: StatusOK}} {
			raw, err := json.Marshal(l)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(fields) != 1 {
				t.Errorf("unauthenticated liveness body has %d fields, want 1: %s", len(fields), raw)
			}
			if _, ok := fields["status"]; !ok {
				t.Errorf("unauthenticated liveness body has no status field: %s", raw)
			}
			if strings.Contains(string(raw), "10.0.0.5") {
				t.Errorf("the database address reached an unauthenticated caller: %s", raw)
			}
		}
	})
}

func TestReportHealthy(t *testing.T) {
	st := healthyStore()
	st.alerts = map[store.Severity]int{store.SeverityCritical: 2}
	kr := healthyKeyring()
	c := New(baseConfig(), st, kr, testNow.Add(-24*time.Hour), fixedClock)

	r := c.Report(context.Background())

	if r.Status != StatusOK {
		t.Errorf("status = %q, want ok (database %q, kek %q, audit %q)", r.Status, r.Database.Status, r.KEK.Status, r.Audit.Status)
	}
	if r.Database.Engine != "sqlite" {
		t.Errorf("engine = %q", r.Database.Engine)
	}
	if r.KEK.CurrentVersion != 3 || r.KEK.RetainedVersions != 2 || r.KEK.RotationOverdue {
		t.Errorf("kek = %+v", r.KEK)
	}
	if r.Audit.HeadSeq != 42 {
		t.Errorf("audit head = %d, want 42", r.Audit.HeadSeq)
	}
	if !r.Timestamp.Equal(testNow) {
		t.Errorf("timestamp = %v, want the injected clock", r.Timestamp)
	}
	if r.LastError != "" {
		t.Errorf("last_error = %q on a checker that has seen none", r.LastError)
	}

	if st.alertsTenant != "tenant-a" {
		t.Errorf("alerts were counted for tenant %q, want tenant-a", st.alertsTenant)
	}
	// All three severities are always present so a dashboard can tell "none
	// open" from "not reported".
	want := map[string]int{"info": 0, "warning": 0, "critical": 2}
	for sev, n := range want {
		if got, ok := r.Alerts[sev]; !ok || got != n {
			t.Errorf("open_alerts[%s] = %d (present %v), want %d", sev, got, ok, n)
		}
	}

	// The checker only needs to know the key can be fetched. Holding a copy
	// of it in a health report's working memory serves nothing.
	for _, b := range kr.key {
		if b != 0 {
			t.Error("the key material fetched for the health check was not wiped")
			break
		}
	}

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"tls"`) {
		t.Errorf("a tls section is present although no certificate is configured: %s", raw)
	}
	if strings.Contains(string(raw), "0123456789abcdef") {
		t.Error("key material reached the report")
	}
}

func TestReportWorstStatus(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name   string
		mutate func(st *fakeStore, kr *fakeKeyring, c *checkerArgs)
		want   Status
	}{
		{"everything ok", func(*fakeStore, *fakeKeyring, *checkerArgs) {}, StatusOK},
		{"database down", func(st *fakeStore, _ *fakeKeyring, _ *checkerArgs) { st.pingErr = boom }, StatusError},
		{"audit head unreadable", func(st *fakeStore, _ *fakeKeyring, _ *checkerArgs) { st.headErr = boom }, StatusError},
		{"current key unavailable", func(_ *fakeStore, kr *fakeKeyring, _ *checkerArgs) { kr.err = boom }, StatusError},
		{"no keyring", func(_ *fakeStore, _ *fakeKeyring, a *checkerArgs) { a.noKeyring = true }, StatusError},
		{"rotation overdue", func(_ *fakeStore, _ *fakeKeyring, a *checkerArgs) {
			a.rotatedAt = testNow.Add(-91 * 24 * time.Hour)
		}, StatusDegraded},
		// An error must not be masked by a later, milder finding.
		{"rotation overdue and database down", func(st *fakeStore, _ *fakeKeyring, a *checkerArgs) {
			a.rotatedAt = testNow.Add(-91 * 24 * time.Hour)
			st.pingErr = boom
		}, StatusError},
		{"rotation overdue and audit unreadable", func(st *fakeStore, _ *fakeKeyring, a *checkerArgs) {
			a.rotatedAt = testNow.Add(-91 * 24 * time.Hour)
			st.headErr = boom
		}, StatusError},
		// Alert counts are informational. A failure to read them must not
		// take a working authenticator out of service.
		{"alert count unreadable", func(st *fakeStore, _ *fakeKeyring, _ *checkerArgs) { st.alertsErr = boom }, StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, kr := healthyStore(), healthyKeyring()
			args := &checkerArgs{rotatedAt: testNow.Add(-24 * time.Hour)}
			tc.mutate(st, kr, args)

			var inspector KeyringInspector = kr
			if args.noKeyring {
				inspector = nil
			}
			r := New(baseConfig(), st, inspector, args.rotatedAt, fixedClock).Report(context.Background())

			if r.Status != tc.want {
				t.Errorf("status = %q, want %q (database %q, kek %q, audit %q): the overall verdict must be the worst component",
					r.Status, tc.want, r.Database.Status, r.KEK.Status, r.Audit.Status)
			}
		})
	}
}

type checkerArgs struct {
	rotatedAt time.Time
	noKeyring bool
}

func TestWorst(t *testing.T) {
	tests := []struct {
		name string
		in   []Status
		want Status
	}{
		{"none", nil, StatusOK},
		{"all ok", []Status{StatusOK, StatusOK}, StatusOK},
		{"one degraded", []Status{StatusOK, StatusDegraded, StatusOK}, StatusDegraded},
		{"error before degraded", []Status{StatusError, StatusDegraded}, StatusError},
		{"error after degraded", []Status{StatusDegraded, StatusOK, StatusError}, StatusError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := worst(tc.in...); got != tc.want {
				t.Errorf("worst(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestKEKRotationReminder(t *testing.T) {
	interval := 90 * 24 * time.Hour

	tests := []struct {
		name        string
		reminder    bool
		interval    time.Duration
		rotatedAt   time.Time
		wantOverdue bool
		wantStatus  Status
	}{
		{"overdue with the reminder on", true, interval, testNow.Add(-interval - time.Hour), true, StatusDegraded},
		// The operator switched the reminder off. Reporting degraded anyway
		// would page them for a policy they have declined.
		{"overdue with the reminder off", false, interval, testNow.Add(-interval - time.Hour), false, StatusOK},
		{"within the interval", true, interval, testNow.Add(-interval + time.Hour), false, StatusOK},
		{"exactly at the interval", true, interval, testNow.Add(-interval), false, StatusOK},
		{"no interval configured", true, 0, testNow.Add(-10 * interval), false, StatusOK},
		{"rotation time unknown", true, interval, time.Time{}, false, StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Features.KEKRotationReminder = tc.reminder
			cfg.KEK.RotationInterval = config.Duration{Duration: tc.interval}

			r := New(cfg, healthyStore(), healthyKeyring(), tc.rotatedAt, fixedClock).Report(context.Background())

			if r.KEK.RotationOverdue != tc.wantOverdue {
				t.Errorf("rotation_overdue = %v, want %v", r.KEK.RotationOverdue, tc.wantOverdue)
			}
			if r.KEK.Status != tc.wantStatus || r.Status != tc.wantStatus {
				t.Errorf("kek status = %q, overall = %q, want %q", r.KEK.Status, r.Status, tc.wantStatus)
			}
			if tc.wantOverdue && r.KEK.Detail == "" {
				t.Error("an overdue rotation carries no detail, so the operator is not told what to do")
			}
			if r.Features["kek_rotation_reminder"] != tc.reminder {
				t.Errorf("features[kek_rotation_reminder] = %v, want %v", r.Features["kek_rotation_reminder"], tc.reminder)
			}
		})
	}
}

// writeCert creates a self-signed certificate valid until notAfter and
// returns the path of its PEM file.
func writeCert(t *testing.T, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "auth.example.test"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"auth.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	return path
}

func TestTLS(t *testing.T) {
	t.Run("absent without a certificate", func(t *testing.T) {
		// TLS is terminated upstream, and this service cannot see that
		// certificate. Saying ok would be a claim about something unknown.
		r := New(baseConfig(), healthyStore(), healthyKeyring(), testNow, fixedClock).Report(context.Background())
		if r.TLS != nil {
			t.Errorf("tls = %+v, want nil", r.TLS)
		}
		if r.Status != StatusOK {
			t.Errorf("status = %q: an absent tls section must not count against the verdict", r.Status)
		}
	})

	day := 24 * time.Hour
	tests := []struct {
		name       string
		notAfter   time.Time
		wantStatus Status
		wantDays   int
	}{
		{"valid for sixty days", testNow.Add(60 * day), StatusOK, 60},
		{"valid for fifteen days", testNow.Add(15*day + time.Hour), StatusOK, 15},
		// Fourteen days sits outside an ACME client's renewal window, so
		// reaching it means automated renewal has stopped.
		{"fourteen days left", testNow.Add(14*day + time.Hour), StatusDegraded, 14},
		{"one day left", testNow.Add(day + time.Hour), StatusDegraded, 1},
		{"expires within the hour", testNow.Add(30 * time.Minute), StatusDegraded, 0},
		{"expired an hour ago", testNow.Add(-time.Hour), StatusError, 0},
		{"expired last month", testNow.Add(-30 * day), StatusError, -30},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Server.TLSCertFile = writeCert(t, tc.notAfter)

			r := New(cfg, healthyStore(), healthyKeyring(), testNow, fixedClock).Report(context.Background())

			if r.TLS == nil {
				t.Fatal("tls section is missing although a certificate is configured")
			}
			if r.TLS.Status != tc.wantStatus {
				t.Errorf("tls status = %q, want %q: clients are refused the moment the certificate lapses, so the warning has to come first", r.TLS.Status, tc.wantStatus)
			}
			if r.Status != tc.wantStatus {
				t.Errorf("overall status = %q, want %q: the certificate must feed the overall verdict", r.Status, tc.wantStatus)
			}
			if r.TLS.ExpiresInDays != tc.wantDays {
				t.Errorf("expires_in_days = %d, want %d", r.TLS.ExpiresInDays, tc.wantDays)
			}
			// X.509 times carry whole seconds.
			if !r.TLS.NotAfter.Equal(tc.notAfter.Truncate(time.Second)) {
				t.Errorf("not_after = %v, want %v", r.TLS.NotAfter, tc.notAfter)
			}
			if r.TLS.Subject != "auth.example.test" {
				t.Errorf("subject = %q", r.TLS.Subject)
			}
			if tc.wantStatus != StatusOK && r.TLS.Detail == "" {
				t.Error("a certificate problem carries no detail")
			}
		})
	}

	t.Run("unreadable file", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Server.TLSCertFile = filepath.Join(t.TempDir(), "missing.pem")
		r := New(cfg, healthyStore(), healthyKeyring(), testNow, fixedClock).Report(context.Background())
		if r.TLS == nil || r.TLS.Status != StatusError {
			t.Fatalf("tls = %+v, want an error status", r.TLS)
		}
		if strings.Contains(r.TLS.Detail, cfg.Server.TLSCertFile) {
			t.Errorf("the detail discloses a filesystem path: %q", r.TLS.Detail)
		}
	})

	t.Run("file without a certificate block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := baseConfig()
		cfg.Server.TLSCertFile = path
		r := New(cfg, healthyStore(), healthyKeyring(), testNow, fixedClock).Report(context.Background())
		if r.TLS == nil || r.TLS.Status != StatusError {
			t.Fatalf("tls = %+v, want an error status", r.TLS)
		}
	})

	t.Run("renewal is seen without a restart", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Server.TLSCertFile = writeCert(t, testNow.Add(2*day))
		c := New(cfg, healthyStore(), healthyKeyring(), testNow, fixedClock)

		if got := c.Report(context.Background()).TLS.Status; got != StatusDegraded {
			t.Fatalf("before renewal: tls status = %q, want degraded", got)
		}

		renewed, err := os.ReadFile(writeCert(t, testNow.Add(80*day)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.Server.TLSCertFile, renewed, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := c.Report(context.Background()).TLS.Status; got != StatusOK {
			t.Errorf("after renewal: tls status = %q, want ok: the file must be re-read on every report", got)
		}
	})
}

func TestNoteError(t *testing.T) {
	c := New(baseConfig(), healthyStore(), healthyKeyring(), testNow, fixedClock)

	c.NoteError("janitor", nil)
	if got := c.Report(context.Background()).LastError; got != "" {
		t.Errorf("last_error = %q after a nil error", got)
	}

	c.NoteError("janitor", errors.New("sweep timed out"))
	if got := c.Report(context.Background()).LastError; got != "janitor: sweep timed out" {
		t.Errorf("last_error = %q, want the component and its reason", got)
	}

	c.NoteError("alerts", errors.New("webhook refused"))
	c.NoteError("alerts", nil)
	r := c.Report(context.Background())
	if r.LastError != "alerts: webhook refused" {
		t.Errorf("last_error = %q, want the most recent failure; a nil must not erase it", r.LastError)
	}

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"last_error":"alerts: webhook refused"`) {
		t.Errorf("last_error is missing from the serialised report: %s", raw)
	}

	// A noted error is context for the operator, not a verdict.
	if r.Status != StatusOK {
		t.Errorf("status = %q: a noted error alone must not change the verdict", r.Status)
	}
}

func TestNoteErrorConcurrent(t *testing.T) {
	// NoteError is called from request handlers and the janitor while the
	// report is being built. Run under -race.
	c := New(baseConfig(), healthyStore(), healthyKeyring(), testNow, fixedClock)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			c.NoteError("writer", errors.New("x"))
		}
	}()
	for i := 0; i < 50; i++ {
		_ = c.Report(context.Background())
	}
	<-done
}

func TestUptime(t *testing.T) {
	now := testNow
	c := New(baseConfig(), healthyStore(), healthyKeyring(), testNow, func() time.Time { return now })
	now = now.Add(90 * time.Second)
	if got := c.Report(context.Background()).UptimeSeconds; got != 90 {
		t.Errorf("uptime_seconds = %d, want 90", got)
	}
}

// TestAuditSinkIsAbsentWithNoSinkConfigured mirrors the TLS block's reasoning:
// with nothing configured there is nothing to be healthy about, and a green
// field would suggest a witness that does not exist.
func TestAuditSinkIsAbsentWithNoSinkConfigured(t *testing.T) {
	c := New(baseConfig(), healthyStore(), healthyKeyring(), testNow, fixedClock)

	r := c.Report(context.Background())
	if r.AuditSink != nil {
		t.Fatalf("a report with no sink configured carries %+v", r.AuditSink)
	}
	if r.Status != StatusOK {
		t.Errorf("status = %q, want ok", r.Status)
	}
}

func TestAuditSinkReportsHowFarBehindDeliveryIs(t *testing.T) {
	st := healthyStore()
	st.headSeq = 42
	c := New(baseConfig(), st, healthyKeyring(), testNow, fixedClock)
	c.SetAuditSinkProbe("https://witness.example.org/audit", func() (int64, int64, string) {
		return 40, 0, ""
	})

	r := c.Report(context.Background())
	if r.AuditSink == nil {
		t.Fatal("the report carries no audit sink block although a probe is wired in")
	}
	if r.AuditSink.PendingEntries != 2 {
		t.Errorf("pending_entries = %d, want 2", r.AuditSink.PendingEntries)
	}

	// Being a couple of entries behind is the normal state of a sink that
	// flushes on an interval, so it must not degrade the whole report.
	if r.AuditSink.Status != StatusOK || r.Status != StatusOK {
		t.Errorf("a sink two entries behind reported %q and %q, want ok",
			r.AuditSink.Status, r.Status)
	}
}

func TestAFailingAuditSinkDegradesTheReport(t *testing.T) {
	st := healthyStore()
	st.headSeq = 100
	c := New(baseConfig(), st, healthyKeyring(), testNow, fixedClock)
	c.SetAuditSinkProbe("https://witness.example.org/audit", func() (int64, int64, string) {
		return 10, 7, "auditsink: the receiver did not accept the batch: 503 Service Unavailable"
	})

	// Degraded rather than error: the service still authenticates users, and
	// the audit log is still intact. What has lapsed is the copy held where the
	// operator cannot rewrite it, which is a thing to be told about and not a
	// reason to take the service out of rotation.
	r := c.Report(context.Background())
	if r.Status != StatusDegraded {
		t.Errorf("overall status = %q, want degraded", r.Status)
	}
	if r.AuditSink.Status != StatusDegraded {
		t.Errorf("audit sink status = %q, want degraded", r.AuditSink.Status)
	}
	if r.AuditSink.DroppedOffers != 7 {
		t.Errorf("dropped_offers = %d, want 7", r.AuditSink.DroppedOffers)
	}
	if !strings.Contains(r.AuditSink.Detail, "503") {
		t.Errorf("detail does not carry the reason: %q", r.AuditSink.Detail)
	}
	if r.AuditSink.Endpoint != "https://witness.example.org/audit" {
		t.Errorf("endpoint = %q", r.AuditSink.Endpoint)
	}
}
