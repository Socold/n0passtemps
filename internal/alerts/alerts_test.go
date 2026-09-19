package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Socold/n0passtemps/internal/store"
)

// fakeStore is an in-memory AlertStore that deduplicates by fingerprint the way
// the real implementations must, so a test can observe the occurrence count
// rising rather than a second row appearing.
type fakeStore struct {
	raised []*store.Alert
	byFP   map[string]*store.Alert
	err    error
}

func newFakeStore() *fakeStore {
	return &fakeStore{byFP: map[string]*store.Alert{}}
}

func (f *fakeStore) RaiseAlert(_ context.Context, a *store.Alert) (*store.Alert, error) {
	if f.err != nil {
		return nil, f.err
	}

	// The same preconditions both real backends check, refused the same way.
	// An earlier version of this double minted the identifier itself, and that
	// one convenience hid a defect in every test that used it: the engine built
	// its row without an identifier, so sqlite and postgresql refused every
	// alert the service ever raised, while these tests went green. A double
	// that supplies what the real thing demands does not stand in for it.
	if a.ID == "" || a.TenantID == "" {
		return nil, errors.New("fakeStore: alert requires an id and a tenant")
	}
	if a.AlertType == "" || a.Fingerprint == "" {
		return nil, errors.New("fakeStore: alert requires a type and a fingerprint")
	}

	f.raised = append(f.raised, a)
	if existing, ok := f.byFP[a.Fingerprint]; ok && existing.AcknowledgedAt == nil {
		existing.Occurrences++
		existing.LastSeenAt = a.LastSeenAt
		cp := *existing
		return &cp, nil
	}
	stored := *a
	f.byFP[a.Fingerprint] = &stored
	cp := stored
	return &cp, nil
}

func (f *fakeStore) ListAlerts(_ context.Context, _ string, _ store.AlertFilter) ([]*store.Alert, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*store.Alert, 0, len(f.byFP))
	for _, a := range f.byFP {
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeStore) AcknowledgeAlert(_ context.Context, _, id, by string, at time.Time) error {
	if f.err != nil {
		return f.err
	}
	for _, a := range f.byFP {
		if a.ID == id {
			t := at
			a.AcknowledgedAt = &t
			a.AcknowledgedBy = by
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeStore) CountOpenAlerts(_ context.Context, _ string) (map[store.Severity]int, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[store.Severity]int{}
	for _, a := range f.byFP {
		if a.AcknowledgedAt == nil {
			out[a.Severity]++
		}
	}
	return out, nil
}

// clock is a manually advanced time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// logBuffer collects log output so a test can assert that a failure was
// reported rather than swallowed.
type logBuffer struct{ sb strings.Builder }

func (b *logBuffer) Write(p []byte) (int, error) { return b.sb.Write(p) }
func (b *logBuffer) String() string              { return b.sb.String() }

func newEngine(t *testing.T) (*Engine, *fakeStore, *clock, *logBuffer) {
	t.Helper()
	c := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	s := newFakeStore()
	buf := &logBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return New(s, log, c.now), s, c, buf
}

const tenant = "tenant-1"

func TestEveryDeclaredTypeIsCounted(t *testing.T) {
	const want = 12
	if len(AllTypes) != want {
		t.Fatalf("AllTypes has %d entries, want %d", len(AllTypes), want)
	}
	if len(specs) != want {
		t.Fatalf("specs has %d entries, want %d", len(specs), want)
	}
	seen := map[Type]bool{}
	for _, ty := range AllTypes {
		if seen[ty] {
			t.Errorf("type %q appears twice in AllTypes", ty)
		}
		seen[ty] = true
		if _, ok := specs[ty]; !ok {
			t.Errorf("type %q has no spec", ty)
		}
	}
}

func TestEveryTypeHasAValidSeverityAndSummary(t *testing.T) {
	for _, ty := range AllTypes {
		if !ty.Valid() {
			t.Errorf("type %q reports itself invalid", ty)
		}
		switch ty.Severity() {
		case store.SeverityInfo, store.SeverityWarning, store.SeverityCritical:
		default:
			t.Errorf("type %q has severity %q, which is not one of the three levels", ty, ty.Severity())
		}
		if ty.Summary() == "" {
			t.Errorf("type %q has an empty summary", ty)
		}
		if ty.String() != string(ty) {
			t.Errorf("String() disagrees with the underlying value for %q", ty)
		}
	}
}

func TestChainBrokenIsCritical(t *testing.T) {
	if got := TypeAuditChainBroken.Severity(); got != store.SeverityCritical {
		t.Errorf("%s severity = %q, want %q", TypeAuditChainBroken, got, store.SeverityCritical)
	}
	// It is the only critical condition. Anything else joining that level
	// should be a deliberate decision rather than a copied constant.
	var critical []Type
	for _, ty := range AllTypes {
		if ty.Severity() == store.SeverityCritical {
			critical = append(critical, ty)
		}
	}
	if len(critical) != 1 || critical[0] != TypeAuditChainBroken {
		t.Errorf("critical types = %v, want only %s", critical, TypeAuditChainBroken)
	}
}

func TestUnknownTypeHasNoSeverity(t *testing.T) {
	unknown := Type("disk.full")
	if unknown.Valid() {
		t.Error("an undeclared type reports itself valid")
	}
	if got := unknown.Severity(); got != "" {
		t.Errorf("undeclared type severity = %q, want the empty severity", got)
	}
	if got := unknown.Summary(); got != "" {
		t.Errorf("undeclared type summary = %q, want empty", got)
	}
}

func TestFingerprintIsStableAcrossTimeAndDetail(t *testing.T) {
	e, _, c, _ := newEngine(t)

	first := Input{
		TenantID:  tenant,
		Type:      TypeAuthFailureSubject,
		SubjectID: "subject-1",
		Detail:    map[string]any{"failures": 3},
	}
	second := Input{
		TenantID:  tenant,
		Type:      TypeAuthFailureSubject,
		SubjectID: "subject-1",
		Detail:    map[string]any{"failures": 47, "note": "still going"},
		Summary:   "a completely different summary",
	}

	a := e.Fingerprint(first)
	c.add(72 * time.Hour)
	b := e.Fingerprint(second)
	if a != b {
		t.Errorf("fingerprint changed with the detail and the clock: %q then %q; every "+
			"occurrence would become a new row", a, b)
	}
	if len(a) != fingerprintHexLen {
		t.Errorf("fingerprint length = %d, want %d", len(a), fingerprintHexLen)
	}
}

func TestFingerprintDivergesAcrossSubjectsTypesAndTenants(t *testing.T) {
	e, _, _, _ := newEngine(t)

	base := Input{TenantID: tenant, Type: TypeAuthFailureSubject, SubjectID: "subject-1"}

	otherSubject := base
	otherSubject.SubjectID = "subject-2"
	if e.Fingerprint(base) == e.Fingerprint(otherSubject) {
		t.Error("two subjects share a fingerprint")
	}

	otherType := base
	otherType.Type = TypeRecoveryExhausted
	if e.Fingerprint(base) == e.Fingerprint(otherType) {
		t.Error("two conditions share a fingerprint")
	}

	otherTenant := base
	otherTenant.TenantID = "tenant-2"
	if e.Fingerprint(base) == e.Fingerprint(otherTenant) {
		t.Error("two tenants share a fingerprint")
	}

	// Two credentials of one subject are two conditions.
	credA := Input{TenantID: tenant, Type: TypeSignCountRegression, SubjectID: "subject-1", ResourceID: "cred-a"}
	credB := credA
	credB.ResourceID = "cred-b"
	if e.Fingerprint(credA) == e.Fingerprint(credB) {
		t.Error("two credentials of one subject share a fingerprint")
	}

	// Length prefixing keeps the field boundary fixed.
	left := Input{TenantID: tenant, Type: TypeSignCountRegression, SubjectID: "ab", ResourceID: ""}
	right := Input{TenantID: tenant, Type: TypeSignCountRegression, SubjectID: "a", ResourceID: "b"}
	if e.Fingerprint(left) == e.Fingerprint(right) {
		t.Error("identifier boundary is ambiguous")
	}
}

func TestRaiseStoresTheCondition(t *testing.T) {
	e, s, c, _ := newEngine(t)

	got, err := e.Raise(context.Background(), Input{
		TenantID:  tenant,
		Type:      TypeAuthFailureSubject,
		SubjectID: "subject-1",
		Detail:    map[string]any{"failures": 3},
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if got.AlertType != TypeAuthFailureSubject.String() {
		t.Errorf("alert type = %q, want %q", got.AlertType, TypeAuthFailureSubject)
	}
	if got.Severity != store.SeverityWarning {
		t.Errorf("severity = %q, want %q", got.Severity, store.SeverityWarning)
	}
	if got.Summary != TypeAuthFailureSubject.Summary() {
		t.Errorf("summary = %q, want the type default %q", got.Summary, TypeAuthFailureSubject.Summary())
	}
	if !got.FirstSeenAt.Equal(c.t) || !got.LastSeenAt.Equal(c.t) {
		t.Errorf("timestamps = %s and %s, want the injected clock %s", got.FirstSeenAt, got.LastSeenAt, c.t)
	}
	if got.Occurrences != 1 {
		t.Errorf("occurrences = %d, want 1", got.Occurrences)
	}

	var detail map[string]any
	if err := json.Unmarshal(s.raised[0].Detail, &detail); err != nil {
		t.Fatalf("detail is not valid JSON: %v", err)
	}
	if detail["failures"] != float64(3) {
		t.Errorf("detail = %v, want the failure count", detail)
	}
}

func TestRepeatedOccurrencesCollapseOntoOneRow(t *testing.T) {
	e, s, c, _ := newEngine(t)

	for i := 0; i < 5; i++ {
		c.add(time.Second)
		if _, err := e.AuthFailureBurst(context.Background(), tenant, "subject-1", i+1); err != nil {
			t.Fatalf("AuthFailureBurst: %v", err)
		}
	}
	if len(s.byFP) != 1 {
		t.Errorf("%d rows for one condition, want 1", len(s.byFP))
	}
	for _, a := range s.byFP {
		if a.Occurrences != 5 {
			t.Errorf("occurrences = %d, want 5", a.Occurrences)
		}
	}
}

func TestRaiseRejectsAnInvalidType(t *testing.T) {
	e, s, _, buf := newEngine(t)

	for _, ty := range []Type{"", "disk.full", Type(strings.ToUpper(string(TypeAuditChainBroken)))} {
		got, err := e.Raise(context.Background(), Input{TenantID: tenant, Type: ty})
		if err == nil {
			t.Errorf("Raise accepted the undeclared type %q", ty)
		}
		if got != nil {
			t.Errorf("Raise returned an alert for the undeclared type %q", ty)
		}
	}
	if len(s.raised) != 0 {
		t.Errorf("%d alerts reached the store, want 0", len(s.raised))
	}
	if !strings.Contains(buf.String(), "alert rejected") {
		t.Error("the rejection was not logged")
	}
}

func TestRaiseRequiresATenant(t *testing.T) {
	e, s, _, _ := newEngine(t)

	if _, err := e.Raise(context.Background(), Input{Type: TypeAuditChainBroken}); err == nil {
		t.Error("Raise accepted an alert with no tenant; its fingerprint would merge tenants")
	}
	if len(s.raised) != 0 {
		t.Errorf("%d alerts reached the store, want 0", len(s.raised))
	}
}

func TestStoreErrorIsReturnedAndLogged(t *testing.T) {
	e, s, _, buf := newEngine(t)
	sentinel := errors.New("alerts table is read only")
	s.err = sentinel

	got, err := e.AuditChainBroken(context.Background(), tenant, 4711)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap %v", err, sentinel)
	}
	if got != nil {
		t.Errorf("an alert was returned alongside the error: %+v", got)
	}
	if !strings.Contains(buf.String(), "alert could not be recorded") {
		t.Error("the store failure was not logged")
	}
}

func TestRaiseSurvivesANilLogger(t *testing.T) {
	// A caller that forgets the logger must still be able to raise: the
	// alternative is a panic on the authentication path.
	e := New(newFakeStore(), nil, nil)
	if _, err := e.AuditChainBroken(context.Background(), tenant, 1); err != nil {
		t.Fatalf("Raise with a default logger: %v", err)
	}
}

func TestUnencodableDetailDoesNotSuppressTheAlert(t *testing.T) {
	e, s, _, buf := newEngine(t)

	got, err := e.Raise(context.Background(), Input{
		TenantID:  tenant,
		Type:      TypeRecoveryExhausted,
		SubjectID: "subject-1",
		Detail:    map[string]any{"callback": func() {}},
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if got == nil {
		t.Fatal("the alert was dropped because its detail could not be encoded")
	}
	if len(s.raised) != 1 || s.raised[0].Detail != nil {
		t.Errorf("detail = %s, want none", s.raised[0].Detail)
	}
	if !strings.Contains(buf.String(), "alert detail could not be encoded") {
		t.Error("the dropped detail was not logged")
	}
}

func TestCriticalAlertsAreLoggedAtErrorLevel(t *testing.T) {
	e, _, _, buf := newEngine(t)

	if _, err := e.AuditChainBroken(context.Background(), tenant, 12); err != nil {
		t.Fatalf("AuditChainBroken: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("critical alert was not logged at error level: %s", out)
	}
	if !strings.Contains(out, "sequence 12") {
		t.Errorf("the log line does not carry the broken sequence: %s", out)
	}

	buf.sb.Reset()
	if _, err := e.RecoveryLow(context.Background(), tenant, "subject-1", 2, 3); err != nil {
		t.Fatalf("RecoveryLow: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "level=INFO") {
		t.Errorf("informational alert was not logged at info level: %s", out)
	}
}

// TestConvenienceMethodsCoverEveryType calls each of the ten and checks that
// the row it produces carries the right type, severity and a summary that says
// more than the default.
func TestConvenienceMethodsCoverEveryType(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		want Type
		call func(e *Engine) (*store.Alert, error)
	}{
		{TypeAuthFailureSubject, func(e *Engine) (*store.Alert, error) {
			return e.AuthFailureBurst(ctx, tenant, "subject-1", 11)
		}},
		{TypeAuthFailureIP, func(e *Engine) (*store.Alert, error) {
			return e.AuthFailureBurstFromNetwork(ctx, tenant, "2001:db8::/64", 51)
		}},
		{TypeSignCountRegression, func(e *Engine) (*store.Alert, error) {
			return e.SignCountRegression(ctx, tenant, "subject-1", "cred-1", 9, 9)
		}},
		{TypeBulkRevocation, func(e *Engine) (*store.Alert, error) {
			return e.BulkRevocation(ctx, tenant, "admin-1", 42, 10)
		}},
		{TypeRecoveryExhausted, func(e *Engine) (*store.Alert, error) {
			return e.RecoveryExhausted(ctx, tenant, "subject-1")
		}},
		{TypeRecoveryLow, func(e *Engine) (*store.Alert, error) {
			return e.RecoveryLow(ctx, tenant, "subject-1", 2, 3)
		}},
		{TypeAPIKeyRejected, func(e *Engine) (*store.Alert, error) {
			return e.APIKeyRejected(ctx, tenant, "AbCdEfGh", 30)
		}},
		{TypeAdminDenied, func(e *Engine) (*store.Alert, error) {
			return e.AdminDenied(ctx, tenant, "token-1", "kek.rotate")
		}},
		{TypeAuditChainBroken, func(e *Engine) (*store.Alert, error) {
			return e.AuditChainBroken(ctx, tenant, 900)
		}},
		{TypeKEKRotationOverdue, func(e *Engine) (*store.Alert, error) {
			return e.KEKRotationOverdue(ctx, tenant, "v3", 400*24*time.Hour, 365*24*time.Hour)
		}},
		{TypeRiskHigh, func(e *Engine) (*store.Alert, error) {
			return e.RiskHigh(ctx, tenant, "subject-1", 45,
				[]string{"recovery_code_used", "recent_failures_subject", "recent_failures_network"})
		}},
		{TypeTicketFactorOverride, func(e *Engine) (*store.Alert, error) {
			return e.TicketFactorOverride(ctx, tenant, "subject-1", "ticket-1", "key-1", 2, true)
		}},
	}

	if len(cases) != len(AllTypes) {
		t.Fatalf("%d convenience methods exercised, want %d", len(cases), len(AllTypes))
	}

	for _, tc := range cases {
		e, s, _, _ := newEngine(t)
		got, err := tc.call(e)
		if err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		if got.AlertType != tc.want.String() {
			t.Errorf("alert type = %q, want %q", got.AlertType, tc.want)
		}
		if got.Severity != tc.want.Severity() {
			t.Errorf("%s severity = %q, want %q", tc.want, got.Severity, tc.want.Severity())
		}
		if got.Summary == "" {
			t.Errorf("%s produced an empty summary", tc.want)
		}
		if got.Fingerprint == "" {
			t.Errorf("%s produced an empty fingerprint", tc.want)
		}
		if len(s.raised) != 1 {
			t.Errorf("%s reached the store %d times, want 1", tc.want, len(s.raised))
		}
	}
}

func TestDiscardLoggerIsAcceptable(t *testing.T) {
	// Guards against an accidental dependency on the logger being a real sink.
	e := New(newFakeStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if _, err := e.RecoveryExhausted(context.Background(), tenant, "subject-1"); err != nil {
		t.Fatalf("Raise: %v", err)
	}
}
