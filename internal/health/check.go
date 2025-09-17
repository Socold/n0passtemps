// Package health reports whether the service is able to do its job.
//
// There are two reports, and the split is deliberate. The unauthenticated one
// answers a single question, is this process alive, because that is all a
// container runtime or a load balancer needs in order to decide whether to keep
// sending traffic. The detailed one, which names the version, the state of the
// key encryption keyring, whether rotation is overdue and when the TLS
// certificate expires, sits behind authentication: handed to an unauthenticated
// caller that is a list of the software to look up advisories for and a
// statement of which maintenance has been neglected. See docs/adr/0008.
package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/version"
)

// Status is the overall verdict.
type Status string

const (
	// StatusOK means every check passed.
	StatusOK Status = "ok"

	// StatusDegraded means the service still authenticates users but
	// something needs attention, such as an overdue key rotation or a
	// certificate nearing expiry.
	StatusDegraded Status = "degraded"

	// StatusError means the service cannot authenticate users, which in
	// practice means the database is unreachable.
	StatusError Status = "error"
)

// Liveness is the unauthenticated report.
//
// It carries no version and no component detail on purpose.
type Liveness struct {
	Status Status `json:"status"`
}

// Report is the authenticated report.
type Report struct {
	Status        Status          `json:"status"`
	Version       version.Info    `json:"version"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	Database      DatabaseHealth  `json:"database"`
	KEK           KEKHealth       `json:"kek"`
	TLS           *TLSHealth      `json:"tls,omitempty"`
	Audit         AuditHealth     `json:"audit"`
	Alerts        map[string]int  `json:"open_alerts"`
	Features      map[string]bool `json:"features"`
	Timestamp     time.Time       `json:"timestamp"`

	// LastError carries the most recent component failure, for the operator
	// who has only this response to work from. It is a component name and a
	// short reason, never a stack trace or a query.
	LastError string `json:"last_error,omitempty"`
}

// DatabaseHealth describes the store.
type DatabaseHealth struct {
	Status    Status `json:"status"`
	Engine    string `json:"engine"`
	LatencyMS int64  `json:"latency_ms"`
	Detail    string `json:"detail,omitempty"`
}

// KEKHealth describes the keyring.
type KEKHealth struct {
	Status Status `json:"status"`

	// CurrentVersion is the key version new secrets are sealed under.
	CurrentVersion uint32 `json:"current_version"`

	// RetainedVersions is how many versions are still available to decrypt
	// older records. A count above one means a rotation is in progress or was
	// never finished.
	RetainedVersions int `json:"retained_versions"`

	RotationOverdue bool   `json:"rotation_overdue"`
	Detail          string `json:"detail,omitempty"`
}

// TLSHealth describes the certificate, when TLS is terminated in process.
type TLSHealth struct {
	Status        Status    `json:"status"`
	NotAfter      time.Time `json:"not_after"`
	ExpiresInDays int       `json:"expires_in_days"`
	Subject       string    `json:"subject,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}

// AuditHealth describes the append-only log.
type AuditHealth struct {
	Status  Status `json:"status"`
	HeadSeq int64  `json:"head_seq"`
	Detail  string `json:"detail,omitempty"`
}

// KeyringInspector is the part of the keyring the health check needs.
//
// It is an interface so that the check does not depend on which provider is
// configured, and so a test can supply an overdue keyring without a file.
type KeyringInspector interface {
	Current() (version uint32, key []byte, err error)
	Versions() []uint32
}

// Checker builds the reports.
type Checker struct {
	store   store.Store
	keyring KeyringInspector
	cfg     *config.Config
	start   time.Time
	now     func() time.Time

	mu           sync.RWMutex
	lastError    string
	kekRotatedAt time.Time
}

// New builds a Checker.
//
// kekRotatedAt is when the current key version became current. It is supplied
// rather than derived because the keyring file records no history; an operator
// who rotates without updating it will see rotation reported as overdue, which
// is the safe direction to be wrong in.
func New(cfg *config.Config, st store.Store, keyring KeyringInspector, kekRotatedAt time.Time, clock func() time.Time) *Checker {
	if clock == nil {
		clock = time.Now
	}
	return &Checker{
		store:        st,
		keyring:      keyring,
		cfg:          cfg,
		start:        clock(),
		now:          clock,
		kekRotatedAt: kekRotatedAt,
	}
}

// NoteError records a component failure for the detailed report.
func (c *Checker) NoteError(component string, err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = component + ": " + err.Error()
}

// Liveness answers the unauthenticated probe.
//
// It touches the database, because a process that is running but cannot reach
// its store is not able to authenticate anyone and should be taken out of
// rotation. The timeout is short: a probe that hangs is worse than one that
// fails, since an orchestrator waiting on it will eventually kill the process
// anyway, and it would do so without the useful signal.
func (c *Checker) Liveness(ctx context.Context) Liveness {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := c.store.Ping(ctx); err != nil {
		return Liveness{Status: StatusError}
	}
	return Liveness{Status: StatusOK}
}

// Report builds the authenticated report.
func (c *Checker) Report(ctx context.Context) Report {
	now := c.now().UTC()

	r := Report{
		Version:       version.Current(),
		UptimeSeconds: int64(now.Sub(c.start).Seconds()),
		Timestamp:     now,
		Features: map[string]bool{
			"lite_mode":             c.cfg.Features.LiteMode,
			"admin_rbac":            c.cfg.Features.AdminRBAC,
			"dual_approval":         c.cfg.Features.DualApproval,
			"deferred_erasure":      c.cfg.Features.DeferredErasure,
			"kek_rotation_reminder": c.cfg.Features.KEKRotationReminder,
			"throttle":              c.cfg.Throttle.Enabled,
			"admin_ui":              c.cfg.Admin.UIEnabled,
		},
	}

	r.Database = c.checkDatabase(ctx)
	r.KEK = c.checkKEK(now)
	r.TLS = c.checkTLS(now)
	r.Audit = c.checkAudit(ctx)
	r.Alerts = c.checkAlerts(ctx)

	c.mu.RLock()
	r.LastError = c.lastError
	c.mu.RUnlock()

	r.Status = worst(
		r.Database.Status,
		r.KEK.Status,
		r.Audit.Status,
		tlsStatus(r.TLS),
	)
	return r
}

func (c *Checker) checkDatabase(ctx context.Context) DatabaseHealth {
	h := DatabaseHealth{Engine: c.store.Engine()}

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Latency is a stopwatch reading, so both ends use the wall clock. The
	// injected clock is for calendar questions such as certificate expiry;
	// taking one end from each made every report degraded whenever the
	// injected clock was not the present.
	start := time.Now()
	err := c.store.Ping(pingCtx)
	h.LatencyMS = time.Since(start).Milliseconds()

	if err != nil {
		h.Status = StatusError
		h.Detail = "database is not reachable"
		return h
	}

	// A reachable but very slow database still authenticates users, so it is
	// degraded rather than failed. The threshold is generous: this is a single
	// round trip, and anything approaching a second means the storage is in
	// trouble even if it answers.
	if h.LatencyMS > 500 {
		h.Status = StatusDegraded
		h.Detail = fmt.Sprintf("a single round trip took %dms", h.LatencyMS)
		return h
	}

	h.Status = StatusOK
	return h
}

func (c *Checker) checkKEK(now time.Time) KEKHealth {
	h := KEKHealth{}

	if c.keyring == nil {
		h.Status = StatusError
		h.Detail = "no keyring is loaded"
		return h
	}

	v, key, err := c.keyring.Current()
	if err != nil {
		h.Status = StatusError
		h.Detail = "the current key is not available"
		return h
	}
	// The key itself is of no interest here, only that it could be fetched.
	for i := range key {
		key[i] = 0
	}

	h.CurrentVersion = v
	h.RetainedVersions = len(c.keyring.Versions())
	h.Status = StatusOK

	interval := c.cfg.KEK.RotationInterval.Duration
	if c.cfg.Features.KEKRotationReminder && interval > 0 && !c.kekRotatedAt.IsZero() {
		age := now.Sub(c.kekRotatedAt)
		if age > interval {
			h.RotationOverdue = true
			h.Status = StatusDegraded
			h.Detail = fmt.Sprintf("the current key has been in use for %d days, the interval is %d",
				int(age.Hours()/24), int(interval.Hours()/24))
		}
	}
	return h
}

// KEKRotation reports the current key version, how long it has been current
// and whether that exceeds the configured interval. The janitor polls it so
// that an overdue rotation becomes an alert an operator sees, instead of a
// field in a report nobody happens to request.
func (c *Checker) KEKRotation() (version uint32, age time.Duration, overdue bool) {
	h := c.checkKEK(c.now().UTC())
	if !c.kekRotatedAt.IsZero() {
		age = c.now().UTC().Sub(c.kekRotatedAt)
	}
	return h.CurrentVersion, age, h.RotationOverdue
}

// checkTLS parses the configured certificate from disk.
//
// It is read on every call rather than cached, so that renewing a certificate
// is reflected without a restart. The file is small and this route is not on
// the hot path.
func (c *Checker) checkTLS(now time.Time) *TLSHealth {
	if c.cfg.Server.TLSCertFile == "" {
		// TLS is terminated by a reverse proxy, whose certificate this service
		// cannot see. Reporting nothing is honest; reporting ok would be a
		// claim about something it does not know.
		return nil
	}

	h := &TLSHealth{}

	raw, err := os.ReadFile(c.cfg.Server.TLSCertFile)
	if err != nil {
		h.Status = StatusError
		h.Detail = "the certificate file could not be read"
		return h
	}

	leaf, err := firstCertificate(raw)
	if err != nil {
		h.Status = StatusError
		h.Detail = "the certificate file could not be parsed"
		return h
	}

	h.NotAfter = leaf.NotAfter.UTC()
	h.Subject = leaf.Subject.CommonName
	h.ExpiresInDays = int(leaf.NotAfter.Sub(now).Hours() / 24)

	switch {
	case now.After(leaf.NotAfter):
		h.Status = StatusError
		h.Detail = "the certificate has expired"
	case h.ExpiresInDays <= 14:
		// Two weeks is chosen to sit well outside the renewal window of an
		// ACME client, which renews at thirty days, so this only fires when
		// automated renewal has actually stopped working.
		h.Status = StatusDegraded
		h.Detail = fmt.Sprintf("the certificate expires in %d days", h.ExpiresInDays)
	default:
		h.Status = StatusOK
	}
	return h
}

// firstCertificate returns the leaf from a PEM bundle.
func firstCertificate(raw []byte) (*x509.Certificate, error) {
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("health: no certificate block found")
}

func (c *Checker) checkAudit(ctx context.Context) AuditHealth {
	h := AuditHealth{}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	seq, _, err := c.store.ChainHead(ctx)
	if err != nil {
		h.Status = StatusError
		h.Detail = "the audit chain head could not be read"
		return h
	}
	h.HeadSeq = seq
	h.Status = StatusOK
	return h
}

func (c *Checker) checkAlerts(ctx context.Context) map[string]int {
	out := map[string]int{
		string(store.SeverityInfo):     0,
		string(store.SeverityWarning):  0,
		string(store.SeverityCritical): 0,
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	counts, err := c.store.CountOpenAlerts(ctx, c.cfg.TenantID())
	if err != nil {
		return out
	}
	for sev, n := range counts {
		out[string(sev)] = n
	}
	return out
}

// MinTLSVersion is the floor for the in-process TLS listener.
//
// TLS 1.2 is the floor rather than 1.3 because some corporate middleboxes on
// the deployment paths this targets still cannot complete a 1.3 handshake.
// Everything below 1.2 has known practical breaks and is not offered.
const MinTLSVersion = tls.VersionTLS12

func tlsStatus(h *TLSHealth) Status {
	if h == nil {
		return StatusOK
	}
	return h.Status
}

// worst returns the most severe status among those given.
func worst(statuses ...Status) Status {
	out := StatusOK
	for _, s := range statuses {
		switch s {
		case StatusError:
			return StatusError
		case StatusDegraded:
			out = StatusDegraded
		}
	}
	return out
}
