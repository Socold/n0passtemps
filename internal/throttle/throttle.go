// Package throttle applies the rate limits that make credential guessing and
// key abuse expensive.
//
// Limits are evaluated per subject, per source address and per API key at the
// same time, because any single dimension is the wrong one. A per-subject limit
// alone lets an attacker spread one guess across ten thousand accounts and
// never trip anything. A per-address limit alone punishes every user behind one
// corporate NAT gateway the moment a single colleague fails twice. Only the
// conjunction bounds both the attacker and the blast radius.
//
// Buckets are addressed by a key derived from a hash of the domain-separated
// tuple (dimension, tenant, value) rather than by concatenating the three into
// a readable string. A scheme such as "subject:" + id is forgeable whenever the
// caller controls part of the value: a subject reference of "1:ip:198.51.100.7"
// lands in, or shadows, a bucket belonging to another dimension, and an
// attacker who can pick which bucket their failures are counted in can pick an
// empty one. Length-prefixing each field before hashing removes the ambiguity
// entirely, and the hash makes the key opaque so that a bucket key leaked in a
// log line does not disclose a subject reference or an address.
package throttle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"time"

	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/store"
)

// Dimension names one axis a limit is applied on.
type Dimension string

const (
	// DimSubject counts attempts against one end user.
	DimSubject Dimension = "subject"

	// DimIP counts attempts from one normalised source network. See
	// NormaliseIP for why the value is a network rather than an address.
	DimIP Dimension = "ip"

	// DimAPIKey caps the total volume one integrating application may send,
	// which bounds what a leaked key achieves before anyone notices it.
	DimAPIKey Dimension = "api_key"

	// DimAdminRevoke caps how many revocations one administrator may perform
	// inside the window. Revocation is final, so this burst limit is the
	// control that replaces the reversibility the design does not offer.
	DimAdminRevoke Dimension = "admin_revoke"

	// DimEnrolmentTicket counts attempts against one enrolment ticket, keyed on
	// the clear selector half of the presented secret.
	//
	// It is keyed on the selector rather than on the subject because a
	// redemption attempt naming a ticket that does not exist resolves to no
	// subject, and those are exactly the attempts a guessing campaign consists
	// of. Bucketing on what the caller presented bounds guessing per ticket,
	// while DimIP bounds spraying across many.
	DimEnrolmentTicket Dimension = "enrolment_ticket"
)

// dimensionOrder fixes the evaluation order.
//
// Ranging over the caller's map would report a different dimension on each
// identical request, which makes both the alerting and the tests
// non-deterministic.
var dimensionOrder = []Dimension{DimSubject, DimIP, DimAPIKey, DimAdminRevoke, DimEnrolmentTicket}

// unknownIP is the single bucket every address that cannot be parsed lands in.
//
// Keying on an empty string instead would merge those attempts with any other
// dimension that happens to be passed an empty value, and dropping them
// silently would leave a caller able to disable its own address limit by
// sending a malformed forwarded header.
const unknownIP = "unknown"

// Limiter evaluates and records rate limits.
//
// It holds no state of its own: every counter lives in the store, so several
// instances of the service share one set of limits.
type Limiter struct {
	store store.ThrottleStore
	cfg   config.Throttle
	now   func() time.Time
}

// New returns a Limiter reading its thresholds from cfg.
//
// clock is injected so tests can advance time. A nil clock falls back to
// time.Now, which is the only place in this package that reads the wall clock.
func New(s store.ThrottleStore, cfg config.Throttle, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{store: s, cfg: cfg, now: clock}
}

// Result reports what a check or a record decided.
//
// Attempts and Failures describe the dimension named in Dimension: the one that
// refused, or, when nothing refused, the one closest to its threshold. That is
// the dimension an operator needs to see, and reporting a mixture of several
// would be meaningless.
type Result struct {
	Allowed    bool
	Blocked    bool
	RetryAfter time.Duration
	Dimension  Dimension
	Attempts   int
	Failures   int

	// Counters reports what every dimension the call actually touched stood
	// at, keyed by dimension. Dimension, Attempts and Failures above name one
	// of them, which is the right answer for a refusal but not for a caller
	// that needs several at once.
	//
	// It exists so that internal/risk can read the per-subject and
	// per-network failure counts without a second round trip to the store:
	// Record already reads every bucket, so the numbers are in hand and the
	// alternative is one extra query per dimension on the authentication
	// path. A dimension the caller did not supply, one with an empty value,
	// and every dimension after the one that refused a Check, are absent
	// rather than zero. It is nil when limiting is disabled.
	Counters map[Dimension]Counter
}

// Counter is one bucket's state inside the current window.
type Counter struct {
	Attempts int
	Failures int
}

// Check reports whether any supplied dimension is currently blocked, without
// recording an attempt.
//
// It exists to be called before the expensive part of a ceremony. An Argon2id
// evaluation or a WebAuthn signature verification performed for a caller that
// is already locked out is work an attacker gets for free.
func (l *Limiter) Check(ctx context.Context, tenantID string, dims map[Dimension]string) (Result, error) {
	if !l.cfg.Enabled {
		// Deliberately before any validation, so a deployment with throttling
		// off never reaches the store and never fails on this path.
		return Result{Allowed: true}, nil
	}

	if err := l.validate(dims); err != nil {
		return Result{}, err
	}

	now := l.now()
	var closest Result
	closest.Allowed = true
	counters := make(map[Dimension]Counter, len(dims))

	for _, dim := range dimensionOrder {
		value, ok := dims[dim]
		if !ok {
			continue
		}
		value = normaliseValue(dim, value)
		if value == "" {
			// An empty value identifies nobody. Counting it would pile
			// unrelated callers into one shared bucket.
			continue
		}

		key := l.BucketKey(dim, tenantID, value)
		st, err := l.store.GetThrottle(ctx, tenantID, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return Result{}, fmt.Errorf("throttle: read bucket for dimension %s: %w", dim, err)
		}
		counters[dim] = Counter{Attempts: st.Attempts, Failures: st.Failures}
		if st.Blocked(now) {
			return withCounters(blockedResult(dim, st, st.BlockedUntil.Sub(now)), counters), nil
		}
		closest = keepClosest(closest, dim, st)
	}

	return withCounters(closest, counters), nil
}

// Record counts one attempt against every supplied dimension and applies a
// block wherever a threshold has been crossed.
//
// A successful attempt still counts towards the volume limits, since volume is
// what bounds a leaked API key, but only a failure counts towards a lockout: a
// user who authenticates fifty times in an afternoon has done nothing wrong.
//
// Every dimension is recorded before any is judged. Returning as soon as the
// first threshold trips would leave the remaining counters short, and an
// attacker could then keep one dimension permanently below its limit by making
// sure another trips first.
func (l *Limiter) Record(ctx context.Context, tenantID string, dims map[Dimension]string, failure bool) (Result,
	error) {
	if !l.cfg.Enabled {
		return Result{Allowed: true}, nil
	}

	if err := l.validate(dims); err != nil {
		return Result{}, err
	}

	now := l.now()

	type observed struct {
		dim Dimension
		key string
		st  *store.ThrottleState
	}
	seen := make([]observed, 0, len(dims))

	for _, dim := range dimensionOrder {
		value, ok := dims[dim]
		if !ok {
			continue
		}
		value = normaliseValue(dim, value)
		if value == "" {
			continue
		}

		key := l.BucketKey(dim, tenantID, value)
		// The owning subject is passed only for the per-subject dimension.
		// The buckets keyed on an address or an API key belong to no single
		// subject, and attributing one to a subject would make a purge delete
		// a counter that still bounds other people's attempts.
		var owner string
		if dim == DimSubject {
			owner = value
		}

		st, err := l.store.Hit(ctx, tenantID, key, owner, l.cfg.Window.Duration, now, failure)
		if err != nil {
			return Result{}, fmt.Errorf("throttle: record attempt for dimension %s: %w", dim, err)
		}
		seen = append(seen, observed{dim: dim, key: key, st: st})
	}

	lockout := l.cfg.LockoutDuration.Duration
	refused := Result{Allowed: true}
	counters := make(map[Dimension]Counter, len(seen))
	for _, o := range seen {
		counters[o.dim] = Counter{Attempts: o.st.Attempts, Failures: o.st.Failures}
	}

	for _, o := range seen {
		if o.st.Blocked(now) {
			// The bucket was already blocked when the attempt arrived. The
			// attempt is still counted, so continued hammering stays visible
			// in the bucket rather than disappearing behind the block.
			if refused.Allowed {
				refused = blockedResult(o.dim, o.st, o.st.BlockedUntil.Sub(now))
			}
			continue
		}

		maxAttempts, maxFailures, err := l.limits(o.dim)
		if err != nil {
			return Result{}, err
		}
		crossed := (maxFailures > 0 && o.st.Failures >= maxFailures) ||
			(maxAttempts > 0 && o.st.Attempts >= maxAttempts)
		if !crossed {
			if refused.Allowed {
				refused = keepClosest(refused, o.dim, o.st)
			}
			continue
		}

		if err := l.store.Block(ctx, tenantID, o.key, now.Add(lockout)); err != nil {
			return Result{}, fmt.Errorf("throttle: block bucket for dimension %s: %w", o.dim, err)
		}
		if refused.Allowed {
			refused = blockedResult(o.dim, o.st, lockout)
		}
	}

	return withCounters(refused, counters), nil
}

// withCounters attaches the per-dimension snapshot to a result.
//
// It is applied at each return rather than inside blockedResult and
// keepClosest, because both of those build a fresh Result and would drop
// whatever had been collected so far.
func withCounters(res Result, counters map[Dimension]Counter) Result {
	if len(counters) > 0 {
		res.Counters = counters
	}
	return res
}

// ResetSubject clears every limit a subject is held under, which is what the
// administrative unlock performs.
//
// Two calls are needed. The subject bucket is addressed by a key only this
// package can derive, so it is cleared explicitly. The store is then asked to
// clear anything else it associates with the subject through its own schema.
// Neither call alone is sufficient: the store cannot recompute the derived key,
// and this package does not know what else the store recorded.
func (l *Limiter) ResetSubject(ctx context.Context, tenantID, subjectID string) error {
	if subjectID == "" {
		return errors.New("throttle: reset subject: subject id is required")
	}

	var errs []error
	key := l.BucketKey(DimSubject, tenantID, subjectID)
	if err := l.store.ResetThrottle(ctx, tenantID, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		errs = append(errs, fmt.Errorf("throttle: reset subject bucket: %w", err))
	}
	_, err := l.store.ResetSubjectThrottles(ctx, tenantID, subjectID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		errs = append(errs, fmt.Errorf("throttle: reset subject buckets: %w", err))
	}
	return errors.Join(errs...)
}

// BucketKey derives the storage key for one bucket.
//
// It is exported because the administrative reset endpoint has to address the
// same bucket the request path wrote to, and a second implementation of the
// derivation would eventually disagree with this one.
//
// The value is normalised first, so a caller passing a raw remote address and a
// caller passing an already normalised network reach the same bucket.
func (l *Limiter) BucketKey(dim Dimension, tenantID, value string) string {
	h := sha256.New()
	writeField(h, bucketDomain)
	writeField(h, string(dim))
	writeField(h, tenantID)
	writeField(h, normaliseValue(dim, value))
	return hex.EncodeToString(h.Sum(nil))[:bucketKeyHexLen]
}

const (
	// bucketDomain separates these hashes from every other use of SHA-256 in
	// the service, and carries a version so the derivation can change without
	// two releases sharing a bucket they disagree about.
	bucketDomain = "n0passtemps/throttle/v1"

	// bucketKeyHexLen keeps 128 bits of the digest. A collision would merge
	// two victims' counters, and 128 bits puts that beyond reach while keeping
	// the key short enough to index cheaply.
	bucketKeyHexLen = 32
)

// writeField length-prefixes each component before hashing it.
//
// Without the prefix, the tuple ("tenant", "aa") and the tuple ("tenanta", "a")
// hash identically, which is exactly the cross-bucket confusion the derivation
// exists to prevent.
func writeField(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

// normaliseValue applies the per-dimension canonical form. Only addresses need
// one; the other dimensions are opaque identifiers the service issued itself.
func normaliseValue(dim Dimension, value string) string {
	if dim == DimIP {
		return NormaliseIP(value)
	}
	return strings.TrimSpace(value)
}

// NormaliseIP reduces a source address to the network a limit should apply to.
//
// IPv6 is bucketed by its /64 prefix. A single host is routinely delegated an
// entire /64, often larger, so a per-address limit is bypassed by picking a new
// address from a range the attacker already holds, at no cost. IPv4 is bucketed
// by its /32, since addresses there are scarce enough that one address is a
// meaningful unit.
//
// A host:port pair, a bracketed IPv6 host:port pair and an IPv4-mapped IPv6
// address are all accepted, because the value reaches this function from
// RemoteAddr or a forwarded header and arrives in whichever of those forms the
// peer chose. Anything that cannot be parsed lands in one fixed bucket rather
// than in an empty key.
//
// The function is idempotent: feeding it its own output returns that output, so
// deriving a bucket key twice for the same address is safe.
func NormaliseIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || s == unknownIP {
		return unknownIP
	}

	// Its own output for IPv6, and a CIDR an operator typed by hand.
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return unknownIP
		}
		s = network.IP.String()
	}

	// SplitHostPort fails on a bare IPv6 address, which is the reason the
	// error is ignored rather than reported: the original value is then still
	// a candidate address.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return unknownIP
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// validate refuses a dimension this package does not know.
//
// It runs before anything is read or written, because a caller that misnames a
// dimension believes it is limited and is not, and discovering that after the
// attempt has been recorded under the remaining dimensions hides the mistake.
func (l *Limiter) validate(dims map[Dimension]string) error {
	for dim := range dims {
		if _, _, err := l.limits(dim); err != nil {
			return err
		}
	}
	return nil
}

// limits returns the attempt and failure thresholds for dim. A zero threshold
// means the dimension does not enforce that kind of limit.
//
// An unrecognised dimension is a programming error and is reported rather than
// ignored: silently skipping it would leave an endpoint unlimited.
func (l *Limiter) limits(dim Dimension) (maxAttempts, maxFailures int, err error) {
	switch dim {
	case DimSubject:
		// Lockout only. A user may authenticate as often as they like.
		return 0, l.cfg.MaxFailuresPerSubject, nil
	case DimIP:
		// Set well above the per-subject limit, so that one NAT gateway
		// tolerates many users each making the occasional mistake.
		return 0, l.cfg.MaxFailuresPerIP, nil
	case DimAPIKey:
		// Volume only. Failures from one key are already counted under the
		// subject and the address they concern.
		return l.cfg.MaxRequestsPerKey, 0, nil
	case DimAdminRevoke:
		// Volume only, and the volume is the point: the burst is what an
		// operator is allowed to destroy before someone has to intervene.
		return l.cfg.AdminRevokeBurst, 0, nil
	case DimEnrolmentTicket:
		// Lockout only, on the per-subject budget. A ticket belongs to exactly
		// one subject, so the number of wrong attempts worth tolerating is the
		// same number, and reusing the setting avoids a configuration key whose
		// correct value nobody could reason about separately.
		return 0, l.cfg.MaxFailuresPerSubject, nil
	default:
		return 0, 0, fmt.Errorf("throttle: unknown dimension %q", dim)
	}
}

// blockedResult builds the refusal, rounding RetryAfter up to whole seconds.
//
// The value is handed to a caller that renders it into a Retry-After header,
// where a sub-second remainder would truncate to zero and invite an immediate
// retry.
func blockedResult(dim Dimension, st *store.ThrottleState, remaining time.Duration) Result {
	return Result{
		Allowed:    false,
		Blocked:    true,
		RetryAfter: ceilSeconds(remaining),
		Dimension:  dim,
		Attempts:   st.Attempts,
		Failures:   st.Failures,
	}
}

// keepClosest retains whichever dimension has come nearest to its threshold, so
// an allowed result still says how much headroom is left.
func keepClosest(current Result, dim Dimension, st *store.ThrottleState) Result {
	if current.Dimension != "" {
		if st.Failures < current.Failures {
			return current
		}
		if st.Failures == current.Failures && st.Attempts <= current.Attempts {
			return current
		}
	}
	return Result{
		Allowed:   true,
		Dimension: dim,
		Attempts:  st.Attempts,
		Failures:  st.Failures,
	}
}

func ceilSeconds(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if r := d % time.Second; r != 0 {
		d += time.Second - r
	}
	return d
}
