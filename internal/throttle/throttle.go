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
// The per-subject limit is kept per authentication factor as well. Anybody can
// fail a ceremony on somebody else's behalf, since the subject reference is not
// a secret, and one bucket for every factor would let wrong TOTP codes lock a
// user out of the passkey nobody can forge. See Factor.
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

// Factor names the authentication factor a per-subject bucket counts for.
//
// A subject is identified by a reference that is not a secret, so anybody who
// knows it can fail on the subject's behalf. With one bucket for every factor,
// ten wrong TOTP codes would lock the subject out of WebAuthn as well, and the
// factor that cannot be guessed would be switched off by failing at the one
// that can. Each factor therefore has a budget of its own, and exhausting one
// leaves the others usable.
//
// The enrolment ticket is not listed: it already has a dimension of its own,
// keyed on the ticket selector rather than on the subject.
type Factor string

// The factors. The empty factor addresses the bucket releases before this type
// existed wrote to, which ResetSubject still clears.
const (
	FactorWebAuthn Factor = "webauthn"
	FactorTOTP     Factor = "totp"
	FactorRecovery Factor = "recovery"
)

// subjectFactors lists every factor a subject may hold a bucket under, the
// empty one included, so that ResetSubject can derive each key.
var subjectFactors = []Factor{"", FactorWebAuthn, FactorTOTP, FactorRecovery}

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

	// factor selects which of a subject's buckets DimSubject addresses. It is
	// set by ForFactor and empty on the Limiter New returns.
	factor Factor
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

// ForFactor returns a Limiter whose per-subject dimension addresses the bucket
// kept for factor. Every other dimension is unaffected.
//
// It is a view rather than a parameter of Check and Record because the factor
// is a property of the route, fixed for the whole ceremony, and threading it
// through every call would give each call site a chance to disagree with the
// one before it about which bucket the ceremony is counted in.
func (l *Limiter) ForFactor(factor Factor) *Limiter {
	view := *l
	view.factor = factor
	return &view
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

	// Advisory says the budget named by Dimension was used up and deliberately
	// not enforced. The attempt is allowed, and the caller reports the crossing
	// as it reports a lockout, minus the lockout. See locksOut for the one case
	// that sets it.
	Advisory bool

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
// A success therefore never applies a failure lockout, whatever the counter
// stands at. It used to: a bucket the janitor had not swept yet, or one whose
// lockout was shorter than its window, still held its failures, and the user
// who finally got their code right was locked out by the request that proved
// who they were.
//
// A success also clears the failures of the buckets that belong to the one
// party that just authenticated, which are the per-subject bucket of the factor
// and the enrolment ticket. It never clears a shared one: an attacker holding
// one working account could otherwise wipe the count of their own network
// between two rounds of guessing at somebody else's.
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

	refused := Result{Allowed: true}
	counters := make(map[Dimension]Counter, len(seen))
	for _, o := range seen {
		counters[o.dim] = Counter{Attempts: o.st.Attempts, Failures: o.st.Failures}
	}

	for _, o := range seen {
		verdict, err := l.judge(ctx, tenantID, o, now, failure)
		if err != nil {
			return Result{}, err
		}
		switch {
		case !refused.Allowed:
			// The first refusal is the one reported. The loop carries on so
			// that every remaining bucket is still judged and blocked.
		case !verdict.Allowed:
			refused = verdict
		case verdict.Advisory && !refused.Advisory:
			// Allowed, and still the thing worth reporting. It outranks the
			// nearest-threshold summary below, which describes a budget nobody
			// has used up.
			refused = verdict
		case refused.Advisory:
			// An advisory crossing is already held. Dimensions are judged in a
			// fixed order, so the first one keeps the report.
		default:
			refused = keepClosest(refused, o.dim, o.st)
		}
	}

	return withCounters(refused, counters), nil
}

// observed is one bucket as an attempt left it.
type observed struct {
	dim Dimension
	key string
	st  *store.ThrottleState
}

// judge decides what one recorded bucket means for the attempt that was just
// counted in it, and applies the lockout when a threshold has been crossed.
func (l *Limiter) judge(ctx context.Context, tenantID string, o observed, now time.Time, failure bool) (Result,
	error) {
	if o.st.Blocked(now) {
		// The bucket was already blocked when the attempt arrived. The attempt
		// is still counted, so continued hammering stays visible in the bucket
		// rather than disappearing behind the block.
		return blockedResult(o.dim, o.st, o.st.BlockedUntil.Sub(now)), nil
	}

	maxAttempts, maxFailures, err := l.limits(o.dim)
	if err != nil {
		return Result{}, err
	}

	if o.dim == DimAPIKey {
		// A rate limit and not a lockout. The ceiling is there to bound what a
		// leaked key achieves, and a block on top of it would make an
		// integrating application that ran hot for one minute unavailable to
		// every one of its users for a further lockout_duration. The refusal
		// lasts until the window rolls and no longer, and the request that
		// reaches the ceiling is served: a ceiling of N means N requests.
		if maxAttempts > 0 && o.st.Attempts > maxAttempts {
			return rateLimitedResult(o.dim, o.st, o.st.WindowStart.Add(l.cfg.Window.Duration).Sub(now)), nil
		}
		return Result{Allowed: true}, nil
	}

	// The failure threshold is read only when this attempt was a failure. See
	// the doc comment on Record for what judging it on a success used to do.
	crossed := (failure && maxFailures > 0 && o.st.Failures >= maxFailures) ||
		(maxAttempts > 0 && o.st.Attempts >= maxAttempts)
	if !crossed {
		if !failure && ownedByOneParty(o.dim) && o.st.Failures > 0 {
			err = l.clear(ctx, tenantID, o)
		}
		return Result{Allowed: true}, err
	}

	if !l.locksOut(o.dim) {
		return advisoryResult(o.dim, o.st), nil
	}

	lockout := l.cfg.LockoutDuration.Duration
	if err = l.store.Block(ctx, tenantID, o.key, now.Add(lockout)); err != nil {
		return Result{}, fmt.Errorf("throttle: block bucket for dimension %s: %w", o.dim, err)
	}
	return blockedResult(o.dim, o.st, lockout), nil
}

// locksOut reports whether crossing the budget of this bucket should stop the
// subject from authenticating, rather than only be counted and reported.
//
// Every bucket locks out except one: the per-subject budget of the WebAuthn
// factor. Nothing in that ceremony is guessed. An assertion is refused unless
// it carries a signature by a key the authenticator holds, so failing ten of
// them proves only that somebody sent ten wrong answers, and anybody who knows
// a subject reference can send them: beginning an assertion for a subject and
// completing it with rubbish would lock that person out of the factor they use
// every day, from a page they do not control, for as long as it was kept up.
//
// The failures are still counted, still reach internal/risk as a signal, and
// still raise the same alert, because an operator does want to know somebody is
// doing this. What is withheld is the refusal, which in this dimension only
// ever served the attacker. Volume stays bounded by the per-address and per-key
// limits, which apply here as everywhere.
func (l *Limiter) locksOut(dim Dimension) bool {
	return !(dim == DimSubject && l.factor == FactorWebAuthn)
}

// advisoryResult reports a budget crossed on a bucket that does not lock out.
func advisoryResult(dim Dimension, st *store.ThrottleState) Result {
	return Result{
		Allowed: true, Advisory: true, Dimension: dim,
		Attempts: st.Attempts, Failures: st.Failures,
	}
}

// ownedByOneParty reports whether a bucket of this dimension counts the
// attempts made in the name of exactly one party, so that a success by that
// party may clear it.
func ownedByOneParty(dim Dimension) bool {
	return dim == DimSubject || dim == DimEnrolmentTicket
}

// clear forgets a bucket after a success.
//
// The row is removed rather than zeroed, which is the only clearing the store
// offers. The counters reported to the caller are the ones read before the
// removal, so risk reporting still sees the failures that preceded the success.
func (l *Limiter) clear(ctx context.Context, tenantID string, o observed) error {
	err := l.store.ResetThrottle(ctx, tenantID, o.key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("throttle: clear bucket for dimension %s: %w", o.dim, err)
	}
	return nil
}

// Reservation is an attempt that has been counted before its outcome is known.
//
// See Reserve. Exactly one of Fail and Succeed is called on it, once.
type Reservation struct {
	limiter  *Limiter
	tenantID string
	now      time.Time

	// held are the buckets the attempt was counted in as a failure.
	held []observed

	// shared are the dimensions that were only checked, and that are recorded
	// once the outcome is known.
	shared map[Dimension]string
}

// Reserve refuses an attempt that is over its budget and otherwise counts it,
// as a failure, before the caller evaluates it.
//
// Check followed by Record leaves the evaluation of the secret between the two.
// Every request of a parallel burst then passes Check before the first of them
// has recorded anything, and a budget of ten guesses at a six-digit code
// becomes a budget of however many connections the attacker opens. Counting the
// attempt first closes that: the store's Hit is one atomic statement, so the
// requests of a burst are handed consecutive counts, and only those whose count
// is within the budget are evaluated. The pessimistic count is then confirmed
// by Fail or taken back by Succeed.
//
// Only the buckets owned by one party are reserved, which are the per-subject
// bucket of the factor and the enrolment ticket. Taking a reservation back
// means clearing the bucket, since the store has no operation that subtracts
// one failure, and clearing is only right where a success is supposed to clear
// anyway. The address dimension is checked here and recorded when the outcome
// is known, as Check and Record would do. A burst can therefore overshoot the
// per-address budget by the number of requests in flight, but it cannot
// overshoot the per-subject one, and that is the one which bounds guessing.
//
// An attempt that arrives while a block is in force is refused before it is
// counted. Counting it would let anybody extend a lockout for as long as they
// cared to keep sending requests into it.
func (l *Limiter) Reserve(ctx context.Context, tenantID string, dims map[Dimension]string) (*Reservation, Result,
	error) {
	if !l.cfg.Enabled {
		return &Reservation{}, Result{Allowed: true}, nil
	}

	checked, err := l.Check(ctx, tenantID, dims)
	if err != nil {
		return nil, Result{}, err
	}
	if !checked.Allowed {
		return nil, checked, nil
	}

	rv := &Reservation{limiter: l, tenantID: tenantID, now: l.now(), shared: make(map[Dimension]string, len(dims))}
	for _, dim := range dimensionOrder {
		value, ok := dims[dim]
		if !ok {
			continue
		}
		if !ownedByOneParty(dim) {
			rv.shared[dim] = value
			continue
		}
		value = normaliseValue(dim, value)
		if value == "" {
			continue
		}

		key := l.BucketKey(dim, tenantID, value)
		var owner string
		if dim == DimSubject {
			owner = value
		}
		st, hitErr := l.store.Hit(ctx, tenantID, key, owner, l.cfg.Window.Duration, rv.now, true)
		if hitErr != nil {
			return nil, Result{}, fmt.Errorf("throttle: reserve attempt for dimension %s: %w", dim, hitErr)
		}
		rv.held = append(rv.held, observed{dim: dim, key: key, st: st})
	}

	// Judged only once every bucket has been hit, for the reason Record gives.
	refused := Result{Allowed: true}
	for _, o := range rv.held {
		verdict, judgeErr := l.judgeReserved(ctx, tenantID, o, rv.now)
		if judgeErr != nil {
			return nil, Result{}, judgeErr
		}
		if refused.Allowed && !verdict.Allowed {
			refused = verdict
		}
	}
	if !refused.Allowed {
		return nil, withCounters(refused, checked.Counters), nil
	}
	return rv, withCounters(Result{Allowed: true}, checked.Counters), nil
}

// judgeReserved refuses a reservation whose count is past the budget.
//
// The comparison is strict where Record's is not. A budget of ten means ten
// evaluated attempts, so the reservation that is handed the count of ten is
// evaluated, and it is Fail that applies the lockout if it turns out wrong. The
// one handed eleven is refused without being evaluated, and blocks the bucket
// itself in case none of the ten in flight ever reports back.
func (l *Limiter) judgeReserved(ctx context.Context, tenantID string, o observed, now time.Time) (Result, error) {
	if o.st.Blocked(now) {
		return blockedResult(o.dim, o.st, o.st.BlockedUntil.Sub(now)), nil
	}
	_, maxFailures, err := l.limits(o.dim)
	if err != nil {
		return Result{}, err
	}
	if maxFailures <= 0 || o.st.Failures <= maxFailures {
		return Result{Allowed: true}, nil
	}

	if !l.locksOut(o.dim) {
		return advisoryResult(o.dim, o.st), nil
	}

	lockout := l.cfg.LockoutDuration.Duration
	if err = l.store.Block(ctx, tenantID, o.key, now.Add(lockout)); err != nil {
		return Result{}, fmt.Errorf("throttle: block bucket for dimension %s: %w", o.dim, err)
	}
	return blockedResult(o.dim, o.st, lockout), nil
}

// Fail confirms the reservation: the attempt was evaluated and was wrong.
//
// The reserved buckets already hold the failure, so nothing is added to them.
// What remains is to apply the lockout when this failure was the one that used
// up the budget, and to record the failure against the shared dimensions. The
// result reads as Record's does, so a refusal in it means a limit has just
// tripped.
func (rv *Reservation) Fail(ctx context.Context) (Result, error) {
	if rv == nil || rv.limiter == nil {
		return Result{Allowed: true}, nil
	}
	l := rv.limiter

	res, err := l.Record(ctx, rv.tenantID, rv.shared, true)
	if err != nil {
		return Result{}, err
	}

	counters := make(map[Dimension]Counter, len(rv.held)+len(res.Counters))
	for dim, c := range res.Counters {
		counters[dim] = c
	}
	tripped := Result{Allowed: true}
	for _, o := range rv.held {
		counters[o.dim] = Counter{Attempts: o.st.Attempts, Failures: o.st.Failures}
		verdict, judgeErr := l.judge(ctx, rv.tenantID, o, rv.now, true)
		if judgeErr != nil {
			return Result{}, judgeErr
		}
		switch {
		case tripped.Allowed && !verdict.Allowed:
			tripped = verdict
		case tripped.Allowed && !tripped.Advisory && verdict.Advisory:
			// Allowed and worth reporting; a refusal on a later bucket still
			// replaces it.
			tripped = verdict
		}
	}
	if !tripped.Allowed || tripped.Advisory {
		res = tripped
	}
	return withCounters(res, counters), nil
}

// Succeed takes the reservation back: the attempt was evaluated and was right.
//
// The reserved buckets are cleared, which both removes the pessimistic failure
// and gives the party that just authenticated a fresh budget. The counters in
// the result are those that preceded this attempt, the reserved failure taken
// out, because that is what risk reporting asks about.
//
// Clearing also lifts a block that a request racing this one applied after it
// found the budget spent. That is accepted: the attempt being confirmed here
// was inside the budget and was right, and the party it authenticated should
// not be locked out by the noise that surrounded it.
func (rv *Reservation) Succeed(ctx context.Context) (Result, error) {
	if rv == nil || rv.limiter == nil {
		return Result{Allowed: true}, nil
	}
	l := rv.limiter

	res, err := l.Record(ctx, rv.tenantID, rv.shared, false)
	if err != nil {
		return Result{}, err
	}

	counters := make(map[Dimension]Counter, len(rv.held)+len(res.Counters))
	for dim, c := range res.Counters {
		counters[dim] = c
	}
	for _, o := range rv.held {
		counters[o.dim] = Counter{Attempts: o.st.Attempts, Failures: o.st.Failures - 1}
		if err = l.clear(ctx, rv.tenantID, o); err != nil {
			return Result{}, err
		}
	}
	return withCounters(res, counters), nil
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
// Two kinds of call are needed. The subject's buckets, one per factor, are
// addressed by keys only this package can derive, so they are cleared
// explicitly. The store is then asked to
// clear anything else it associates with the subject through its own schema.
// Neither call alone is sufficient: the store cannot recompute the derived key,
// and this package does not know what else the store recorded.
func (l *Limiter) ResetSubject(ctx context.Context, tenantID, subjectID string) error {
	if subjectID == "" {
		return errors.New("throttle: reset subject: subject id is required")
	}

	var errs []error
	for _, factor := range subjectFactors {
		// Every factor, whichever view of the Limiter this was called on. An
		// operator unlocking a subject means all of it, and an unlock that
		// left the TOTP bucket blocked would be reported as a bug.
		key := l.ForFactor(factor).BucketKey(DimSubject, tenantID, subjectID)
		if err := l.store.ResetThrottle(ctx, tenantID, key); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("throttle: reset subject bucket: %w", err))
		}
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
	if dim == DimSubject && l.factor != "" {
		// A fifth field, and only for the per-subject dimension. The fields
		// are length-prefixed, so a five-field tuple cannot hash to the same
		// input as any four-field one, and the factor-less key stays what it
		// was. The factor is part of the hashed key and not a column, so the
		// schema is unchanged and the row is still found by its subject_id.
		writeField(h, string(l.factor))
	}
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

// rateLimitedResult builds the refusal of a dimension that limits a rate and
// never locks out. Blocked stays false: nothing was written that outlasts the
// window, and RetryAfter is what is left of the window.
func rateLimitedResult(dim Dimension, st *store.ThrottleState, remaining time.Duration) Result {
	res := blockedResult(dim, st, remaining)
	res.Blocked = false
	return res
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
