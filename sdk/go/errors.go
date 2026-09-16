package n0passtemps

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Problem type identifiers, as the server publishes them in the "type" member
// of an RFC 9457 body. They are stable, and they are what a client branches on.
const (
	// TypeBadRequest marks malformed or invalid input. Error.Detail says what.
	TypeBadRequest = "urn:n0passtemps:error:bad-request"

	// TypeUnauthorized marks a refused API key. See ErrUnauthorized.
	TypeUnauthorized = "urn:n0passtemps:error:unauthorized"

	// TypeForbidden marks an API key without the scope. See ErrForbidden.
	TypeForbidden = "urn:n0passtemps:error:forbidden"

	// TypeNotFound marks an absent resource. See ErrNotFound.
	TypeNotFound = "urn:n0passtemps:error:not-found"

	// TypeConflict marks a state conflict. See ErrConflict.
	TypeConflict = "urn:n0passtemps:error:conflict"

	// TypeCeremonyFailed marks a WebAuthn, TOTP or recovery-code failure. See
	// ErrAuthenticationFailed.
	TypeCeremonyFailed = "urn:n0passtemps:error:ceremony-failed"

	// TypeThrottled marks a rate limit. See ErrThrottled.
	TypeThrottled = "urn:n0passtemps:error:throttled"

	// TypePayloadTooLarge marks a request body above the server's limit.
	TypePayloadTooLarge = "urn:n0passtemps:error:payload-too-large"

	// TypeUnsupportedMedia marks a write whose Content-Type was not JSON. The
	// Client always sets it, so this points at a proxy rewriting requests.
	TypeUnsupportedMedia = "urn:n0passtemps:error:unsupported-media-type"

	// TypeInternal marks a fault in the server.
	TypeInternal = "urn:n0passtemps:error:internal"

	// TypeUnavailable marks a server that cannot reach its store. See
	// ErrUnavailable.
	TypeUnavailable = "urn:n0passtemps:error:unavailable"
)

// Sentinel errors for errors.Is. Each matches an *Error by its problem type,
// and by its status code when the body carried no type, which is the case
// when a proxy in front of the server produced the answer.
var (
	// ErrUnauthorized reports that the API key was missing, malformed, unknown
	// or revoked. It says nothing about the end user.
	ErrUnauthorized = errors.New("n0passtemps: the API key was refused")

	// ErrForbidden reports a valid API key that lacks the scope for the route.
	ErrForbidden = errors.New("n0passtemps: the API key lacks the required scope")

	// ErrNotFound reports an absent resource. Among the /v1 routes only
	// GetSubject distinguishes an unknown subject this way.
	ErrNotFound = errors.New("n0passtemps: the resource does not exist")

	// ErrConflict reports a request at odds with the current state, such as
	// confirming a TOTP enrolment that has expired.
	ErrConflict = errors.New("n0passtemps: the request conflicts with the current state")

	// ErrAuthenticationFailed reports that a ceremony did not succeed. The
	// server gives the same answer for a wrong code, an expired challenge, an
	// unknown subject and a locked one, so there is nothing further to learn
	// from it and nothing to gain by repeating the call.
	//
	// It shares status 401 with ErrUnauthorized. The two are told apart by the
	// problem type alone, which is why this sentinel never matches on status.
	ErrAuthenticationFailed = errors.New("n0passtemps: authentication did not succeed")

	// ErrThrottled reports a rate limit. Error.RetryAfter says how long the
	// server asks the caller to wait.
	ErrThrottled = errors.New("n0passtemps: too many attempts")

	// ErrUnavailable reports that the server could not reach its store. The
	// API key was not examined, so it is still good and the call may be
	// repeated later.
	ErrUnavailable = errors.New("n0passtemps: the service is temporarily unavailable")
)

// Error is a refusal from the server, decoded from its RFC 9457 problem body.
//
// Title and Type name a class of failure and never the reason one request was
// refused. RequestID is the field to log and to quote to the operator: it
// locates the server-side log and audit entries where the reason was written.
type Error struct {
	// Status is the HTTP status code of the response.
	Status int

	// Type is the "urn:n0passtemps:error:*" identifier, or empty when the body
	// was not a problem document.
	Type string

	// Title is the fixed description of the class of failure.
	Title string

	// Detail is present only on input validation and state conflicts.
	Detail string

	// RequestID matches the X-Request-Id response header.
	RequestID string

	// RetryAfter is the wait the server asks for, parsed from the Retry-After
	// header, or taken from the body's retry_after_seconds when a proxy
	// dropped the header. It is zero when neither is present.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("n0passtemps: ")
	b.WriteString(strconv.Itoa(e.Status))
	if e.Title != "" {
		b.WriteString(" ")
		b.WriteString(e.Title)
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Type != "" {
		b.WriteString(" [")
		b.WriteString(e.Type)
		b.WriteString("]")
	}
	if e.RequestID != "" {
		b.WriteString(" (request ")
		b.WriteString(e.RequestID)
		b.WriteString(")")
	}
	return b.String()
}

// Is reports whether target is the sentinel for this error's class, so that
// errors.Is(err, ErrThrottled) works without a type assertion.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.class(TypeUnauthorized, http.StatusUnauthorized)
	case ErrForbidden:
		return e.class(TypeForbidden, http.StatusForbidden)
	case ErrNotFound:
		return e.class(TypeNotFound, http.StatusNotFound)
	case ErrConflict:
		return e.class(TypeConflict, http.StatusConflict)
	case ErrAuthenticationFailed:
		return e.Type == TypeCeremonyFailed
	case ErrThrottled:
		return e.class(TypeThrottled, http.StatusTooManyRequests)
	case ErrUnavailable:
		return e.class(TypeUnavailable, http.StatusServiceUnavailable)
	}
	return false
}

// class matches on the problem type, and on the status code only when there is
// no type to go by. A typed body always wins: a 401 of type ceremony-failed
// must not read as a refused API key.
func (e *Error) class(problemType string, status int) bool {
	if e.Type != "" {
		return e.Type == problemType
	}
	return e.Status == status
}

// problemBody is the wire form of an RFC 9457 document from this server.
type problemBody struct {
	Type              string `json:"type"`
	Title             string `json:"title"`
	Detail            string `json:"detail"`
	RequestID         string `json:"request_id"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// newError builds an *Error from a response outside the 2xx range.
func newError(resp *http.Response, raw []byte) *Error {
	e := &Error{
		// The status line is authoritative. The body repeats it for clients
		// that have nothing else, and this one has the real thing.
		Status:    resp.StatusCode,
		RequestID: resp.Header.Get("X-Request-Id"),
	}

	var body problemBody
	if err := json.Unmarshal(raw, &body); err == nil {
		e.Type = body.Type
		e.Title = body.Title
		e.Detail = body.Detail
		if body.RequestID != "" {
			e.RequestID = body.RequestID
		}
	}
	// A body that is not a problem document comes from something in front of
	// the server. It is not echoed: it may be a page of HTML.
	if e.Title == "" {
		e.Title = http.StatusText(resp.StatusCode)
	}

	e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	if e.RetryAfter == 0 && body.RetryAfterSeconds > 0 {
		e.RetryAfter = time.Duration(body.RetryAfterSeconds) * time.Second
	}
	return e
}

// parseRetryAfter reads both forms RFC 9110 section 10.2.3 allows: a number of
// seconds, which is what the server sends, and an HTTP date, which a proxy may
// substitute.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
