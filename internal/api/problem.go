// Package api exposes the HTTP surface: the public /v1 routes an integrating
// application calls, and the /admin/v1 routes an operator uses.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Socold/n0passtemps/internal/logging"
)

// Problem is the error body returned by every route, following RFC 9457.
//
// The fields are deliberately spare. Title and Type describe a class of
// failure, never the specific reason one request was refused: an authentication
// service that explains why a ceremony failed is an oracle for probing its own
// configuration. The real reason is logged and audited, where an operator can
// read it and an attacker cannot.
type Problem struct {
	// Type is a stable identifier for the class of error, usable by a client
	// to branch on. It is a URN rather than a URL because there is no
	// documentation site to dereference.
	Type string `json:"type"`

	// Title is a short, fixed description of the class.
	Title string `json:"title"`

	// Status repeats the HTTP status code, so a client that has only the body
	// still knows.
	Status int `json:"status"`

	// Detail is present only where the extra information is safe to disclose,
	// which in practice means input validation: telling a caller that a field
	// is missing helps them and tells an attacker nothing.
	Detail string `json:"detail,omitempty"`

	// RequestID lets an operator find the corresponding log and audit entries.
	// It is the one piece of information a support exchange actually needs.
	RequestID string `json:"request_id,omitempty"`

	// RetryAfterSeconds is set on a throttled response, mirroring the header.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

// Problem type identifiers.
const (
	TypeBadRequest       = "urn:n0passtemps:error:bad-request"
	TypeUnauthorized     = "urn:n0passtemps:error:unauthorized"
	TypeForbidden        = "urn:n0passtemps:error:forbidden"
	TypeNotFound         = "urn:n0passtemps:error:not-found"
	TypeConflict         = "urn:n0passtemps:error:conflict"
	TypeCeremonyFailed   = "urn:n0passtemps:error:ceremony-failed"
	TypeThrottled        = "urn:n0passtemps:error:throttled"
	TypePayloadTooLarge  = "urn:n0passtemps:error:payload-too-large"
	TypeUnsupportedMedia = "urn:n0passtemps:error:unsupported-media-type"
	TypeApprovalRequired = "urn:n0passtemps:error:approval-required"
	TypeInternal         = "urn:n0passtemps:error:internal"
	TypeUnavailable      = "urn:n0passtemps:error:unavailable"
)

// APIError is an error that carries the response it should produce.
//
// Handlers return one of these instead of writing a response themselves, so
// that the status code, the logged message and the audit outcome are decided in
// one place rather than drifting apart across handlers.
type APIError struct {
	Status int
	Type   string
	Title  string

	// Detail reaches the client. Leave it empty unless it is safe to disclose.
	Detail string

	// Internal is logged and never sent. It is where the real reason goes.
	Internal error

	RetryAfterSeconds int
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Internal != nil {
		return e.Title + ": " + e.Internal.Error()
	}
	return e.Title
}

// Unwrap exposes the internal cause to errors.Is and errors.As.
func (e *APIError) Unwrap() error { return e.Internal }

// Constructors for the cases that occur more than once. Each fixes the title so
// that the same condition always produces the same body.

// BadRequest reports malformed or invalid input. Detail is safe here.
func BadRequest(detail string, cause error) *APIError {
	return &APIError{
		Status: http.StatusBadRequest, Type: TypeBadRequest,
		Title: "the request is not valid", Detail: detail, Internal: cause,
	}
}

// Unauthorized reports a missing, malformed or unrecognised credential.
//
// The four cases are one response on purpose. Distinguishing "no credential"
// from "unknown credential" from "revoked credential" would let a caller
// enumerate valid selectors.
func Unauthorized(cause error) *APIError {
	return &APIError{
		Status: http.StatusUnauthorized, Type: TypeUnauthorized,
		Title: "authentication is required", Internal: cause,
	}
}

// Forbidden reports a credential that is valid but lacks the permission.
func Forbidden(cause error) *APIError {
	return &APIError{
		Status: http.StatusForbidden, Type: TypeForbidden,
		Title: "this credential is not permitted to perform that operation", Internal: cause,
	}
}

// NotFound reports an absent resource.
func NotFound(cause error) *APIError {
	return &APIError{
		Status: http.StatusNotFound, Type: TypeNotFound,
		Title: "the resource does not exist", Internal: cause,
	}
}

// Conflict reports a uniqueness or state conflict.
func Conflict(detail string, cause error) *APIError {
	return &APIError{
		Status: http.StatusConflict, Type: TypeConflict,
		Title: "the request conflicts with the current state", Detail: detail, Internal: cause,
	}
}

// CeremonyFailed reports a WebAuthn, TOTP or recovery-code failure.
//
// Every such failure returns this, with no detail. A caller learns that
// authentication did not succeed, which is all it needs to act on, and cannot
// tell a wrong signature from an expired challenge from an unknown credential.
func CeremonyFailed(cause error) *APIError {
	return &APIError{
		Status: http.StatusUnauthorized, Type: TypeCeremonyFailed,
		Title: "authentication did not succeed", Internal: cause,
	}
}

// Throttled reports a rate limit, with the wait a client should respect.
func Throttled(retryAfterSeconds int, cause error) *APIError {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	return &APIError{
		Status: http.StatusTooManyRequests, Type: TypeThrottled,
		Title: "too many attempts", Internal: cause,
		RetryAfterSeconds: retryAfterSeconds,
	}
}

// ApprovalRequired reports that the operation was queued for a second
// administrator rather than performed.
func ApprovalRequired(detail string) *APIError {
	return &APIError{
		Status: http.StatusAccepted, Type: TypeApprovalRequired,
		Title:  "the operation requires approval by a second administrator",
		Detail: detail,
	}
}

// NotConfigured reports that a route exists and this deployment has not
// configured what it serves.
//
// It is separate from Unavailable, which means a dependency is down and a retry
// may work. Nothing here will change on a retry, and the two deserve different
// alerts: one is an incident, the other is a configuration somebody has to go
// and change.
//
// It is 503 rather than 404 because 404 says the route is not there, and an
// operator reading that would go looking for a version mismatch. It is not an
// empty body either: an empty document scrapes clean and reads as "nothing has
// happened", which a monitoring system will believe until somebody checks.
func NotConfigured(detail string, cause error) *APIError {
	return &APIError{
		Status: http.StatusServiceUnavailable, Type: TypeUnavailable,
		Title:  "the service is not configured to answer that request",
		Detail: detail, Internal: cause,
	}
}

// Internal reports a fault in the service.
func Internal(cause error) *APIError {
	return &APIError{
		Status: http.StatusInternalServerError, Type: TypeInternal,
		Title: "the service could not complete the request", Internal: cause,
	}
}

// Unavailable reports a dependency being down, such as the database.
func Unavailable(cause error) *APIError {
	return &APIError{
		Status: http.StatusServiceUnavailable, Type: TypeUnavailable,
		Title: "the service is temporarily unavailable", Internal: cause,
	}
}

// WriteProblem sends an APIError as an RFC 9457 response.
//
// Anything that is not an APIError becomes a 500 with no detail, so a new
// handler that returns a bare error cannot accidentally leak its text.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		apiErr = Internal(err)
	}

	requestID := RequestIDFrom(r.Context())
	log := logging.FromContext(r.Context())

	// A fault in the service is logged at error level; a refused request is
	// not. Logging every rejected authentication as an error would bury the
	// faults that need attention under the ordinary noise of an internet
	// facing service.
	attrs := []any{
		slog.Int(logging.KeyStatus, apiErr.Status),
		slog.String("problem_type", apiErr.Type),
	}
	if apiErr.Internal != nil {
		attrs = append(attrs, slog.String("reason", apiErr.Internal.Error()))
	}
	if apiErr.Status >= 500 {
		log.ErrorContext(r.Context(), apiErr.Title, attrs...)
	} else {
		log.InfoContext(r.Context(), "request refused", attrs...)
	}

	body := Problem{
		Type:              apiErr.Type,
		Title:             apiErr.Title,
		Status:            apiErr.Status,
		Detail:            apiErr.Detail,
		RequestID:         requestID,
		RetryAfterSeconds: apiErr.RetryAfterSeconds,
	}

	h := w.Header()
	h.Set("Content-Type", "application/problem+json; charset=utf-8")
	if apiErr.RetryAfterSeconds > 0 {
		h.Set("Retry-After", itoa(apiErr.RetryAfterSeconds))
	}
	if apiErr.Status == http.StatusUnauthorized {
		// RFC 9110 section 11.6.1 requires the challenge on a 401.
		h.Set("WWW-Authenticate", `Bearer realm="n0passtemps"`)
	}

	w.WriteHeader(apiErr.Status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.ErrorContext(r.Context(), "problem response could not be written", slog.Any("error", err))
	}
}

// WriteJSON sends a successful response.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line has already gone out, so the response cannot be
		// changed. Recording it is all that is left.
		logging.FromContext(r.Context()).ErrorContext(r.Context(),
			"response body could not be written", slog.Any("error", err))
	}
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
