package api

import (
	"context"

	"github.com/Socold/n0passtemps/internal/store"
)

// contextKey is an unexported type so no other package can write a value this
// package would read, which is what makes the caller identity below
// trustworthy inside a handler.
type contextKey struct{ name string }

var (
	requestIDKey = &contextKey{"request-id"}
	callerKey    = &contextKey{"caller"}
	sourceIPKey  = &contextKey{"source-ip"}
)

// Caller is the authenticated identity behind a request.
//
// Exactly one of APIKey or AdminToken is set. The middleware that authenticates
// the request is the only writer, and it runs before any handler, so a handler
// can treat a present Caller as proof that authentication succeeded rather than
// re-checking.
type Caller struct {
	TenantID string

	APIKey     *store.APIKey
	AdminToken *store.AdminToken
}

// IsAdmin reports whether the caller authenticated on the administrative
// surface.
func (c *Caller) IsAdmin() bool { return c != nil && c.AdminToken != nil }

// Role returns the administrative role, or the empty role for an API key.
func (c *Caller) Role() store.Role {
	if c == nil || c.AdminToken == nil {
		return ""
	}
	return c.AdminToken.Role
}

// ActorType maps the caller onto the audit vocabulary.
func (c *Caller) ActorType() store.ActorType {
	switch {
	case c == nil:
		return store.ActorSystem
	case c.AdminToken != nil:
		return store.ActorAdmin
	case c.APIKey != nil:
		return store.ActorAPIKey
	default:
		return store.ActorSystem
	}
}

// ActorID returns the identifier recorded on an audit entry.
//
// It is the credential's own identifier, not its name and never its secret, so
// that revoking a credential does not make the history of what it did
// ambiguous.
func (c *Caller) ActorID() string {
	switch {
	case c == nil:
		return ""
	case c.AdminToken != nil:
		return c.AdminToken.ID
	case c.APIKey != nil:
		return c.APIKey.ID
	default:
		return ""
	}
}

// withRequestID attaches the request identifier.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFrom returns the request identifier, or an empty string.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// withCaller attaches the authenticated identity.
func withCaller(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerKey, c)
}

// CallerFrom returns the authenticated identity, or nil.
//
// A handler behind the authentication middleware can rely on this being
// non-nil. It returns nil rather than panicking so that a route mounted without
// that middleware fails as an authorisation refusal instead of taking the
// process down.
func CallerFrom(ctx context.Context) *Caller {
	if v, ok := ctx.Value(callerKey).(*Caller); ok {
		return v
	}
	return nil
}

// withSourceIP attaches the resolved client address.
func withSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey, ip)
}

// SourceIPFrom returns the resolved client address.
//
// This is the value the rate limiter keys on and the value written to audit
// entries, so it is resolved once by the middleware rather than re-derived from
// headers by each caller. See resolveSourceIP for why a forwarded header is
// only honoured from a configured proxy.
func SourceIPFrom(ctx context.Context) string {
	if v, ok := ctx.Value(sourceIPKey).(string); ok {
		return v
	}
	return ""
}
