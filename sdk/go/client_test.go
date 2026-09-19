package n0passtemps

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testAPIKey = "npt_EXAMPLEONLY0000.EXAMPLE-NOT-A-REAL-KEY"

// awkwardRef holds the characters that break a naive path join: a slash would
// add a segment, a space is not legal in a path, and an at sign is what an
// email address used as a reference would carry.
const (
	awkwardRef        = "team/a b@example.org"
	awkwardRefEscaped = "team%2Fa%20b@example.org"
)

// recorded is what the stub server saw of one request.
type recorded struct {
	method      string
	uri         string
	contentType string
	accept      string
	auth        string
	hasAuth     bool
	userAgent   string
	body        []byte
}

// stub answers every request with one fixed response and records the request.
type stub struct {
	status int
	header map[string]string
	body   string

	hits atomic.Int32
	last atomic.Pointer[recorded]
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	_, hasAuth := r.Header["Authorization"]
	s.last.Store(&recorded{
		method:      r.Method,
		uri:         r.RequestURI,
		contentType: r.Header.Get("Content-Type"),
		accept:      r.Header.Get("Accept"),
		auth:        r.Header.Get("Authorization"),
		hasAuth:     hasAuth,
		userAgent:   r.Header.Get("User-Agent"),
		body:        body,
	})
	for k, v := range s.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(s.status)
	_, _ = io.WriteString(w, s.body)
}

func newStubClient(t *testing.T, s *stub, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testAPIKey, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.retryDelay = time.Millisecond
	return c
}

const (
	subjectJSON = `{"subject_id":"5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c","status":"active",` +
		`"created_at":"2026-09-16T10:00:00Z","credential_count":2,"totp_enrolled":true,"recovery_codes_remaining":7}`
	ceremonyJSON = `{"challenge_id":"0f1d2b3c-4e5f-6a7b-8c9d-0e1f2a3b4c5d",` +
		`"options":{"publicKey":{"challenge":"abc","unknownMember":[1,2,3]}},"expires_at":"2026-09-16T10:05:00Z"}`
	assertionJSON = `{"subject_id":"5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c","assertion":"aaa.bbb.ccc",` +
		`"expires_at":"2026-09-16T10:01:00Z","factors":["webauthn","webauthn-uv"],"signals":{"sign_count_regression":true}}`
	registrationJSON = `{"credential":{"id":"c0ffee00-0000-4000-8000-000000000001","tenant_id":"default",` +
		`"subject_id":"5b0c9d3e-8a41-4f6e-9c27-1d2e3f4a5b6c","credential_id":"AQIDBA==","attestation_type":"none",` +
		`"transports":null,"sign_count":0,"clone_warning":false,"backup_eligible":true,"backup_state":false,` +
		`"user_verified":true,"rp_id":"example.org","created_at":"2026-09-16T10:00:00Z"},"recovery_codes_remaining":0}`
	credentialJSON = `{"id":"cred","rawId":"cred","type":"public-key","response":{"clientDataJSON":"e30","futureMember":true}}`
)

func TestRequestShape(t *testing.T) {
	ctx := context.Background()
	credential := json.RawMessage(credentialJSON)
	const challengeID = "0f1d2b3c-4e5f-6a7b-8c9d-0e1f2a3b4c5d"

	cases := []struct {
		name       string
		status     int
		response   string
		invoke     func(*Client) (any, error)
		wantMethod string
		wantURI    string
		wantBody   string // empty means the request must carry no body
		anonymous  bool
		check      func(*testing.T, any)
	}{
		{
			name: "ResolveSubject", status: 200, response: subjectJSON,
			invoke:     func(c *Client) (any, error) { return c.ResolveSubject(ctx, awkwardRef, "Ada") },
			wantMethod: "POST", wantURI: "/v1/subjects",
			wantBody: `{"subject_ref":"team/a b@example.org","display_name":"Ada"}`,
			check: func(t *testing.T, got any) {
				s := got.(*Subject)
				if s.SubjectID == "" || s.Status != SubjectActive || s.CredentialCount != 2 || !s.TOTPEnrolled || s.RecoveryCodesRemaining != 7 {
					t.Errorf("subject decoded as %+v", s)
				}
			},
		},
		{
			name: "ResolveSubject without display name", status: 200, response: subjectJSON,
			invoke:     func(c *Client) (any, error) { return c.ResolveSubject(ctx, "u-1", "") },
			wantMethod: "POST", wantURI: "/v1/subjects",
			wantBody: `{"subject_ref":"u-1"}`,
		},
		{
			name: "GetSubject", status: 200, response: subjectJSON,
			invoke:     func(c *Client) (any, error) { return c.GetSubject(ctx, awkwardRef) },
			wantMethod: "GET", wantURI: "/v1/subjects/" + awkwardRefEscaped,
		},
		{
			name: "BeginRegistration", status: 200, response: ceremonyJSON,
			invoke:     func(c *Client) (any, error) { return c.BeginRegistration(ctx, awkwardRef, "laptop") },
			wantMethod: "POST", wantURI: "/v1/webauthn/" + awkwardRefEscaped + "/register",
			wantBody: `{"label":"laptop"}`,
			check: func(t *testing.T, got any) {
				cer := got.(*Ceremony)
				// The options must come back byte for byte, unknown members
				// included.
				want := `{"publicKey":{"challenge":"abc","unknownMember":[1,2,3]}}`
				if string(cer.Options) != want {
					t.Errorf("options = %s, want %s", cer.Options, want)
				}
				if cer.ChallengeID != challengeID || cer.ExpiresAt.IsZero() {
					t.Errorf("ceremony decoded as %+v", cer)
				}
			},
		},
		{
			name: "BeginRegistration without label", status: 200, response: ceremonyJSON,
			invoke:     func(c *Client) (any, error) { return c.BeginRegistration(ctx, "u-1", "") },
			wantMethod: "POST", wantURI: "/v1/webauthn/u-1/register",
		},
		{
			name: "CompleteRegistration", status: 201, response: registrationJSON,
			invoke: func(c *Client) (any, error) {
				return c.CompleteRegistration(ctx, awkwardRef, challengeID, credential)
			},
			wantMethod: "POST", wantURI: "/v1/webauthn/" + awkwardRefEscaped + "/register/complete",
			wantBody: `{"challenge_id":"` + challengeID + `","credential":` + credentialJSON + `}`,
			check: func(t *testing.T, got any) {
				reg := got.(*Registration)
				if string(reg.Credential.CredentialID) != "\x01\x02\x03\x04" || !reg.Credential.UserVerified || reg.Credential.RPID != "example.org" {
					t.Errorf("registration decoded as %+v", reg)
				}
			},
		},
		{
			name: "BeginAssertion", status: 200, response: ceremonyJSON,
			invoke:     func(c *Client) (any, error) { return c.BeginAssertion(ctx, awkwardRef) },
			wantMethod: "POST", wantURI: "/v1/webauthn/" + awkwardRefEscaped + "/assert",
		},
		{
			name: "CompleteAssertion", status: 200, response: assertionJSON,
			invoke: func(c *Client) (any, error) {
				return c.CompleteAssertion(ctx, awkwardRef, challengeID, credential)
			},
			wantMethod: "POST", wantURI: "/v1/webauthn/" + awkwardRefEscaped + "/assert/complete",
			wantBody: `{"challenge_id":"` + challengeID + `","credential":` + credentialJSON + `}`,
			check: func(t *testing.T, got any) {
				res := got.(*AssertionResult)
				if res.Assertion != "aaa.bbb.ccc" || len(res.Factors) != 2 || res.Factors[1] != FactorWebAuthnUV || res.Signals["sign_count_regression"] != true {
					t.Errorf("assertion result decoded as %+v", res)
				}
			},
		},
		{
			name: "EnrolTOTP", status: 201,
			response: `{"secret_id":"s1","secret":"JBSWY3DPEHPK3PXP","provisioning_uri":"otpauth://totp/x","algorithm":"SHA1","digits":6,"period_seconds":30,"expires_at":"2026-09-16T10:15:00Z"}`,
			invoke:   func(c *Client) (any, error) { return c.EnrolTOTP(ctx, awkwardRef) },
			// The British spelling is the canonical route; "enroll" is an alias.
			wantMethod: "POST", wantURI: "/v1/totp/" + awkwardRefEscaped + "/enrol",
			check: func(t *testing.T, got any) {
				e := got.(*TOTPEnrolment)
				if e.Secret != "JBSWY3DPEHPK3PXP" || e.Digits != 6 || e.PeriodSeconds != 30 {
					t.Errorf("enrolment decoded as %+v", e)
				}
			},
		},
		{
			name: "ConfirmTOTP", status: 200, response: `{"secret_id":"s1","confirmed":true}`,
			invoke:     func(c *Client) (any, error) { return c.ConfirmTOTP(ctx, awkwardRef, "123456") },
			wantMethod: "POST", wantURI: "/v1/totp/" + awkwardRefEscaped + "/enrol/confirm",
			wantBody: `{"code":"123456"}`,
			check: func(t *testing.T, got any) {
				if !got.(*TOTPConfirmation).Confirmed {
					t.Error("confirmed = false")
				}
			},
		},
		{
			name: "VerifyTOTP", status: 200, response: assertionJSON,
			invoke:     func(c *Client) (any, error) { return c.VerifyTOTP(ctx, awkwardRef, "654321") },
			wantMethod: "POST", wantURI: "/v1/totp/" + awkwardRefEscaped + "/verify",
			wantBody: `{"code":"654321"}`,
		},
		{
			name: "IssueRecoveryCodes", status: 201,
			response:   `{"batch_id":"b1","codes":["AAAAA-BBBBB","CCCCC-DDDDD"],"count":2,"warning":"show them now"}`,
			invoke:     func(c *Client) (any, error) { return c.IssueRecoveryCodes(ctx, awkwardRef) },
			wantMethod: "POST", wantURI: "/v1/recovery/" + awkwardRefEscaped + "/issue",
			check: func(t *testing.T, got any) {
				codes := got.(*RecoveryCodes)
				if len(codes.Codes) != 2 || codes.Count != 2 || codes.Warning == "" {
					t.Errorf("recovery codes decoded as %+v", codes)
				}
			},
		},
		{
			name: "ConsumeRecoveryCode", status: 200,
			response: `{"subject_id":"s","assertion":"aaa.bbb.ccc","expires_at":"2026-09-16T10:01:00Z","factors":["recovery-code"],"recovery_codes_remaining":3}`,
			invoke: func(c *Client) (any, error) {
				return c.ConsumeRecoveryCode(ctx, awkwardRef, "aaaaa-bbbbb")
			},
			wantMethod: "POST", wantURI: "/v1/recovery/" + awkwardRefEscaped + "/consume",
			wantBody: `{"code":"aaaaa-bbbbb"}`,
			check: func(t *testing.T, got any) {
				res := got.(*RecoveryResult)
				if res.Assertion != "aaa.bbb.ccc" || res.RecoveryCodesRemaining != 3 || res.Factors[0] != FactorRecoveryCode {
					t.Errorf("recovery result decoded as %+v", res)
				}
			},
		},
		{
			name: "Health", status: 200, response: `{"status":"ok"}`,
			invoke:     func(c *Client) (any, error) { return c.Health(ctx) },
			wantMethod: "GET", wantURI: "/v1/health", anonymous: true,
			check: func(t *testing.T, got any) {
				if got.(*Liveness).Status != HealthOK {
					t.Errorf("liveness = %+v", got)
				}
			},
		},
		{
			name: "HealthDetail", status: 200,
			response: `{"status":"degraded","version":{"version":"1.0.0"},"uptime_seconds":42,` +
				`"database":{"status":"ok","engine":"sqlite","latency_ms":1},` +
				`"kek":{"status":"degraded","current_version":3,"retained_versions":2,"rotation_overdue":true},` +
				`"audit":{"status":"ok","head_seq":99},"open_alerts":{"info":0,"warning":2,"critical":0},` +
				`"features":{"throttle":true},"timestamp":"2026-09-16T10:00:00Z"}`,
			invoke:     func(c *Client) (any, error) { return c.HealthDetail(ctx) },
			wantMethod: "GET", wantURI: "/v1/health/detail",
			check: func(t *testing.T, got any) {
				r := got.(*HealthReport)
				if r.Status != HealthDegraded || r.Version.Version != "1.0.0" || r.KEK.CurrentVersion != 3 ||
					!r.KEK.RotationOverdue || r.TLS != nil || r.OpenAlerts["warning"] != 2 || !r.Features["throttle"] || r.Audit.HeadSeq != 99 {
					t.Errorf("health report decoded as %+v", r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stub{status: tc.status, body: tc.response}
			c := newStubClient(t, s, WithUserAgent("acme-portal/2.1"))

			got, err := tc.invoke(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			req := s.last.Load()
			if req == nil {
				t.Fatal("the server saw no request")
			}

			if req.method != tc.wantMethod {
				t.Errorf("method = %s, want %s", req.method, tc.wantMethod)
			}
			if req.uri != tc.wantURI {
				t.Errorf("request URI = %s, want %s", req.uri, tc.wantURI)
			}
			// The server answers 415 to a write without this header, bodyless
			// or not, so it is checked on every call.
			if req.contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", req.contentType)
			}
			if !strings.Contains(req.accept, "application/json") {
				t.Errorf("Accept = %q", req.accept)
			}
			if req.userAgent != "acme-portal/2.1" {
				t.Errorf("User-Agent = %q", req.userAgent)
			}
			if tc.anonymous {
				if req.hasAuth {
					t.Errorf("an anonymous route was sent Authorization %q", req.auth)
				}
			} else if req.auth != "Bearer "+testAPIKey {
				t.Errorf("Authorization = %q", req.auth)
			}
			if string(req.body) != tc.wantBody {
				t.Errorf("body = %s, want %s", req.body, tc.wantBody)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestDefaultUserAgent(t *testing.T) {
	s := &stub{status: 200, body: `{"status":"ok"}`}
	c := newStubClient(t, s)
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := s.last.Load().userAgent, "n0passtemps-go/"+Version; got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}

func TestBasePathPrefixIsKept(t *testing.T) {
	s := &stub{status: 200, body: subjectJSON}
	srv := httptest.NewServer(s)
	defer srv.Close()

	c, err := New(srv.URL+"/auth/", testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSubject(context.Background(), "u-1"); err != nil {
		t.Fatal(err)
	}
	if got := s.last.Load().uri; got != "/auth/v1/subjects/u-1" {
		t.Errorf("request URI = %s", got)
	}
}

func TestSubjectReferenceIsValidatedLocally(t *testing.T) {
	s := &stub{status: 200, body: subjectJSON}
	c := newStubClient(t, s)
	ctx := context.Background()

	for _, ref := range []string{"", ".", ".."} {
		if _, err := c.GetSubject(ctx, ref); err == nil {
			t.Errorf("GetSubject(%q) succeeded", ref)
		}
		if _, err := c.BeginAssertion(ctx, ref); err == nil {
			t.Errorf("BeginAssertion(%q) succeeded", ref)
		}
	}
	if _, err := c.ResolveSubject(ctx, "", ""); err == nil {
		t.Error("ResolveSubject with an empty reference succeeded")
	}
	if _, err := c.CompleteAssertion(ctx, "u-1", "", json.RawMessage(`{}`)); err == nil {
		t.Error("CompleteAssertion with an empty challenge succeeded")
	}
	if _, err := c.CompleteAssertion(ctx, "u-1", "x", json.RawMessage(`{"truncated":`)); err == nil {
		t.Error("CompleteAssertion with malformed credential JSON succeeded")
	}
	if _, err := c.CompleteRegistration(ctx, "u-1", "x", nil); err == nil {
		t.Error("CompleteRegistration with a nil credential succeeded")
	}
	if n := s.hits.Load(); n != 0 {
		t.Errorf("%d requests reached the server", n)
	}
}

func TestResponseBodySizeLimit(t *testing.T) {
	ctx := context.Background()

	t.Run("a body above the limit is refused", func(t *testing.T) {
		padding := strings.Repeat("a", maxResponseBytes)
		s := &stub{status: 200, body: `{"status":"ok","padding":"` + padding + `"}`}
		c := newStubClient(t, s)
		_, err := c.Health(ctx)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("an oversized error body is refused too", func(t *testing.T) {
		s := &stub{status: 500, body: strings.Repeat("<p>no</p>", maxResponseBytes/4)}
		c := newStubClient(t, s)
		_, err := c.Health(ctx)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("a body at the limit is read", func(t *testing.T) {
		envelope := `{"status":"ok","padding":""}`
		padding := strings.Repeat("a", maxResponseBytes-len(envelope))
		s := &stub{status: 200, body: `{"status":"ok","padding":"` + padding + `"}`}
		c := newStubClient(t, s)
		if _, err := c.Health(ctx); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestNewTransportRule(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		opts    []Option
		wantErr bool
	}{
		{name: "https", url: "https://auth.example.org"},
		{name: "https with port and prefix", url: "https://auth.example.org:8443/n0/"},
		{name: "http to a named host", url: "http://auth.example.org", wantErr: true},
		{name: "http to a private address", url: "http://192.168.1.20:8080", wantErr: true},
		{name: "http to a name that merely starts with localhost", url: "http://localhost.example.org", wantErr: true},
		{name: "http to localhost", url: "http://localhost:8080"},
		{name: "http to 127.0.0.1", url: "http://127.0.0.1:8080"},
		{name: "http elsewhere in 127/8", url: "http://127.8.9.10:8080"},
		{name: "http to the IPv6 loopback", url: "http://[::1]:8080"},
		{name: "http with the explicit option", url: "http://auth.internal:8080", opts: []Option{WithInsecureTransport()}},
		{name: "another scheme", url: "ftp://auth.example.org", wantErr: true},
		{name: "another scheme with the option", url: "ftp://auth.example.org", opts: []Option{WithInsecureTransport()}, wantErr: true},
		{name: "no scheme", url: "auth.example.org", wantErr: true},
		{name: "empty", url: "", wantErr: true},
		{name: "credentials in the URL", url: "https://user:secret@auth.example.org", wantErr: true},
		{name: "query", url: "https://auth.example.org/?x=1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.url, testAPIKey, tc.opts...)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%q) succeeded", tc.url)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Errorf("the error repeats the URL credentials: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q): %v", tc.url, err)
			}
			if c == nil {
				t.Fatal("nil client without an error")
			}
		})
	}
}

func TestNewRefusesBadConfiguration(t *testing.T) {
	const base = "https://auth.example.org"
	if _, err := New(base, ""); err == nil {
		t.Error("an empty API key was accepted")
	}
	if _, err := New(base, "  "); err == nil {
		t.Error("a blank API key was accepted")
	}
	if _, err := New(base, testAPIKey, WithHTTPClient(nil)); err == nil {
		t.Error("a nil HTTP client was accepted")
	}
	if _, err := New(base, testAPIKey, WithTimeout(-time.Second)); err == nil {
		t.Error("a negative timeout was accepted")
	}
	if _, err := New(base, testAPIKey, WithRetries(-1)); err == nil {
		t.Error("a negative retry count was accepted")
	}
}

func TestTimeoutAppliesToEachAttempt(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c, err := New(srv.URL, testAPIKey, WithTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.GetSubject(context.Background(), awkwardRef)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the call took %s", elapsed)
	}
	// The reference travels in the path, and an error string is what gets
	// logged.
	if strings.Contains(err.Error(), "example.org") || strings.Contains(err.Error(), srv.URL) {
		t.Errorf("the error repeats the request URL: %v", err)
	}
}

func TestCustomHTTPClientIsUsed(t *testing.T) {
	s := &stub{status: 200, body: `{"status":"ok"}`}
	srv := httptest.NewServer(s)
	defer srv.Close()

	var used atomic.Bool
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Store(true)
		return http.DefaultTransport.RoundTrip(r)
	})}
	c, err := New(srv.URL, testAPIKey, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !used.Load() {
		t.Error("the supplied HTTP client was not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRedirectsAreNotFollowed(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, subjectJSON)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/subjects/u-1", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c, err := New(origin.URL, testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetSubject(context.Background(), "u-1")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want an *Error with status 307", err)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("the redirect target received %d requests", n)
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{
		1:   200 * time.Millisecond,
		2:   400 * time.Millisecond,
		3:   800 * time.Millisecond,
		6:   retryMaxDelay,
		500: retryMaxDelay, // a plain shift would have overflowed long before
	}
	for attempt, want := range cases {
		if got := backoff(retryBaseDelay, attempt); got != want {
			t.Errorf("backoff(attempt %d) = %s, want %s", attempt, got, want)
		}
	}
}
