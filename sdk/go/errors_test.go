package n0passtemps

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var allSentinels = []error{
	ErrUnauthorized, ErrForbidden, ErrNotFound, ErrConflict,
	ErrAuthenticationFailed, ErrThrottled, ErrUnavailable,
}

func problemJSON(problemType, title string, status int, extra string) string {
	body := `{"type":"` + problemType + `","title":"` + title + `","status":` + itoa(status) + `,"request_id":"9f2a1c7b5d3e4f60a1b2c3d4"`
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestProblemDecoding(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		header     map[string]string
		want       error // the one sentinel that must match, nil for none
		wantType   string
		wantTitle  string
		wantDetail string
		wantRetry  time.Duration
	}{
		{
			name: "unauthorized", status: 401,
			body: problemJSON(TypeUnauthorized, "authentication is required", 401, ""),
			want: ErrUnauthorized, wantType: TypeUnauthorized, wantTitle: "authentication is required",
		},
		{
			name: "forbidden", status: 403,
			body: problemJSON(TypeForbidden, "this credential is not permitted to perform that operation", 403, ""),
			want: ErrForbidden, wantType: TypeForbidden, wantTitle: "this credential is not permitted to perform that operation",
		},
		{
			name: "not found", status: 404,
			body: problemJSON(TypeNotFound, "the resource does not exist", 404, ""),
			want: ErrNotFound, wantType: TypeNotFound, wantTitle: "the resource does not exist",
		},
		{
			name: "conflict", status: 409,
			body: problemJSON(TypeConflict, "the request conflicts with the current state", 409, `"detail":"the enrolment has expired"`),
			want: ErrConflict, wantType: TypeConflict, wantTitle: "the request conflicts with the current state",
			wantDetail: "the enrolment has expired",
		},
		{
			// Same status as a refused API key. Only the type tells them apart.
			name: "ceremony failed", status: 401,
			body: problemJSON(TypeCeremonyFailed, "authentication did not succeed", 401, ""),
			want: ErrAuthenticationFailed, wantType: TypeCeremonyFailed, wantTitle: "authentication did not succeed",
		},
		{
			name: "throttled", status: 429,
			body:   problemJSON(TypeThrottled, "too many attempts", 429, `"retry_after_seconds":17`),
			header: map[string]string{"Retry-After": "17"},
			want:   ErrThrottled, wantType: TypeThrottled, wantTitle: "too many attempts", wantRetry: 17 * time.Second,
		},
		{
			name: "unavailable", status: 503,
			body: problemJSON(TypeUnavailable, "the service is temporarily unavailable", 503, ""),
			want: ErrUnavailable, wantType: TypeUnavailable, wantTitle: "the service is temporarily unavailable",
		},
		{
			name: "bad request matches no sentinel", status: 400,
			body:     problemJSON(TypeBadRequest, "the request is not valid", 400, `"detail":"challenge_id is required"`),
			wantType: TypeBadRequest, wantTitle: "the request is not valid", wantDetail: "challenge_id is required",
		},
		{
			name: "internal matches no sentinel", status: 500,
			body:     problemJSON(TypeInternal, "the service could not complete the request", 500, ""),
			wantType: TypeInternal, wantTitle: "the service could not complete the request",
		},
		{
			// A proxy answered, so there is no type and the status decides.
			name: "untyped 503 from a proxy", status: 503,
			body: "<html><body>upstream down</body></html>",
			want: ErrUnavailable, wantTitle: "Service Unavailable",
		},
		{
			name: "untyped 401 is the key, never the ceremony", status: 401,
			body: "",
			want: ErrUnauthorized, wantTitle: "Unauthorized",
		},
		{
			name: "liveness 503 carries a plain JSON body", status: 503,
			body: `{"status":"error"}`,
			want: ErrUnavailable, wantTitle: "Service Unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := map[string]string{"Content-Type": "application/problem+json; charset=utf-8"}
			for k, v := range tc.header {
				header[k] = v
			}
			s := &stub{status: tc.status, header: header, body: tc.body}
			c := newStubClient(t, s)

			_, err := c.VerifyTOTP(context.Background(), "u-1", "000000")
			if err == nil {
				t.Fatal("no error")
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("err is %T, want *Error", err)
			}
			if apiErr.Status != tc.status || apiErr.Type != tc.wantType || apiErr.Title != tc.wantTitle || apiErr.Detail != tc.wantDetail {
				t.Errorf("decoded as %+v", apiErr)
			}
			if apiErr.RetryAfter != tc.wantRetry {
				t.Errorf("RetryAfter = %s, want %s", apiErr.RetryAfter, tc.wantRetry)
			}
			for _, sentinel := range allSentinels {
				if got, want := errors.Is(err, sentinel), sentinel == tc.want; got != want {
					t.Errorf("errors.Is(err, %q) = %v, want %v", sentinel, got, want)
				}
			}
			if strings.Contains(err.Error(), "<html>") {
				t.Errorf("the error echoes a foreign body: %v", err)
			}
		})
	}
}

func TestRequestIDSources(t *testing.T) {
	ctx := context.Background()

	t.Run("from the body", func(t *testing.T) {
		s := &stub{status: 404, body: problemJSON(TypeNotFound, "the resource does not exist", 404, "")}
		_, err := newStubClient(t, s).GetSubject(ctx, "u-1")
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.RequestID != "9f2a1c7b5d3e4f60a1b2c3d4" {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), "9f2a1c7b5d3e4f60a1b2c3d4") {
			t.Errorf("the message omits the request identifier: %v", err)
		}
	})

	t.Run("from the header when the body has none", func(t *testing.T) {
		s := &stub{status: 502, header: map[string]string{"X-Request-Id": "fromheader01"}, body: "bad gateway"}
		_, err := newStubClient(t, s).GetSubject(ctx, "u-1")
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.RequestID != "fromheader01" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestStatusLineWinsOverBodyStatus(t *testing.T) {
	s := &stub{status: 403, body: problemJSON(TypeForbidden, "no", 200, "")}
	_, err := newStubClient(t, s).GetSubject(context.Background(), "u-1")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		value string
		want  time.Duration
	}{
		{"", 0},
		{"1", time.Second},
		{" 30 ", 30 * time.Second},
		{"3600", time.Hour},
		{"0", 0},
		{"-5", 0},
		{"1.5", 0},
		{"soon", 0},
		{"99999999999999999999", 0},
		{"Wed, 16 Sep 2026 12:00:45 GMT", 45 * time.Second},
		{"Wed, 16 Sep 2026 11:59:00 GMT", 0},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.value, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.value, got, tc.want)
		}
	}
}

func TestRetryAfterFallsBackOnTheBody(t *testing.T) {
	s := &stub{status: 429, body: problemJSON(TypeThrottled, "too many attempts", 429, `"retry_after_seconds":8`)}
	_, err := newStubClient(t, s).VerifyTOTP(context.Background(), "u-1", "000000")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 8*time.Second {
		t.Fatalf("err = %v", err)
	}
}

// sequence answers each request with the next status of a list, then repeats
// the last one.
type sequence struct {
	statuses []int
	hits     atomic.Int32
}

func (s *sequence) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := int(s.hits.Add(1)) - 1
	if n >= len(s.statuses) {
		n = len(s.statuses) - 1
	}
	status := s.statuses[n]
	if status == 200 {
		_, _ = w.Write([]byte(subjectJSON))
		return
	}
	problemType := map[int]string{401: TypeCeremonyFailed, 429: TypeThrottled, 503: TypeUnavailable}[status]
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(problemJSON(problemType, "refused", status, "")))
}

func newSequenceClient(t *testing.T, s *sequence, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testAPIKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	c.retryDelay = time.Millisecond
	return c
}

func TestRetryPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing is retried by default", func(t *testing.T) {
		s := &sequence{statuses: []int{503, 200}}
		_, err := newSequenceClient(t, s).GetSubject(ctx, "u-1")
		if !errors.Is(err, ErrUnavailable) || s.hits.Load() != 1 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})

	t.Run("an idempotent call is retried on 503", func(t *testing.T) {
		s := &sequence{statuses: []int{503, 503, 200}}
		sub, err := newSequenceClient(t, s, WithRetries(2)).GetSubject(ctx, "u-1")
		if err != nil || sub == nil || s.hits.Load() != 3 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})

	t.Run("the retry budget is respected", func(t *testing.T) {
		s := &sequence{statuses: []int{503}}
		_, err := newSequenceClient(t, s, WithRetries(2)).ResolveSubject(ctx, "u-1", "")
		if !errors.Is(err, ErrUnavailable) || s.hits.Load() != 3 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})

	t.Run("a non-idempotent call is never retried", func(t *testing.T) {
		calls := map[string]func(*Client) error{
			"BeginRegistration": func(c *Client) error { _, err := c.BeginRegistration(ctx, "u-1", ""); return err },
			"CompleteRegistration": func(c *Client) error {
				_, err := c.CompleteRegistration(ctx, "u-1", "x", json.RawMessage(`{}`))
				return err
			},
			"BeginAssertion": func(c *Client) error { _, err := c.BeginAssertion(ctx, "u-1"); return err },
			"CompleteAssertion": func(c *Client) error {
				_, err := c.CompleteAssertion(ctx, "u-1", "x", json.RawMessage(`{}`))
				return err
			},
			"EnrolTOTP":           func(c *Client) error { _, err := c.EnrolTOTP(ctx, "u-1"); return err },
			"ConfirmTOTP":         func(c *Client) error { _, err := c.ConfirmTOTP(ctx, "u-1", "000000"); return err },
			"VerifyTOTP":          func(c *Client) error { _, err := c.VerifyTOTP(ctx, "u-1", "000000"); return err },
			"IssueRecoveryCodes":  func(c *Client) error { _, err := c.IssueRecoveryCodes(ctx, "u-1"); return err },
			"ConsumeRecoveryCode": func(c *Client) error { _, err := c.ConsumeRecoveryCode(ctx, "u-1", "aaaaa"); return err },
		}
		for name, invoke := range calls {
			s := &sequence{statuses: []int{503, 200}}
			err := invoke(newSequenceClient(t, s, WithRetries(5)))
			if !errors.Is(err, ErrUnavailable) || s.hits.Load() != 1 {
				t.Errorf("%s: err = %v after %d requests", name, err, s.hits.Load())
			}
		}
	})

	t.Run("an authentication failure is never retried", func(t *testing.T) {
		s := &sequence{statuses: []int{401, 200}}
		_, err := newSequenceClient(t, s, WithRetries(5)).GetSubject(ctx, "u-1")
		if !errors.Is(err, ErrAuthenticationFailed) || s.hits.Load() != 1 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})

	t.Run("a throttled call is never retried", func(t *testing.T) {
		s := &sequence{statuses: []int{429, 200}}
		_, err := newSequenceClient(t, s, WithRetries(5)).GetSubject(ctx, "u-1")
		if !errors.Is(err, ErrThrottled) || s.hits.Load() != 1 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})

	t.Run("a cancelled context stops the retries", func(t *testing.T) {
		s := &sequence{statuses: []int{503}}
		c := newSequenceClient(t, s, WithRetries(50))
		c.retryDelay = time.Hour
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		_, err := c.GetSubject(cctx, "u-1")
		if !errors.Is(err, context.DeadlineExceeded) || s.hits.Load() != 1 {
			t.Fatalf("err = %v after %d requests", err, s.hits.Load())
		}
	})
}

func TestErrorMessage(t *testing.T) {
	e := &Error{Status: 409, Type: TypeConflict, Title: "the request conflicts with the current state", Detail: "expired", RequestID: "abc"}
	want := "n0passtemps: 409 the request conflicts with the current state: expired [urn:n0passtemps:error:conflict] (request abc)"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
