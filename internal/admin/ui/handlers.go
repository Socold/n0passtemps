package ui

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/crypto/recovery"
	"github.com/Socold/n0passtemps/internal/rbac"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/throttle"
)

// The interface is six screens and a dashboard, and stays that way.
//
// ADR 0012 counted six screens as the reason a single-page application was not
// worth its build toolchain, and the specification required that an operator
// never needs more than three clicks and is never shown technical vocabulary. A
// seventh screen erodes both. Anything genuinely new belongs on the API surface,
// where the audience is an integrating application rather than a person handling
// a support call.
//
//	/admin/            dashboard: is the service healthy, what needs attention
//	/admin/sign-in     paste an administrative token
//	/admin/subjects    the people this deployment authenticates
//	/admin/subjects/id one person, their factors and the actions available
//	/admin/audit       the history, with filters and a check of its integrity
//	/admin/alerts      conditions worth looking at
//	/admin/approvals   changes waiting for a second administrator

// pageData is what every template receives.
//
// It is one struct rather than a map so that a misspelled field in a template is
// a rendering error rather than a silently empty value. An empty value in a
// template that decides whether to show a control would hide the control, and a
// hidden control is a bug an operator reports as "the button is missing" rather
// than something a test catches.
type pageData struct {
	Title    string
	Tenant   string
	Path     string
	Assets   assetRefs
	CSRF     string
	SignedIn bool
	Operator operatorView
	Can      permissions
	Notice   string
	Problem  string
	Data     any
}

// operatorView is what the page says about who is signed in.
//
// The administrative token is never part of it. Only the name the operator gave
// the token and the authority it carries, which is what they need in order to
// know why an action is or is not offered.
type operatorView struct {
	TokenName string
	RoleLabel string
}

// permissions mirrors the decisions rbac has already made, so a template asks a
// question rather than making one.
type permissions struct {
	ReadPerson            bool
	BlockSignIn           bool
	AllowSignIn           bool
	WithdrawAuthenticator bool
	IssueRecoveryCodes    bool
	ClearSignInLimit      bool
	CheckHistory          bool
	AcknowledgeAlert      bool
	DecideRequest         bool
}

// roleLabels name the three roles in words that describe what the holder can do
// rather than what the configuration calls them.
var roleLabels = map[store.Role]string{
	store.RoleFull:     "Full administrator",
	store.RoleOperator: "Support operator",
	store.RoleAuditor:  "Read only",
}

func roleLabel(r store.Role) string {
	if l, ok := roleLabels[r]; ok {
		return l
	}
	return "Unknown"
}

// notices are the confirmations shown after an action.
//
// They are looked up from a fixed table by key. Putting the sentence itself in
// the redirect would mean rendering text an attacker could choose, and while
// html/template would escape it, a page that repeats whatever the URL says is a
// convincing place to put a misleading instruction.
var notices = map[string]string{
	"signed-out":            "You have signed out.",
	"sign-in-blocked":       "This person can no longer sign in.",
	"sign-in-allowed":       "This person can sign in again.",
	"limit-cleared":         "The sign-in limit for this person has been cleared.",
	"authenticator-removed": "The security key or passkey has been withdrawn.",
	"alert-acknowledged":    "The alert has been marked as seen.",
	"request-approved":      "The request has been approved.",
	"request-rejected":      "The request has been rejected.",
	"passkey-added":         "The passkey has been added to your sign-in.",
	"passkey-withdrawn":     "The passkey has been withdrawn from your sign-in.",
}

// statusLabels describe a person's state without naming the column value.
var statusLabels = map[store.SubjectStatus]string{
	store.SubjectActive:          "Can sign in",
	store.SubjectLocked:          "Blocked from signing in",
	store.SubjectPendingDeletion: "Waiting to be deleted",
}

func statusLabel(s store.SubjectStatus) string {
	if l, ok := statusLabels[s]; ok {
		return l
	}
	return string(s)
}

// approvalStatusLabels describe where a queued change has got to.
var approvalStatusLabels = map[store.ApprovalStatus]string{
	store.ApprovalPending:  "Waiting for a second administrator",
	store.ApprovalApproved: "Approved",
	store.ApprovalRejected: "Rejected",
	store.ApprovalExpired:  "Expired without a decision",
	store.ApprovalExecuted: "Carried out",
	store.ApprovalFailed:   "Could not be carried out",
}

func approvalStatusLabel(s store.ApprovalStatus) string {
	if l, ok := approvalStatusLabels[s]; ok {
		return l
	}
	return string(s)
}

// newPage assembles the common part of every screen.
//
// The permission set is filled in here, once, from the session's role. Computing
// it in each handler would eventually produce a screen that asked a different
// question from the one its handler enforces.
func (h *Handler) newPage(r *http.Request, sess *session, title string) *pageData {
	pd := &pageData{
		Title:  title,
		Tenant: h.deps.Config.Tenant.Name,
		Path:   r.URL.Path,
		Assets: h.assetRefs,
	}
	if key := r.URL.Query().Get("notice"); key != "" {
		pd.Notice = notices[key]
	}
	if sess == nil {
		return pd
	}

	pd.SignedIn = true
	pd.CSRF = sess.csrf
	pd.Operator = operatorView{
		TokenName: sess.TokenName,
		RoleLabel: roleLabel(sess.Role),
	}
	pd.Can = permissions{
		ReadPerson:            h.allowed(sess.Role, rbac.PermSubjectRead),
		BlockSignIn:           h.allowed(sess.Role, rbac.PermSubjectLock),
		AllowSignIn:           h.allowed(sess.Role, rbac.PermSubjectUnlock),
		WithdrawAuthenticator: h.allowed(sess.Role, rbac.PermCredentialRevoke),
		IssueRecoveryCodes:    h.allowed(sess.Role, rbac.PermRecoveryReissue),
		ClearSignInLimit:      h.allowed(sess.Role, rbac.PermThrottleReset),
		CheckHistory:          h.allowed(sess.Role, rbac.PermAuditVerify),
		AcknowledgeAlert:      h.allowed(sess.Role, rbac.PermAlertAcknowledge),
		DecideRequest:         h.allowed(sess.Role, rbac.PermApprovalDecide),
	}
	return pd
}

// renderMessage shows a refusal or a not-found in the same frame as the rest of
// the interface, so the operator keeps the navigation and knows where they are.
func (h *Handler) renderMessage(w http.ResponseWriter, r *http.Request, sess *session, status int, heading, body string) {
	pd := h.newPage(r, sess, heading)
	pd.Data = messageData{Heading: heading, Body: body}
	h.render(w, r, status, "message", pd)
}

type messageData struct {
	Heading string
	Body    string
}

// renderSignInRefusal shows the sign-in form again with a reason.
//
// The status is 401 rather than 200, so a monitoring check or a log line records
// the refusal even though the body is a form rather than an error document.
func (h *Handler) renderSignInRefusal(w http.ResponseWriter, r *http.Request, problem string) {
	pd := h.newPage(r, nil, "Sign in")
	pd.Problem = problem
	pd.Data = signInData{PasskeyOffered: h.passkeysOffered()}
	h.render(w, r, http.StatusUnauthorized, "signin", pd)
}

// handleNotFound answers a path the interface does not serve.
func (h *Handler) handleNotFound(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.sessions.get(h.now().UTC(), cookieValue(r), h.idleTTL, h.absoluteTTL)
	h.renderMessage(w, r, sess, http.StatusNotFound, "That page does not exist",
		"Use the navigation above to get back to a screen that does.")
}

// audited records an event, logging rather than failing when the append does not
// work.
//
// A handler that has already changed state cannot be undone by a failed audit
// append, so the choice is between losing the record and losing the change. The
// failure is logged at error level, because an audit log that has started
// dropping entries is itself an incident.
func (h *Handler) audited(w http.ResponseWriter, r *http.Request, ev audit.Event) {
	ctx := r.Context()
	if ev.SourceIP == "" {
		ev.SourceIP = h.sourceIP(r)
	}
	if ev.RequestID == "" {
		// The surrounding middleware assigns the identifier and echoes it on the
		// response, so the response header is where a handler reads it back. The
		// request header is not used: a client may set it to anything, and the
		// sanitised value is the one on the way out.
		ev.RequestID = w.Header().Get("X-Request-Id")
	}
	if err := h.deps.Recorder.Record(ctx, ev); err != nil {
		h.deps.Logger.ErrorContext(ctx, "adminui: event not audited",
			slog.String("event_type", ev.EventType), slog.Any("error", err))
	}
}

// auditDenied records a refused action.
//
// A refusal is audited for the same reason a success is: an operator probing for
// authority they do not hold looks exactly like an operator who mistyped a URL,
// and only the pattern over time tells the two apart.
func (h *Handler) auditDenied(w http.ResponseWriter, r *http.Request, sess *session, resourceType, resourceID, reason string) {
	h.audited(w, r, audit.Event{
		TenantID:     sess.TenantID,
		EventType:    audit.EventAdminDenied,
		ActorType:    store.ActorAdmin,
		ActorID:      sess.TokenID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      store.OutcomeDenied,
		Detail: map[string]any{
			"role":    string(sess.Role),
			"reason":  reason,
			"surface": "administration interface",
		},
	})
}

// requirePermission refuses an action the role does not carry.
//
// This is the check that matters. The templates omit a control the operator
// cannot use, but a form can be submitted directly with any fields the sender
// chooses, so hiding is a courtesy and this is the boundary. Every action
// handler calls it before touching the store.
func (h *Handler) requirePermission(w http.ResponseWriter, r *http.Request, sess *session, p rbac.Permission) bool {
	if h.allowed(sess.Role, p) {
		return true
	}
	h.auditDenied(w, r, sess, "permission", p.String(),
		fmt.Sprintf("role %s does not hold %s", sess.Role, p))
	h.renderMessage(w, r, sess, http.StatusForbidden, "You cannot do that",
		"Your sign-in does not allow this action. Ask an administrator with more "+
			"authority to carry it out.")
	return false
}

// pathID reads and checks the shape of an identifier from the path.
//
// Checking the shape here means a malformed identifier never reaches a query, so
// a stream of rubbish cannot be turned into database load.
func pathID(r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		return "", false
	}
	if _, err := uuid.Parse(v); err != nil {
		return "", false
	}
	return v, true
}

// queryLimit reads a page size, applying the configured cap.
//
// The cap is the audit query limit, because that is the setting an operator
// already has for bounding a single read, and the audit log is the largest table
// any of these screens touches.
func (h *Handler) queryLimit(r *http.Request, def int) int {
	max := h.deps.Config.Audit.MaxQueryLimit
	if max < 1 {
		max = def
	}
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// serverFault reports a failure the operator can do nothing about.
//
// The cause is logged and never rendered. A database error text on the page
// would name tables and columns, which is a map of the schema handed to whoever
// is reading the screen.
func (h *Handler) serverFault(w http.ResponseWriter, r *http.Request, sess *session, what string, err error) {
	h.deps.Logger.ErrorContext(r.Context(), "adminui: "+what, slog.Any("error", err))
	h.renderMessage(w, r, sess, http.StatusInternalServerError, "Something went wrong",
		"The service could not complete that. Try again, and if it keeps happening "+
			"look at the service log.")
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// dashboardData is the landing screen.
type dashboardData struct {
	Health           healthSummary
	Alerts           alertCounts
	PendingApprovals int
	Features         []featureLine
	Sessions         int

	// Passkeys is the operator's own sign-in: the keys enrolled for the token
	// they are signed in with, and the controls to add or withdraw one. It is
	// a section here rather than a screen of its own, because ADR 0012 counted
	// six screens as the reason this interface has no build toolchain.
	Passkeys passkeyView
}

// healthSummary is the health report in the terms an operator can act on.
//
// It is assembled from the same store methods the detailed health endpoint uses,
// rather than from the health checker, so the interface needs no dependency
// beyond the store. The version, the keyring state and the certificate expiry
// are deliberately absent: they are on the authenticated API report, and the
// question this screen answers is whether people can sign in right now.
type healthSummary struct {
	DatabaseReachable bool
	Engine            string
	LatencyMS         int64
	HistoryReadable   bool
	HistoryEntries    int64
}

type alertCounts struct {
	Critical int
	Warning  int
	Info     int
	Total    int
}

type featureLine struct {
	Name string
	On   bool
}

// handleDashboard renders the health summary and what needs attention.
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	tenantID := h.tenantID()
	data := dashboardData{Sessions: h.sessions.count()}

	start := h.now()
	if err := h.deps.Store.Ping(ctx); err == nil {
		data.Health.DatabaseReachable = true
	} else {
		h.deps.Logger.WarnContext(ctx, "adminui: database not reachable", slog.Any("error", err))
	}
	data.Health.LatencyMS = h.now().Sub(start).Milliseconds()
	data.Health.Engine = h.deps.Store.Engine()

	if seq, _, err := h.deps.Store.ChainHead(ctx); err == nil {
		data.Health.HistoryReadable = true
		data.Health.HistoryEntries = seq
	}

	if counts, err := h.deps.Store.CountOpenAlerts(ctx, tenantID); err == nil {
		data.Alerts = toAlertCounts(counts)
	}

	if pending, err := h.deps.Store.ListApprovals(ctx, tenantID, store.ApprovalPending, 100); err == nil {
		data.PendingApprovals = len(pending)
	}

	cfg := h.deps.Config
	data.Features = []featureLine{
		{Name: "Separate administrator roles", On: cfg.Features.AdminRBAC},
		{Name: "A second administrator must approve sensitive changes", On: cfg.Features.DualApproval},
		{Name: "Deletion waits before the record is destroyed", On: cfg.Features.DeferredErasure},
		{Name: "Repeated sign-in failures are slowed down", On: cfg.Throttle.Enabled},
	}

	data.Passkeys = h.passkeySection(r, sess)

	pd := h.newPage(r, sess, "Overview")
	pd.Data = data
	h.render(w, r, http.StatusOK, "dashboard", pd)
}

func toAlertCounts(counts map[store.Severity]int) alertCounts {
	out := alertCounts{
		Critical: counts[store.SeverityCritical],
		Warning:  counts[store.SeverityWarning],
		Info:     counts[store.SeverityInfo],
	}
	out.Total = out.Critical + out.Warning + out.Info
	return out
}

// ---------------------------------------------------------------------------
// People
// ---------------------------------------------------------------------------

// subjectsData is the list screen.
type subjectsData struct {
	Rows      []subjectRow
	Status    string
	Reference string

	// LookupOffered is false when no reference resolver is wired in, in which
	// case the exact lookup box is not shown at all rather than shown broken.
	LookupOffered bool

	// Searched records that a reference was supplied, so the page can say that
	// nothing matched rather than looking like an empty deployment.
	Searched bool

	NextAfter string
	Limit     int
}

type subjectRow struct {
	ID          string
	DisplayName string
	StatusLabel string
	CreatedAt   time.Time
	Deleted     bool
}

// handleSubjectList pages through the people this deployment authenticates.
//
// There is no substring search. The reference an application supplies is stored
// encrypted precisely so that it cannot be scanned, and a search that decrypted
// every row to match part of a name would undo that for the whole table. The
// page says so in plain words, because an operator who does not know why the
// search box only accepts an exact value will assume the box is broken.
func (h *Handler) handleSubjectList(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermSubjectList) {
		return
	}

	q := r.URL.Query()
	data := subjectsData{
		Status:        q.Get("status"),
		Reference:     strings.TrimSpace(q.Get("reference")),
		LookupOffered: h.deps.Subjects != nil,
		Limit:         h.queryLimit(r, 50),
	}

	f := store.SubjectFilter{
		AfterID: q.Get("after"),
		Limit:   data.Limit,
	}
	switch store.SubjectStatus(data.Status) {
	case store.SubjectActive, store.SubjectLocked, store.SubjectPendingDeletion:
		f.Status = store.SubjectStatus(data.Status)
	default:
		data.Status = ""
	}

	if data.Reference != "" {
		if h.deps.Subjects == nil {
			data.Reference = ""
		} else if err := h.deps.Subjects.ValidateRef(data.Reference); err != nil {
			pd := h.newPage(r, sess, "People")
			pd.Problem = "That reference cannot be looked up. It is either empty, too long, " +
				"or contains characters that are not allowed."
			pd.Data = data
			h.render(w, r, http.StatusBadRequest, "subjects", pd)
			return
		} else {
			data.Searched = true
			f.RefHMAC = h.deps.Subjects.RefHMAC(data.Reference)
			// A lookup returns one row at most, so paging state from a previous
			// listing would only confuse the result.
			f.AfterID = ""
		}
	}

	subjects, err := h.deps.Store.ListSubjects(r.Context(), h.tenantID(), f)
	if err != nil {
		h.serverFault(w, r, sess, "list people", err)
		return
	}

	data.Rows = make([]subjectRow, 0, len(subjects))
	for _, s := range subjects {
		data.Rows = append(data.Rows, subjectRow{
			ID:          s.ID,
			DisplayName: s.DisplayName,
			StatusLabel: statusLabel(s.Status),
			CreatedAt:   s.CreatedAt,
			Deleted:     s.DeletedAt != nil,
		})
	}
	if len(data.Rows) == f.Limit && len(data.Rows) > 0 {
		data.NextAfter = data.Rows[len(data.Rows)-1].ID
	}

	// Reading the list is audited on both surfaces. Who looked at the roll of
	// people a service authenticates is part of the record, not an
	// implementation detail of the interface.
	h.audited(w, r, audit.Event{
		TenantID:  sess.TenantID,
		EventType: audit.EventAdminSubjectsListed,
		ActorType: store.ActorAdmin,
		ActorID:   sess.TokenID,
		Outcome:   store.OutcomeSuccess,
		Detail: map[string]any{
			"returned": len(data.Rows),
			"surface":  "administration interface",
			"lookup":   data.Searched,
		},
	})

	pd := h.newPage(r, sess, "People")
	pd.Data = data
	h.render(w, r, http.StatusOK, "subjects", pd)
}

// subjectData is the detail screen.
type subjectData struct {
	ID          string
	DisplayName string
	StatusLabel string
	Blocked     bool
	Deleted     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time

	Reference      string
	ReferenceShown bool
	ReferenceReady bool

	Authenticators []authenticatorRow
	ActiveCount    int

	AuthenticatorApp  bool
	RecoveryRemaining int
	RecoveryLow       bool

	Deletion *deletionView

	// NewCodes carries a freshly issued batch of recovery codes. They are
	// rendered once, on the response to the request that created them, because
	// nothing stores them in a form anyone can read back.
	NewCodes []string
}

// authenticatorRow describes one registered security key or passkey.
//
// The authenticator model identifier and the public key are not shown. Neither
// means anything to an operator handling a support call, and the specification
// rules out putting that vocabulary on the screen.
type authenticatorRow struct {
	ID                string
	Label             string
	AddedAt           time.Time
	LastUsedAt        *time.Time
	Withdrawn         bool
	WithdrawnAt       *time.Time
	WithdrawnReason   string
	MayHaveBeenCopied bool
}

type deletionView struct {
	Requested   time.Time
	PurgeAfter  time.Time
	StatusLabel string
	Reason      string
}

var deletionStatusLabels = map[store.ErasureStatus]string{
	store.ErasurePending:   "Waiting for the retention period to end",
	store.ErasureCancelled: "Cancelled",
	store.ErasurePurged:    "The record has been destroyed",
}

// subjectRenderOptions carry what a preceding action wants the detail page to
// say.
type subjectRenderOptions struct {
	Status    int
	Problem   string
	RevealRef bool
	NewCodes  []string
}

// handleSubjectDetail shows one person, their factors and the actions available.
func (h *Handler) handleSubjectDetail(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermSubjectRead) {
		return
	}
	id, ok := pathID(r, "subject_id")
	if !ok {
		h.renderMessage(w, r, sess, http.StatusNotFound, "That person does not exist",
			"The link you followed does not name anyone in this deployment.")
		return
	}
	h.renderSubject(w, r, sess, id, subjectRenderOptions{Status: http.StatusOK})
}

// renderSubject builds and writes the detail screen.
//
// Every action on a person re-renders this page, either directly when something
// has to be shown once, such as a batch of recovery codes, or after a redirect
// when there is nothing to show but a confirmation.
func (h *Handler) renderSubject(w http.ResponseWriter, r *http.Request, sess *session, id string, opts subjectRenderOptions) {
	ctx := r.Context()
	tenantID := h.tenantID()

	sub, err := h.deps.Store.GetSubject(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusNotFound, "That person does not exist",
				"They may have been deleted, or the link may be out of date.")
			return
		}
		h.serverFault(w, r, sess, "read person", err)
		return
	}

	creds, err := h.deps.Store.ListCredentials(ctx, tenantID, sub.ID, true)
	if err != nil {
		h.serverFault(w, r, sess, "list authenticators", err)
		return
	}
	remaining, err := h.deps.Store.CountUnusedRecoveryCodes(ctx, tenantID, sub.ID)
	if err != nil {
		h.serverFault(w, r, sess, "count recovery codes", err)
		return
	}

	data := subjectData{
		ID:                sub.ID,
		DisplayName:       sub.DisplayName,
		StatusLabel:       statusLabel(sub.Status),
		Blocked:           sub.Status == store.SubjectLocked,
		Deleted:           sub.DeletedAt != nil,
		CreatedAt:         sub.CreatedAt,
		UpdatedAt:         sub.UpdatedAt,
		RecoveryRemaining: remaining,
		RecoveryLow:       remaining <= h.deps.Config.Recovery.LowWatermark,
		ReferenceReady:    h.deps.Subjects != nil && len(sub.RefSealed) > 0,
		NewCodes:          opts.NewCodes,
	}

	for _, c := range creds {
		label := c.Label
		if strings.TrimSpace(label) == "" {
			label = "Security key or passkey"
		}
		row := authenticatorRow{
			ID:                c.ID,
			Label:             label,
			AddedAt:           c.CreatedAt,
			LastUsedAt:        c.LastUsedAt,
			Withdrawn:         c.Revoked(),
			WithdrawnAt:       c.RevokedAt,
			WithdrawnReason:   c.RevokedReason,
			MayHaveBeenCopied: c.CloneWarning,
		}
		if !row.Withdrawn {
			data.ActiveCount++
		}
		data.Authenticators = append(data.Authenticators, row)
	}

	if _, err := h.deps.Store.GetActiveTOTPSecret(ctx, tenantID, sub.ID); err == nil {
		data.AuthenticatorApp = true
	} else if !errors.Is(err, store.ErrNotFound) {
		h.serverFault(w, r, sess, "read authenticator app state", err)
		return
	}

	if er, err := h.deps.Store.GetErasureBySubject(ctx, tenantID, sub.ID); err == nil {
		label, ok := deletionStatusLabels[er.Status]
		if !ok {
			label = string(er.Status)
		}
		data.Deletion = &deletionView{
			Requested:   er.RequestedAt,
			PurgeAfter:  er.PurgeAfter,
			StatusLabel: label,
			Reason:      er.Reason,
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		h.serverFault(w, r, sess, "read deletion request", err)
		return
	}

	if opts.RevealRef && data.ReferenceReady {
		ref, err := h.deps.Subjects.RevealRef(sub)
		if err != nil {
			h.deps.Logger.WarnContext(ctx, "adminui: reference not revealed", slog.Any("error", err))
			data.ReferenceReady = false
		} else {
			data.Reference = ref
			data.ReferenceShown = true
		}
	}

	status := opts.Status
	if status == 0 {
		status = http.StatusOK
	}
	pd := h.newPage(r, sess, "Person")
	pd.Problem = opts.Problem
	pd.Data = data
	h.render(w, r, status, "subject", pd)
}

// actionPreamble is the common start of every action on a person: a session, a
// valid request token, a permission and a well-formed identifier.
//
// Returning the session and the identifier together is what keeps the four
// checks in one place. A handler that resolved the identifier before checking
// the permission would have read a record it was not allowed to see.
func (h *Handler) actionPreamble(w http.ResponseWriter, r *http.Request, p rbac.Permission, idName string) (*session, string, bool) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return nil, "", false
	}
	if !h.checkCSRF(w, r, sess) {
		return nil, "", false
	}
	if !h.requirePermission(w, r, sess, p) {
		return nil, "", false
	}
	id, ok := pathID(r, idName)
	if !ok {
		h.renderMessage(w, r, sess, http.StatusNotFound, "That record does not exist",
			"The form named something this deployment does not hold.")
		return nil, "", false
	}
	return sess, id, true
}

// handleSubjectLock stops a person signing in.
func (h *Handler) handleSubjectLock(w http.ResponseWriter, r *http.Request) {
	h.setSubjectStatus(w, r, rbac.PermSubjectLock, store.SubjectLocked,
		audit.EventSubjectLocked, "sign-in-blocked")
}

// handleSubjectUnlock lets a blocked person sign in again.
//
// Blocking is separate from clearing a sign-in limit, and an operator needs
// both. A block is a decision someone took and persists until it is reversed; a
// limit is automatic, follows a run of failures, and expires on its own.
func (h *Handler) handleSubjectUnlock(w http.ResponseWriter, r *http.Request) {
	h.setSubjectStatus(w, r, rbac.PermSubjectUnlock, store.SubjectActive,
		audit.EventSubjectUnlocked, "sign-in-allowed")
}

func (h *Handler) setSubjectStatus(w http.ResponseWriter, r *http.Request, p rbac.Permission,
	status store.SubjectStatus, eventType, notice string) {

	sess, id, ok := h.actionPreamble(w, r, p, "subject_id")
	if !ok {
		return
	}

	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if err := h.deps.Store.SetSubjectStatus(r.Context(), h.tenantID(), id, status); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusNotFound, "That person does not exist",
				"They may have been deleted since the page was loaded.")
			return
		}
		h.serverFault(w, r, sess, "change sign-in status", err)
		return
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: eventType,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		SubjectID: id, ResourceType: "subject", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"status":  string(status),
			"reason":  reason,
			"surface": "administration interface",
		},
	})

	// Answer with a redirect so that a reload does not repeat the action and the
	// back button does not show a form waiting to be resubmitted.
	//
	// #nosec G710 -- the target is a fixed path, an identifier pathID accepted only because it parses as a UUID, and
	// a notice string passed by handleSubjectLock and handleSubjectUnlock as a literal
	http.Redirect(w, r, "/admin/subjects/"+id+"?notice="+notice, http.StatusSeeOther)
}

// handleSubjectClearLimit clears a person's rate-limit state.
//
// This is the operation behind someone reporting that they cannot sign in after
// several failed attempts. It removes every bucket the person is counted under,
// which is why it goes through the limiter rather than the store: only the
// limiter can derive the keys it wrote.
func (h *Handler) handleSubjectClearLimit(w http.ResponseWriter, r *http.Request) {
	sess, id, ok := h.actionPreamble(w, r, rbac.PermThrottleReset, "subject_id")
	if !ok {
		return
	}
	if h.deps.Limiter == nil {
		h.renderSubject(w, r, sess, id, subjectRenderOptions{
			Status:  http.StatusConflict,
			Problem: "Sign-in limits are switched off in this deployment, so there is nothing to clear.",
		})
		return
	}

	if err := h.deps.Limiter.ResetSubject(r.Context(), h.tenantID(), id); err != nil {
		h.serverFault(w, r, sess, "clear sign-in limit", err)
		return
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: audit.EventThrottleReset,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		SubjectID: id, ResourceType: "subject", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"surface": "administration interface"},
	})

	// #nosec G710 -- the target is a fixed path and query, with an identifier pathID accepted only because it parses
	// as a UUID
	http.Redirect(w, r, "/admin/subjects/"+id+"?notice=limit-cleared", http.StatusSeeOther)
}

// handleSubjectRecoveryCodes issues a fresh batch of recovery codes.
//
// The codes are shown on this response and never again: only a selector and a
// digest of each one are stored, so there is no operation that can display them
// a second time. Issuing a batch also retires every unused code from the
// previous batch, in one transaction, so nothing the person believes is dead
// stays usable.
//
// This response renders the page directly rather than redirecting, because the
// codes cannot travel in a URL.
func (h *Handler) handleSubjectRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	sess, id, ok := h.actionPreamble(w, r, rbac.PermRecoveryReissue, "subject_id")
	if !ok {
		return
	}

	ctx := r.Context()
	tenantID := h.tenantID()

	sub, err := h.deps.Store.GetSubject(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusNotFound, "That person does not exist",
				"They may have been deleted since the page was loaded.")
			return
		}
		h.serverFault(w, r, sess, "read person", err)
		return
	}

	codes, err := recovery.Generate(h.deps.Config.Recovery.CodeCount)
	if err != nil {
		h.serverFault(w, r, sess, "generate recovery codes", err)
		return
	}

	batchID := uuid.NewString()
	now := h.now().UTC()
	records := make([]*store.RecoveryCode, 0, len(codes))
	display := make([]string, 0, len(codes))
	for _, c := range codes {
		records = append(records, &store.RecoveryCode{
			ID: uuid.NewString(), TenantID: tenantID, SubjectID: sub.ID,
			BatchID: batchID, Selector: c.Selector, VerifierHash: c.Hash,
			CreatedAt: now,
		})
		display = append(display, c.Display)
	}

	if err := h.deps.Store.ReplaceRecoveryCodes(ctx, tenantID, sub.ID, batchID, records); err != nil {
		h.serverFault(w, r, sess, "store recovery codes", err)
		return
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: audit.EventRecoveryIssued,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		SubjectID: sub.ID, ResourceType: "recovery_batch", ResourceID: batchID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"count":   len(display),
			"surface": "administration interface",
		},
	})

	h.renderSubject(w, r, sess, id, subjectRenderOptions{
		Status:   http.StatusOK,
		NewCodes: display,
	})
}

// handleSubjectReference shows the reference the application supplied.
//
// This is the one operation that turns a row back into something identifying a
// person, so it is a deliberate act with its own audit entry rather than part of
// reading the record. It is a form rather than a link for the same reason: a
// link would be followed by a browser prefetching the page, and the record would
// show a reference having been read that nobody asked for.
func (h *Handler) handleSubjectReference(w http.ResponseWriter, r *http.Request) {
	sess, id, ok := h.actionPreamble(w, r, rbac.PermSubjectRead, "subject_id")
	if !ok {
		return
	}
	if h.deps.Subjects == nil {
		h.renderSubject(w, r, sess, id, subjectRenderOptions{
			Status:  http.StatusConflict,
			Problem: "This deployment cannot show the reference an application supplied.",
		})
		return
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: audit.EventAdminSubjectRefRevealed,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		SubjectID: id, ResourceType: "subject", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"surface": "administration interface"},
	})

	h.renderSubject(w, r, sess, id, subjectRenderOptions{
		Status:    http.StatusOK,
		RevealRef: true,
	})
}

// handleCredentialWithdraw withdraws one security key or passkey.
//
// Withdrawal is final. There is deliberately no way to restore one: an
// authenticator is withdrawn because it is believed to be in the wrong hands,
// and a window in which that can be undone is a window in which it can be put
// back. What protects against a mistaken run of withdrawals is the burst limit
// applied here, not reversibility. See docs/adr/0010.
func (h *Handler) handleCredentialWithdraw(w http.ResponseWriter, r *http.Request) {
	sess, subjectID, ok := h.actionPreamble(w, r, rbac.PermCredentialRevoke, "subject_id")
	if !ok {
		return
	}
	credentialID, ok := pathID(r, "credential_id")
	if !ok {
		h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
			Status:  http.StatusNotFound,
			Problem: "That authenticator does not exist.",
		})
		return
	}

	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" {
		// A withdrawal with no stated reason is an entry in the history nobody
		// can act on later, so the reason is required rather than optional.
		h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
			Status:  http.StatusBadRequest,
			Problem: "Say why you are withdrawing this authenticator. The reason is kept with the record.",
		})
		return
	}
	allowLast := r.PostFormValue("allow_last") != ""

	ctx := r.Context()
	tenantID := h.tenantID()

	// The burst limit bounds how much one operator can destroy inside the
	// window. It is checked before the read, so an operator who has already
	// reached it gets no further work out of the service.
	dims := map[throttle.Dimension]string{throttle.DimAdminRevoke: sess.TokenID}
	if h.deps.Limiter != nil {
		res, err := h.deps.Limiter.Check(ctx, tenantID, dims)
		if err != nil {
			h.deps.Logger.WarnContext(ctx, "adminui: withdrawal limit state unavailable",
				slog.Any("error", err))
		} else if !res.Allowed {
			h.auditDenied(w, r, sess, "credential", credentialID,
				"the withdrawal burst limit for this operator has been reached")
			h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
				Status: http.StatusTooManyRequests,
				Problem: fmt.Sprintf("You have withdrawn as many authenticators as one sign-in "+
					"is allowed in this period. Wait %d minutes, or ask another administrator.",
					minutesAtLeastOne(res.RetryAfter)),
			})
			return
		}
	}

	cred, err := h.deps.Store.GetCredential(ctx, tenantID, credentialID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
				Status:  http.StatusNotFound,
				Problem: "That authenticator does not exist.",
			})
			return
		}
		h.serverFault(w, r, sess, "read authenticator", err)
		return
	}
	if cred.SubjectID != subjectID {
		// The authenticator exists but belongs to someone else. Reported as
		// absent, so this form cannot be used to discover who owns one.
		h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
			Status:  http.StatusNotFound,
			Problem: "That authenticator does not exist.",
		})
		return
	}
	if cred.Revoked() {
		h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
			Status:  http.StatusConflict,
			Problem: "That authenticator has already been withdrawn.",
		})
		return
	}

	active, err := h.deps.Store.CountActiveCredentials(ctx, tenantID, subjectID)
	if err != nil {
		h.serverFault(w, r, sess, "count authenticators", err)
		return
	}
	if active <= 1 && !allowLast {
		h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
			Status: http.StatusConflict,
			Problem: "This is the only authenticator this person has left. Withdrawing it " +
				"locks them out unless they hold recovery codes. Tick the box to go " +
				"ahead anyway.",
		})
		return
	}

	if err := h.deps.Store.RevokeCredential(ctx, tenantID, credentialID, reason, h.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderSubject(w, r, sess, subjectID, subjectRenderOptions{
				Status:  http.StatusNotFound,
				Problem: "That authenticator does not exist.",
			})
			return
		}
		h.serverFault(w, r, sess, "withdraw authenticator", err)
		return
	}

	if h.deps.Limiter != nil {
		if _, err := h.deps.Limiter.Record(ctx, tenantID, dims, false); err != nil {
			h.deps.Logger.WarnContext(ctx, "adminui: withdrawal not counted", slog.Any("error", err))
		}
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: audit.EventCredentialRevoked,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		SubjectID: subjectID, ResourceType: "credential", ResourceID: credentialID,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"reason":              reason,
			"remaining_active":    active - 1,
			"was_last_credential": active <= 1,
			"surface":             "administration interface",
		},
	})

	// #nosec G710 -- the target is a fixed path and query, with an identifier pathID accepted only because it parses
	// as a UUID
	http.Redirect(w, r, "/admin/subjects/"+subjectID+"?notice=authenticator-removed", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

// auditData is the history screen.
type auditData struct {
	Rows   []auditRow
	Filter auditFilterView

	NextSeq int64
	Limit   int

	// Check holds the result of an integrity check, present only on the
	// response to the request that ran one.
	Check *checkResult

	EventOptions []option
}

// auditFilterView is the filter form, rendered back so the fields keep their
// values across a page of results.
type auditFilterView struct {
	EventType string
	SubjectID string
	ActorID   string
	Outcome   string
	Since     string
	Until     string
	AfterSeq  int64
}

type auditRow struct {
	Seq        int64
	OccurredAt time.Time
	Event      string
	Outcome    string
	ActorID    string
	SubjectID  string
	Resource   string
	Fields     []field
}

type option struct {
	Value string
	Label string
}

// checkResult is the outcome of recomputing the history's hash chain, in words.
type checkResult struct {
	Intact   bool
	From     int64
	Checked  int64
	BrokenAt int64
	Headline string
	Body     string
}

// eventOptions is the filter list, built once from the translation table so the
// two cannot fall out of step.
var eventOptions = func() []option {
	out := make([]option, 0, len(eventNames))
	for value, label := range eventNames {
		out = append(out, option{Value: value, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}()

// handleAuditList reads the history with filters and forward paging.
//
// Paging is keyset, on the sequence number, because the history is the one table
// that grows without bound. An offset scan re-reads every skipped row, so page
// two hundred of an offset-paged log costs two hundred pages of reading.
func (h *Handler) handleAuditList(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermAuditRead) {
		return
	}
	h.renderAudit(w, r, sess, nil, http.StatusOK, "")
}

// renderAudit builds and writes the history screen.
func (h *Handler) renderAudit(w http.ResponseWriter, r *http.Request, sess *session,
	check *checkResult, status int, problem string) {

	q := r.URL.Query()
	if r.Method == http.MethodPost {
		// A check is submitted from the filter form, so the filters arrive in
		// the body rather than the query string.
		q = r.PostForm
	}

	data := auditData{
		Limit:        h.queryLimit(r, 100),
		Check:        check,
		EventOptions: eventOptions,
		Filter: auditFilterView{
			EventType: q.Get("event_type"),
			SubjectID: strings.TrimSpace(q.Get("subject_id")),
			ActorID:   strings.TrimSpace(q.Get("actor_id")),
			Outcome:   q.Get("outcome"),
			Since:     strings.TrimSpace(q.Get("since")),
			Until:     strings.TrimSpace(q.Get("until")),
		},
	}

	f := store.AuditFilter{
		EventType: data.Filter.EventType,
		SubjectID: data.Filter.SubjectID,
		ActorID:   data.Filter.ActorID,
		Limit:     data.Limit,
	}
	switch store.Outcome(data.Filter.Outcome) {
	case store.OutcomeSuccess, store.OutcomeFailure, store.OutcomeDenied, store.OutcomeError:
		f.Outcome = store.Outcome(data.Filter.Outcome)
	default:
		data.Filter.Outcome = ""
	}
	if v := q.Get("after_seq"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			f.AfterSeq = n
			data.Filter.AfterSeq = n
		}
	}
	// The two date fields accept a plain calendar date, because that is what an
	// operator types. A full timestamp is accepted as well so a link copied from
	// the API keeps working.
	if t, ok := parseDay(data.Filter.Since, false); ok {
		f.Since = t
	} else if data.Filter.Since != "" {
		problem = "The start date was not understood. Use a date such as 2024-06-05."
		data.Filter.Since = ""
	}
	if t, ok := parseDay(data.Filter.Until, true); ok {
		f.Until = t
	} else if data.Filter.Until != "" {
		problem = "The end date was not understood. Use a date such as 2024-06-05."
		data.Filter.Until = ""
	}

	entries, err := h.deps.Store.QueryAudit(r.Context(), h.tenantID(), f)
	if err != nil {
		h.serverFault(w, r, sess, "read history", err)
		return
	}

	data.Rows = make([]auditRow, 0, len(entries))
	for _, e := range entries {
		data.Rows = append(data.Rows, auditRow{
			Seq:        e.Seq,
			OccurredAt: e.OccurredAt,
			Event:      eventName(e.EventType),
			Outcome:    outcomeWord(e.Outcome),
			ActorID:    e.ActorID,
			SubjectID:  e.SubjectID,
			Resource:   strings.TrimSpace(strings.ReplaceAll(e.ResourceType, "_", " ")),
			Fields:     payloadFields(e.Detail),
		})
	}
	if len(data.Rows) == f.Limit && len(data.Rows) > 0 {
		data.NextSeq = data.Rows[len(data.Rows)-1].Seq
	}

	pd := h.newPage(r, sess, "History")
	pd.Problem = problem
	pd.Data = data
	h.render(w, r, status, "audit", pd)
}

// parseDay accepts a calendar date or a full timestamp.
//
// endOfDay makes the upper bound inclusive of the day the operator typed, which
// is what they mean by "until the fifth".
func parseDay(v string, endOfDay bool) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if endOfDay {
			return t.UTC().Add(24*time.Hour - time.Nanosecond), true
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}

// handleAuditCheck recomputes the hash chain and reports the result in plain
// language.
//
// This is the operation that makes the chain worth keeping. It answers whether
// the history has been altered since it was written, and the run is itself
// recorded, so a check cannot be performed quietly.
//
// It cannot prevent tampering. On an on-premise deployment the operator owns the
// database file, and the page says as much rather than implying a guarantee the
// design does not offer.
func (h *Handler) handleAuditCheck(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.checkCSRF(w, r, sess) {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermAuditVerify) {
		return
	}

	from := int64(1)
	if v := r.PostFormValue("from_seq"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			from = n
		}
	}

	checked, brokenAt, err := h.deps.Recorder.Verify(r.Context(), h.tenantID(), from)
	if err != nil {
		h.serverFault(w, r, sess, "check history", err)
		return
	}

	result := &checkResult{
		Intact:   brokenAt == 0,
		From:     from,
		Checked:  checked,
		BrokenAt: brokenAt,
	}
	if result.Intact {
		result.Headline = "The history has not been altered."
		result.Body = fmt.Sprintf("Every one of the %d entries checked still matches what was "+
			"recorded when it was written.", checked)
	} else {
		result.Headline = fmt.Sprintf("Entry %d does not match what was recorded.", brokenAt)
		result.Body = "Everything before that entry is intact. Something has changed the " +
			"history after it was written, which on a self-hosted service usually " +
			"means the database file was edited. Keep a copy of it and find out who " +
			"had access."
	}

	// A broken chain is answered with 409 so that a monitoring check reading only
	// the status code does not miss it.
	status := http.StatusOK
	if !result.Intact {
		status = http.StatusConflict
	}
	h.renderAudit(w, r, sess, result, status, "")
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

// alertsData is the alerts screen.
type alertsData struct {
	Rows                []alertRow
	Counts              alertCounts
	Severity            string
	IncludeAcknowledged bool
	NextAfter           string
	Limit               int
	SeverityOptions     []option
}

type alertRow struct {
	ID             string
	Summary        string
	SeverityLabel  string
	Severity       string
	SubjectID      string
	Occurrences    int
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	Acknowledged   bool
	AcknowledgedAt *time.Time
	AcknowledgedBy string
	Fields         []field
}

var severityOptions = []option{
	{Value: string(store.SeverityCritical), Label: severityWord(store.SeverityCritical)},
	{Value: string(store.SeverityWarning), Label: severityWord(store.SeverityWarning)},
	{Value: string(store.SeverityInfo), Label: severityWord(store.SeverityInfo)},
}

// handleAlertList shows the conditions worth looking at.
func (h *Handler) handleAlertList(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermAlertRead) {
		return
	}

	q := r.URL.Query()
	data := alertsData{
		Severity:            q.Get("severity"),
		IncludeAcknowledged: q.Get("include_acknowledged") == "yes",
		Limit:               h.queryLimit(r, 50),
		SeverityOptions:     severityOptions,
	}

	f := store.AlertFilter{
		IncludeAcked: data.IncludeAcknowledged,
		AfterID:      q.Get("after"),
		Limit:        data.Limit,
	}
	switch store.Severity(data.Severity) {
	case store.SeverityCritical, store.SeverityWarning, store.SeverityInfo:
		f.Severity = store.Severity(data.Severity)
	default:
		data.Severity = ""
	}

	list, err := h.deps.Store.ListAlerts(r.Context(), h.tenantID(), f)
	if err != nil {
		h.serverFault(w, r, sess, "list alerts", err)
		return
	}
	if counts, err := h.deps.Store.CountOpenAlerts(r.Context(), h.tenantID()); err == nil {
		data.Counts = toAlertCounts(counts)
	}

	data.Rows = make([]alertRow, 0, len(list))
	for _, a := range list {
		data.Rows = append(data.Rows, alertRow{
			ID:             a.ID,
			Summary:        a.Summary,
			SeverityLabel:  severityWord(a.Severity),
			Severity:       string(a.Severity),
			SubjectID:      a.SubjectID,
			Occurrences:    a.Occurrences,
			FirstSeenAt:    a.FirstSeenAt,
			LastSeenAt:     a.LastSeenAt,
			Acknowledged:   a.AcknowledgedAt != nil,
			AcknowledgedAt: a.AcknowledgedAt,
			AcknowledgedBy: a.AcknowledgedBy,
			Fields:         payloadFields(a.Detail),
		})
	}
	if len(data.Rows) == f.Limit && len(data.Rows) > 0 {
		data.NextAfter = data.Rows[len(data.Rows)-1].ID
	}

	pd := h.newPage(r, sess, "Alerts")
	pd.Data = data
	h.render(w, r, http.StatusOK, "alerts", pd)
}

// handleAlertAcknowledge marks an alert as seen.
//
// An auditor cannot do this, and the restriction is the point of the role: an
// auditor who can quietly clear an alert can quietly cover a trace.
func (h *Handler) handleAlertAcknowledge(w http.ResponseWriter, r *http.Request) {
	sess, id, ok := h.actionPreamble(w, r, rbac.PermAlertAcknowledge, "alert_id")
	if !ok {
		return
	}

	if err := h.deps.Store.AcknowledgeAlert(r.Context(), h.tenantID(), id,
		sess.TokenID, h.now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderMessage(w, r, sess, http.StatusNotFound, "That alert does not exist",
				"It may have been acknowledged by someone else since the page was loaded.")
			return
		}
		h.serverFault(w, r, sess, "acknowledge alert", err)
		return
	}

	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: audit.EventAlertAcknowledged,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		ResourceType: "alert", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail:  map[string]any{"surface": "administration interface"},
	})

	http.Redirect(w, r, "/admin/alerts?notice=alert-acknowledged", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Requests waiting for a second administrator
// ---------------------------------------------------------------------------

// approvalsData is the approvals screen.
type approvalsData struct {
	Rows          []approvalRow
	Status        string
	StatusOptions []option
	Limit         int
}

type approvalRow struct {
	ID          string
	Operation   string
	Reason      string
	RequestedBy string
	RequestedAt time.Time
	ExpiresAt   time.Time
	StatusLabel string
	Pending     bool

	// Yours is true when the signed-in operator raised the request, in which
	// case the decision controls are not offered. The store refuses it anyway;
	// showing buttons that are certain to be refused is not helpful.
	Yours bool

	Fields []field
}

var approvalStatusOptions = []option{
	{Value: string(store.ApprovalPending), Label: approvalStatusLabel(store.ApprovalPending)},
	{Value: string(store.ApprovalApproved), Label: approvalStatusLabel(store.ApprovalApproved)},
	{Value: string(store.ApprovalRejected), Label: approvalStatusLabel(store.ApprovalRejected)},
	{Value: string(store.ApprovalExpired), Label: approvalStatusLabel(store.ApprovalExpired)},
	{Value: string(store.ApprovalExecuted), Label: approvalStatusLabel(store.ApprovalExecuted)},
	{Value: string(store.ApprovalFailed), Label: approvalStatusLabel(store.ApprovalFailed)},
}

// handleApprovalList shows the changes waiting for a second administrator.
func (h *Handler) handleApprovalList(w http.ResponseWriter, r *http.Request) {
	sess := h.requireSession(w, r)
	if sess == nil {
		return
	}
	if !h.requirePermission(w, r, sess, rbac.PermApprovalRead) {
		return
	}
	h.renderApprovals(w, r, sess, http.StatusOK, "")
}

func (h *Handler) renderApprovals(w http.ResponseWriter, r *http.Request, sess *session, status int, problem string) {
	requested := r.URL.Query().Get("status")
	wanted := store.ApprovalStatus(requested)
	switch wanted {
	case store.ApprovalPending, store.ApprovalApproved, store.ApprovalRejected,
		store.ApprovalExpired, store.ApprovalExecuted, store.ApprovalFailed:
	default:
		wanted = store.ApprovalPending
		requested = string(store.ApprovalPending)
	}

	data := approvalsData{
		Status:        requested,
		StatusOptions: approvalStatusOptions,
		Limit:         h.queryLimit(r, 50),
	}

	list, err := h.deps.Store.ListApprovals(r.Context(), h.tenantID(), wanted, data.Limit)
	if err != nil {
		h.serverFault(w, r, sess, "list requests", err)
		return
	}

	data.Rows = make([]approvalRow, 0, len(list))
	for _, a := range list {
		data.Rows = append(data.Rows, approvalRow{
			ID:          a.ID,
			Operation:   operationWord(a.Operation),
			Reason:      a.Reason,
			RequestedBy: a.RequestedBy,
			RequestedAt: a.RequestedAt,
			ExpiresAt:   a.ExpiresAt,
			StatusLabel: approvalStatusLabel(a.Status),
			Pending:     a.Status == store.ApprovalPending,
			Yours:       a.RequestedBy == sess.TokenID,
			Fields:      payloadFields(a.Payload),
		})
	}

	pd := h.newPage(r, sess, "Requests")
	pd.Problem = problem
	pd.Data = data
	h.render(w, r, status, "approvals", pd)
}

// handleApprovalApprove grants a queued change.
func (h *Handler) handleApprovalApprove(w http.ResponseWriter, r *http.Request) {
	h.decideApproval(w, r, true)
}

// handleApprovalReject refuses a queued change.
func (h *Handler) handleApprovalReject(w http.ResponseWriter, r *http.Request) {
	h.decideApproval(w, r, false)
}

// decideApproval records a decision on a queued change.
//
// The store refuses a decision taken by whoever raised the request. A
// two-administrator rule one administrator can satisfy alone is not a control,
// so that check lives in the same transaction as the state change rather than
// here, where a second code path could route around it.
func (h *Handler) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	sess, id, ok := h.actionPreamble(w, r, rbac.PermApprovalDecide, "approval_id")
	if !ok {
		return
	}

	note := strings.TrimSpace(r.PostFormValue("note"))
	decided, err := h.deps.Store.DecideApproval(r.Context(), h.tenantID(), id,
		sess.TokenID, approve, note, h.now().UTC())
	switch {
	case errors.Is(err, store.ErrSelfApproval):
		h.audited(w, r, audit.Event{
			TenantID: sess.TenantID, EventType: audit.EventApprovalRejected,
			ActorType: store.ActorAdmin, ActorID: sess.TokenID,
			ResourceType: "approval_request", ResourceID: id,
			Outcome: store.OutcomeDenied,
			Detail:  map[string]any{"reason": "the decision was taken by the requester"},
		})
		h.renderApprovals(w, r, sess, http.StatusForbidden,
			"You raised this request, so a different administrator has to decide it.")
		return
	case errors.Is(err, store.ErrStaleWrite):
		h.renderApprovals(w, r, sess, http.StatusConflict,
			"That request is no longer waiting for a decision.")
		return
	case errors.Is(err, store.ErrNotFound):
		h.renderApprovals(w, r, sess, http.StatusNotFound, "That request does not exist.")
		return
	case err != nil:
		h.serverFault(w, r, sess, "decide request", err)
		return
	}

	eventType := audit.EventApprovalGranted
	notice := "request-approved"
	if !approve {
		eventType = audit.EventApprovalRejected
		notice = "request-rejected"
	}
	h.audited(w, r, audit.Event{
		TenantID: sess.TenantID, EventType: eventType,
		ActorType: store.ActorAdmin, ActorID: sess.TokenID,
		ResourceType: "approval_request", ResourceID: id,
		Outcome: store.OutcomeSuccess,
		Detail: map[string]any{
			"operation":    decided.Operation,
			"requested_by": decided.RequestedBy,
			"note":         note,
			"surface":      "administration interface",
		},
	})

	http.Redirect(w, r, "/admin/approvals?notice="+notice, http.StatusSeeOther)
}
